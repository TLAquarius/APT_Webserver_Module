import re
import pandas as pd
import json
from urllib.parse import unquote, urlparse
from datetime import datetime, timezone
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
import os


def worker_parse_chunk(chunk_data):
    """
    Parses a chunk of log lines into structured dictionaries independently.
    """
    chunk, filepath, log_format, log_type, time_window, last_timestamp = chunk_data
    parsed_records, errors = [], []
    pattern = WebServerLogParser.FORMAT_PATTERNS.get(log_format)

    start_time, end_time = None, None
    if time_window and len(time_window) == 2:
        try:
            start_time = datetime.fromisoformat(time_window[0].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(time_window[1].replace('Z', '+00:00'))
        except ValueError:
            pass

    for line_num, line in chunk:
        match = pattern.match(line)
        if match:
            log_dict = match.groupdict()

            if log_type == "access":
                ts_str = WebServerLogParser._normalize_access_time(log_dict.get('timestamp'))
                if ts_str:
                    last_timestamp = ts_str
            elif log_type == "error":
                ts_str = log_dict.get('timestamp')
                if ts_str:
                    normalized_ts = WebServerLogParser._normalize_error_time(ts_str)
                    if normalized_ts:
                        last_timestamp = normalized_ts

            if start_time and end_time and last_timestamp:
                try:
                    log_dt = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))
                    if not (start_time <= log_dt <= end_time):
                        continue
                except ValueError:
                    pass

            if log_type == "access":
                raw_x_fwd = log_dict.get('x_forwarded_for')
                if raw_x_fwd and raw_x_fwd != '-':
                    real_ip = raw_x_fwd.split(',')[0].strip()
                else:
                    real_ip = log_dict.get('ip')

                uri_comp = WebServerLogParser._process_uri(log_dict.get('raw_uri', ''))
                parsed_records.append({
                    'event_source': log_format,
                    'event_id': f"acc_{os.path.basename(filepath)}_{line_num}",
                    '@timestamp': last_timestamp,
                    'source_ip': real_ip,
                    'user_id': None if log_dict.get('user_id') == '-' else log_dict.get('user_id'),
                    'http_method': log_dict.get('method'),
                    'status_code': int(log_dict.get('status', 0)),
                    'bytes_sent': 0 if log_dict.get('bytes') == '-' else int(log_dict.get('bytes', 0)),
                    'user_agent': log_dict.get('user_agent', ''),
                    'vhost': log_dict.get('vhost', ''),
                    **uri_comp,
                    'raw_message': line.strip()
                })
            elif log_type == "error":
                parsed_records.append({
                    'event_source': log_format,
                    'event_id': f"err_{os.path.basename(filepath)}_{line_num}",
                    '@timestamp': last_timestamp,
                    'source_ip': log_dict.get('client_ip', None),
                    'error_module': log_dict.get('module', 'core'),
                    'error_message': log_dict.get('error_message', ''),
                    'raw_message': line.strip()
                })
        else:
            if line.strip():
                errors.append({'file': os.path.basename(filepath), 'line': line_num, 'raw': line.strip()})
    return parsed_records, errors


class WebServerLogParser:
    FORMAT_PATTERNS = {
        "vhost_combined_access": re.compile(
            r'(?P<vhost>\S+) (?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"(?: "(?P<x_forwarded_for>[^"]*)")?'
        ),
        "combined_access": re.compile(
            r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"(?: "(?P<x_forwarded_for>[^"]*)")?'
        ),
        "common_access": re.compile(
            r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+)'
        ),
        "apache_error": re.compile(
            r'\[(?P<timestamp>[^\]]+)\] \[(?P<module>[^\]]+)\] '
            r'(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\] )?'
            r'(?:\[client (?P<client_ip>[^:]+)(?::(?P<client_port>\d+))?\] )?'
            r'(?P<error_message>.*)'
        ),
        "nginx_error": re.compile(
            r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
            r'(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<error_message>.*?)'
            r'(?:, client: (?P<client_ip>[^,]+))?(?:, server: (?P<server>[^,]+))?'
            r'(?:, request: "(?P<request>[^"]+)")?'
        )
    }

    def __init__(self, chunk_size=50000, max_workers=None):
        """
        Initializes the parser configuration.
        """
        self.chunk_size = chunk_size
        self.max_workers = max_workers or mp.cpu_count()
        self.parsed_data = []
        self.error_logs = []

    @classmethod
    def auto_detect_format(cls, filepath, sample_lines=20):
        """
        Scans the initial lines of a file to determine the correct regex pattern.
        """
        match_counts = {fmt: 0 for fmt in cls.FORMAT_PATTERNS.keys()}
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [f.readline() for _ in range(sample_lines)]
        except Exception:
            raise ValueError(f"Không thể đọc file {os.path.basename(filepath)}")

        for line in lines:
            if not line.strip(): continue
            for fmt, pattern in cls.FORMAT_PATTERNS.items():
                if pattern.match(line):
                    match_counts[fmt] += 1

        best_format = max(match_counts, key=match_counts.get)
        if match_counts[best_format] == 0:
            raise ValueError("Không tìm thấy mẫu định dạng tương thích (Không phải Web Log hợp lệ).")

        log_type = "error" if "error" in best_format else "access"
        return best_format, log_type

    @staticmethod
    def _normalize_access_time(time_str):
        """
        Normalizes Apache/Nginx access log timestamps to ISO8601 UTC.
        """
        try:
            dt = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None

    @staticmethod
    def _normalize_error_time(time_str):
        """
        Normalizes various error log timestamp formats to ISO8601 UTC.
        """
        try:
            dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S.%f %Y')
        except ValueError:
            try:
                dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S %Y')
            except ValueError:
                try:
                    dt = datetime.strptime(time_str, '%Y/%m/%d %H:%M:%S')
                except ValueError:
                    return None
        return dt.replace(tzinfo=timezone.utc).isoformat()

    @staticmethod
    def _process_uri(raw_uri):
        """
        Decodes the URI, prevents infinite recursion, and evaluates depth.
        """
        single_decoded_uri = unquote(raw_uri)
        parsed_single = urlparse(single_decoded_uri)
        current_uri = raw_uri
        decode_depth = 0
        while True:
            decoded_uri = unquote(current_uri)
            if decoded_uri == current_uri or decode_depth >= 5:
                break
            current_uri = decoded_uri
            decode_depth += 1
        return {
            'uri_path': parsed_single.path,
            'uri_query': parsed_single.query,
            'decode_depth': decode_depth,
            'is_evasion_attempt': decode_depth > 2
        }

    def process_log_file(self, filepath, log_format, log_type, stream_to_disk=False, temp_out="temp_parsed.ndjson", time_window=None):
        """
        Processes a log file sequentially or in chunks via multi-threading.
        """
        if log_format not in self.FORMAT_PATTERNS:
            raise ValueError(f"Unsupported format '{log_format}'.")

        def get_chunks():
            chunk = []
            last_timestamp = None
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    if log_type == "error":
                        if line.startswith('['):
                            ts_str = line[1:line.find(']')]
                            last_timestamp = self._normalize_error_time(ts_str) or last_timestamp
                        elif len(line) > 20 and line[0].isdigit() and line[4] == '/':
                            ts_str = line[:19]
                            last_timestamp = self._normalize_error_time(ts_str) or last_timestamp

                    chunk.append((line_num, line))
                    if len(chunk) >= self.chunk_size:
                        yield (chunk, filepath, log_format, log_type, time_window, last_timestamp)
                        chunk = []
                if chunk:
                    yield (chunk, filepath, log_format, log_type, time_window, last_timestamp)

        # Switched to ThreadPoolExecutor to prevent Streamlit + Windows Pickling Crash
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for parsed, errors in executor.map(worker_parse_chunk, get_chunks()):
                if stream_to_disk:
                    with open(temp_out, 'a', encoding='utf-8') as f:
                        for record in parsed:
                            f.write(json.dumps(record) + '\n')
                else:
                    self.parsed_data.extend(parsed)
                self.error_logs.extend(errors)

    def get_timeline_dataframe(self, from_disk=False, temp_out="temp_parsed.ndjson"):
        """
        Transforms parsed JSON dictionaries into a standardized Pandas DataFrame timeline.
        """
        if from_disk:
            if not os.path.exists(temp_out): return pd.DataFrame()
            df = pd.read_json(temp_out, lines=True)
        else:
            if not self.parsed_data: return pd.DataFrame()
            df = pd.DataFrame(self.parsed_data)

        if not df.empty and '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='ISO8601', errors='coerce')
            df = df.dropna(subset=['@timestamp']).sort_values(by='@timestamp').reset_index(drop=True)
        return df

    def export_to_ndjson(self, out_path, from_disk=False, temp_out="temp_parsed.ndjson"):
        """
        Exports the chronologically sorted timeline dataframe to disk as NDJSON.
        """
        df = self.get_timeline_dataframe(from_disk=from_disk, temp_out=temp_out)

        if df.empty:
            open(out_path, 'w').close()
            return

        if '@timestamp' in df.columns:
            df['@timestamp'] = df['@timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

        df.to_json(out_path, orient='records', lines=True, force_ascii=False)