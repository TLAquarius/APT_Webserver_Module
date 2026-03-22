import re
import pandas as pd
import json
from urllib.parse import unquote, urlparse
from datetime import datetime, timezone
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
import os


# =================================================================
# 🟢 HÀM WORKER NẰM NGOÀI CLASS (TRÁNH LỖI PICKLING MULTIPROCESSING)
# =================================================================
def worker_parse_chunk(chunk_data):
    """Hàm xử lý đa tiến trình độc lập, an toàn tuyệt đối với Multiprocessing"""
    chunk, filepath, log_format, log_type = chunk_data
    parsed_records, errors = [], []
    pattern = WebServerLogParser.FORMAT_PATTERNS.get(log_format)
    last_timestamp = None

    for line_num, line in chunk:
        match = pattern.match(line)
        if match:
            log_dict = match.groupdict()
            if log_type == "access":
                uri_comp = WebServerLogParser._process_uri(log_dict.get('raw_uri', ''))
                parsed_records.append({
                    'event_source': log_format,
                    'event_id': f"acc_{os.path.basename(filepath)}_{line_num}",
                    '@timestamp': WebServerLogParser._normalize_access_time(log_dict.get('timestamp')),
                    'source_ip': log_dict.get('ip'),
                    'user_id': None if log_dict.get('user_id') == '-' else log_dict.get('user_id'),
                    'http_method': log_dict.get('method'),
                    'status_code': int(log_dict.get('status', 0)),
                    'bytes_sent': 0 if log_dict.get('bytes') == '-' else int(log_dict.get('bytes', 0)),
                    'user_agent': log_dict.get('user_agent', ''),
                    # Hứng thêm Virtual Host (Nếu có)
                    'vhost': log_dict.get('vhost', ''),
                    **uri_comp,
                    'raw_message': line.strip()
                })
            elif log_type == "error":
                timestamp_str = log_dict.get('timestamp')
                if timestamp_str: last_timestamp = WebServerLogParser._normalize_error_time(timestamp_str)
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
            if line.strip(): errors.append({'file': os.path.basename(filepath), 'line': line_num, 'raw': line.strip()})
    return parsed_records, errors


class WebServerLogParser:
    FORMAT_PATTERNS = {
        # 🟢 THÊM MỚI: Định dạng VHOST COMBINED (Dành cho file log của bạn)
        "vhost_combined_access": re.compile(
            r'(?P<vhost>\S+) (?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        ),
        "combined_access": re.compile(
            r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
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
        self.chunk_size = chunk_size
        self.max_workers = max_workers or mp.cpu_count()
        self.parsed_data = []
        self.error_logs = []

    @classmethod
    def auto_detect_format(cls, filepath, sample_lines=20):
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
        try:
            dt = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None

    @staticmethod
    def _normalize_error_time(time_str):
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

    def process_log_file(self, filepath, log_format, log_type, stream_to_disk=False, temp_out="temp_parsed.ndjson"):
        if log_format not in self.FORMAT_PATTERNS: raise ValueError(f"Unsupported format '{log_format}'.")

        def get_chunks():
            chunk = []
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    chunk.append((line_num, line))
                    if len(chunk) >= self.chunk_size:
                        yield (chunk, filepath, log_format, log_type)
                        chunk = []
                if chunk: yield (chunk, filepath, log_format, log_type)

        # 🟢 SỬA DÒNG NÀY: Dùng ThreadPoolExecutor thay vì ProcessPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for parsed, errors in executor.map(worker_parse_chunk, get_chunks()):
                if stream_to_disk:
                    with open(temp_out, 'a', encoding='utf-8') as f:
                        for record in parsed: f.write(json.dumps(record) + '\n')
                else:
                    self.parsed_data.extend(parsed)
                self.error_logs.extend(errors)

    def get_timeline_dataframe(self, from_disk=False, temp_out="temp_parsed.ndjson"):
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
        df = self.get_timeline_dataframe(from_disk=from_disk, temp_out=temp_out)

        if df.empty:
            open(out_path, 'w').close()
            return

        if '@timestamp' in df.columns:
            df['@timestamp'] = df['@timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

        df.to_json(out_path, orient='records', lines=True, force_ascii=False)