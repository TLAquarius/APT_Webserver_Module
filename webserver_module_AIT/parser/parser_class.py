import re
import pandas as pd
import json
from urllib.parse import unquote, urlparse
from datetime import datetime, timezone
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import os


class WebServerLogParser:
    """
    Parses various formats of Web Server access and error logs.
    Optimized with Multiprocessing and Chunking to handle Big Data safely.
    Updated for Dynamic Format Support.
    """

    # =================================================================
    # 1. DYNAMIC REGEX PATTERNS REGISTRY
    # Expand this dictionary to support new log formats in the future.
    # =================================================================
    FORMAT_PATTERNS = {
        # Standard Apache/Nginx Combined Access Log
        "combined_access": re.compile(
            r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        ),
        # Basic Common Log Format (No Referer or User-Agent)
        "common_access": re.compile(
            r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>\S+)'
        ),
        # Standard Apache Error Log
        "apache_error": re.compile(
            r'\[(?P<timestamp>[^\]]+)\] \[(?P<module>[^\]]+)\] '
            r'(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\] )?'
            r'(?:\[client (?P<client_ip>[^:]+)(?::(?P<client_port>\d+))?\] )?'
            r'(?P<error_message>.*)'
        ),
        # Standard Nginx Error Log
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

    @staticmethod
    def _normalize_access_time(time_str):
        try:
            dt = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None

    @staticmethod
    def _normalize_error_time(time_str):
        """Safely parses Error timestamps with multiple fallbacks."""
        try:
            # Try Apache with microseconds: Mon Jan 24 03:57:26.696483 2022
            dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S.%f %Y')
        except ValueError:
            try:
                # Try Apache without microseconds: Mon Jan 24 03:57:26 2022
                dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S %Y')
            except ValueError:
                try:
                    # Try Nginx format: 2022/01/24 03:57:26
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
        max_depth = 5

        while True:
            decoded_uri = unquote(current_uri)
            if decoded_uri == current_uri:
                break
            current_uri = decoded_uri
            decode_depth += 1
            if decode_depth >= max_depth:
                break

        return {
            'uri_path': parsed_single.path,
            'uri_query': parsed_single.query,
            'decode_depth': decode_depth,
            'is_evasion_attempt': decode_depth > 2
        }

    # =================================================================
    # 2. MULTIPROCESSING WORKER FUNCTIONS
    # =================================================================
    @staticmethod
    def _parse_chunk(chunk_data):
        """
        Universal chunk parser that accepts the regex pattern dynamically.
        chunk_data = (chunk_list, filepath, log_format_key, log_type)
        """
        chunk, filepath, log_format, log_type = chunk_data
        parsed_records = []
        errors = []

        pattern = WebServerLogParser.FORMAT_PATTERNS.get(log_format)
        if not pattern:
            raise ValueError(f"Unsupported log format: {log_format}")

        last_timestamp = None

        for line_num, line in chunk:
            match = pattern.match(line)
            if match:
                log_dict = match.groupdict()

                if log_type == "access":
                    # --- Logic for Access Logs ---
                    uri_comp = WebServerLogParser._process_uri(log_dict.get('raw_uri', ''))
                    parsed_records.append({
                        'event_source': f'{log_format}',
                        'event_id': f"acc_{os.path.basename(filepath)}_{line_num}",
                        '@timestamp': WebServerLogParser._normalize_access_time(log_dict.get('timestamp')),
                        'source_ip': log_dict.get('ip'),
                        'user_id': None if log_dict.get('user_id') == '-' else log_dict.get('user_id'),
                        'http_method': log_dict.get('method'),
                        'status_code': int(log_dict.get('status', 0)),
                        'bytes_sent': 0 if log_dict.get('bytes') == '-' else int(log_dict.get('bytes', 0)),
                        'user_agent': log_dict.get('user_agent', ''),
                        **uri_comp,
                        'raw_message': line.strip()
                    })
                elif log_type == "error":
                    # --- Logic for Error Logs ---
                    timestamp_str = log_dict.get('timestamp')
                    if timestamp_str:
                        last_timestamp = WebServerLogParser._normalize_error_time(timestamp_str)

                    parsed_records.append({
                        'event_source': f'{log_format}',
                        'event_id': f"err_{os.path.basename(filepath)}_{line_num}",
                        '@timestamp': last_timestamp,
                        'source_ip': log_dict.get('client_ip', None),
                        'error_module': log_dict.get('module', 'core'),
                        'error_message': log_dict.get('error_message', ''),
                        'raw_message': line.strip()
                    })
            else:
                # If regex fails, record the error for UI reporting
                raw_line = line.strip()
                if raw_line:  # Ignore completely empty lines
                    errors.append({'file': os.path.basename(filepath), 'line': line_num, 'raw': raw_line})

        return parsed_records, errors

    # =================================================================
    # 3. PUBLIC API (CALLED BY BACKEND_BRIDGE)
    # =================================================================
    def process_log_file(self, filepath, log_format, log_type, stream_to_disk=False, temp_out="temp_parsed.ndjson"):
        """
        Main function to process a single log file based on its dynamic format.
        log_type must be "access" or "error".
        """
        if log_format not in self.FORMAT_PATTERNS:
            raise ValueError(f"Log format '{log_format}' is not registered in FORMAT_PATTERNS.")

        print(f"[*] Parsing {log_type.upper()} Log [{log_format}]: {filepath}")

        def get_chunks():
            chunk = []
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    chunk.append((line_num, line))
                    if len(chunk) >= self.chunk_size:
                        # Yield the chunk along with metadata needed by the worker
                        yield (chunk, filepath, log_format, log_type)
                        chunk = []
                if chunk:
                    yield (chunk, filepath, log_format, log_type)

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            for parsed, errors in executor.map(self._parse_chunk, get_chunks()):
                if stream_to_disk:
                    with open(temp_out, 'a', encoding='utf-8') as f:
                        for record in parsed:
                            f.write(json.dumps(record) + '\n')
                else:
                    self.parsed_data.extend(parsed)
                self.error_logs.extend(errors)

    def get_timeline_dataframe(self, from_disk=False, temp_out="temp_parsed.ndjson"):
        """Compiles parsed data into a chronologically sorted Pandas DataFrame."""
        if from_disk:
            if not os.path.exists(temp_out):
                return pd.DataFrame()
            df = pd.read_json(temp_out, lines=True)
        else:
            if not self.parsed_data:
                return pd.DataFrame()
            df = pd.DataFrame(self.parsed_data)

        if not df.empty and '@timestamp' in df.columns:
            # Handles mixed ISO8601 formats
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='ISO8601')
            df = df.sort_values(by='@timestamp').reset_index(drop=True)
        return df

    def get_parsing_stats(self):
        """Returns statistics about the parsing process for the UI."""
        total_success = len(self.parsed_data)
        total_failed = len(self.error_logs)
        total_lines = total_success + total_failed
        success_rate = (total_success / total_lines * 100) if total_lines > 0 else 0

        return {
            "total_lines": total_lines,
            "parsed_successfully": total_success,
            "failed_lines": total_failed,
            "success_rate_percent": round(success_rate, 2),
            "sample_errors": self.error_logs[:5]  # Top 5 errors for debugging
        }