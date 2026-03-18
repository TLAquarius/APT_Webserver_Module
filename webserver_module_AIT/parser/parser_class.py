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
    Class parse loại log access và log error của web server.
    Optimized with Multiprocessing and Chunking to handle Big Data without RAM explosion.
    """

    # Access Log: captures %h (IP), %l (identd), %u (UserID), etc.
    ACCESS_PATTERN = re.compile(
        r'(?P<ip>\S+) (?P<identd>\S+) (?P<user_id>\S+) \[(?P<timestamp>.*?)\] '
        r'"(?P<method>\S+)\s+(?P<raw_uri>\S+)\s+(?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<bytes>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    # Error Log Format
    ERROR_PATTERN = re.compile(
        r'\[(?P<timestamp>[^\]]+)\] \[(?P<module>[^\]]+)\] '
        r'(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\] )?'
        r'(?:\[client (?P<client_ip>[^:]+)(?::(?P<client_port>\d+))?\] )?'
        r'(?P<error_message>.*)'
    )

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
        """FIXED: Safely parses Apache Error timestamps with or without microseconds."""
        try:
            # Try parsing with microseconds: Mon Jan 24 03:57:26.696483 2022
            dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S.%f %Y')
        except ValueError:
            try:
                # Fallback for logs without microseconds: Mon Jan 24 03:57:26 2022
                dt = datetime.strptime(time_str, '%a %b %d %H:%M:%S %Y')
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

    @staticmethod
    def _parse_access_chunk(chunk_data):
        chunk, filepath, host_name = chunk_data
        parsed_records = []
        errors = []

        for line_num, line in chunk:
            match = WebServerLogParser.ACCESS_PATTERN.match(line)
            if match:
                log_dict = match.groupdict()
                uri_comp = WebServerLogParser._process_uri(log_dict['raw_uri'])

                parsed_records.append({
                    'event_source': 'apache_access',
                    'host_name': host_name,
                    'event_id': f"acc_{filepath}_{line_num}",
                    '@timestamp': WebServerLogParser._normalize_access_time(log_dict['timestamp']),
                    'source_ip': log_dict['ip'],
                    'user_id': None if log_dict['user_id'] == '-' else log_dict['user_id'],
                    'http_method': log_dict['method'],
                    'status_code': int(log_dict['status']),
                    'bytes_sent': 0 if log_dict['bytes'] == '-' else int(log_dict['bytes']),
                    'user_agent': log_dict['user_agent'],
                    **uri_comp,
                    'raw_message': line.strip()
                })
            else:
                errors.append({'file': filepath, 'line': line_num, 'raw': line.strip()})

        return parsed_records, errors

    @staticmethod
    def _parse_error_chunk(chunk_data):
        chunk, filepath, host_name = chunk_data
        parsed_records = []
        errors = []
        last_timestamp = None

        for line_num, line in chunk:
            match = WebServerLogParser.ERROR_PATTERN.match(line)
            if match:
                log_dict = match.groupdict()
                last_timestamp = WebServerLogParser._normalize_error_time(log_dict['timestamp'])
                parsed_records.append({
                    'event_source': 'apache_error',
                    'host_name': host_name,
                    'event_id': f"err_{filepath}_{line_num}",
                    '@timestamp': last_timestamp,
                    'source_ip': log_dict['client_ip'],
                    'error_module': log_dict['module'],
                    'error_message': log_dict['error_message'],
                    'raw_message': line.strip()
                })
            else:
                raw_line = line.strip()
                if raw_line:
                    parsed_records.append({
                        'event_source': 'apache_error_stderr',
                        'host_name': host_name,
                        'event_id': f"err_stderr_{filepath}_{line_num}",
                        '@timestamp': last_timestamp,
                        'source_ip': None,
                        'error_module': 'stderr',
                        'error_message': 'raw_shell_output',
                        'raw_message': raw_line
                    })
                else:
                    errors.append({'file': filepath, 'line': line_num, 'raw': raw_line})

        return parsed_records, errors

    def parse_access_log(self, filepath, host_name, stream_to_disk=False, temp_out="temp_parsed.ndjson"):
        print(f"[*] Parsing Access Logs (Optimized): {filepath}")

        def get_chunks():
            chunk = []
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    chunk.append((line_num, line))
                    if len(chunk) >= self.chunk_size:
                        yield (chunk, filepath, host_name)
                        chunk = []
                if chunk:
                    yield (chunk, filepath, host_name)

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            for parsed, errors in executor.map(self._parse_access_chunk, get_chunks()):
                if stream_to_disk:
                    with open(temp_out, 'a', encoding='utf-8') as f:
                        for record in parsed:
                            f.write(json.dumps(record) + '\n')
                else:
                    self.parsed_data.extend(parsed)
                self.error_logs.extend(errors)

    def parse_error_log(self, filepath, host_name, stream_to_disk=False, temp_out="temp_parsed.ndjson"):
        print(f"[*] Parsing Error Logs (Optimized): {filepath}")

        def get_chunks():
            chunk = []
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    chunk.append((line_num, line))
                    if len(chunk) >= self.chunk_size:
                        yield (chunk, filepath, host_name)
                        chunk = []
                if chunk:
                    yield (chunk, filepath, host_name)

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            for parsed, errors in executor.map(self._parse_error_chunk, get_chunks()):
                if stream_to_disk:
                    with open(temp_out, 'a', encoding='utf-8') as f:
                        for record in parsed:
                            f.write(json.dumps(record) + '\n')
                else:
                    self.parsed_data.extend(parsed)
                self.error_logs.extend(errors)

    def get_timeline_dataframe(self, from_disk=False, temp_out="temp_parsed.ndjson"):
        if from_disk:
            if not os.path.exists(temp_out):
                print("[!] Intermediate file not found.")
                return pd.DataFrame()
            print("[*] Loading timeline from disk to save RAM...")
            df = pd.read_json(temp_out, lines=True)
        else:
            if not self.parsed_data:
                return pd.DataFrame()
            df = pd.DataFrame(self.parsed_data)

        # FIX: Tell Pandas to expect mixed ISO8601 formats (with and without microseconds)
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='ISO8601')
        df = df.sort_values(by='@timestamp').reset_index(drop=True)
        return df

    def export_to_ndjson(self, output_filepath, from_disk=False, temp_out="temp_parsed.ndjson"):
        df = self.get_timeline_dataframe(from_disk=from_disk, temp_out=temp_out)
        if df.empty:
            print("[!] No data to export.")
            return

        records = [
            {k: v for k, v in record.items() if pd.notna(v)}
            for record in df.to_dict(orient='records')
        ]

        with open(output_filepath, 'w', encoding='utf-8') as f:
            for event in records:
                if isinstance(event.get('@timestamp'), pd.Timestamp):
                    event['@timestamp'] = event['@timestamp'].isoformat()
                f.write(json.dumps(event) + '\n')
        print(f"[+] Exported {len(records)} unified events to {output_filepath}")