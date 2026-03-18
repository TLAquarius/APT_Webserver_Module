import json
import csv
from datetime import datetime, timezone
import ipaddress
import geoip2.database
import geoip2.errors


class UserSession:
    """Stateful memory object tracking an IP's behavior and building its timeline."""
    __slots__ = [
        'ip', 'start_time', 'last_seen', 'total_logs', 'error_404', 'error_403', 'error_50x',
        'post_count', 'rare_method_count', 'bytes_sent_total', 'max_resp_bytes', 'unique_uris',
        'unique_uas', 'unique_statuses', 'l1_alert_count', 'l1_alert_types', 'raw_logs',
        'static_asset_count', 'suspicious_ext_count', 'min_interarrival_sec', 'last_host',
        'total_uri_depth', 'parent_tracking_id'
    ]

    STATIC_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.woff', '.woff2', '.svg'}
    SUSPICIOUS_EXTS = {'.bak', '.sql', '.env', '.old', '.log', '.git', '.sh', '.zip', '.tar.gz', '.inc', '.php'}
    STANDARD_METHODS = {'GET', 'POST', 'HEAD'}

    def __init__(self, ip, start_time, parent_tracking_id=None):
        self.ip = ip
        self.start_time = start_time
        self.last_seen = start_time
        self.last_host = None

        # Entity Linking: Retain parent ID if split, else create a new one
        self.parent_tracking_id = parent_tracking_id if parent_tracking_id else f"{self.ip}_{self.start_time.strftime('%Y%m%d%H%M%S')}"

        self.total_logs = 0
        self.error_404 = 0
        self.error_403 = 0
        self.error_50x = 0
        self.post_count = 0
        self.rare_method_count = 0
        self.bytes_sent_total = 0
        self.max_resp_bytes = 0

        self.unique_uris = set()
        self.unique_uas = set()
        self.unique_statuses = set()

        self.static_asset_count = 0
        self.suspicious_ext_count = 0
        self.total_uri_depth = 0
        self.min_interarrival_sec = float('inf')

        self.l1_alert_count = 0
        self.l1_alert_types = set()

        self.raw_logs = []

    def _get_extension(self, uri):
        if not uri or '?' in uri: return ""
        parts = uri.split('.')
        if len(parts) > 1:
            return "." + parts[-1].lower()
        return ""

    def update(self, record, log_time):
        if self.total_logs > 0:
            time_diff = (log_time - self.last_seen).total_seconds()
            if 0 <= time_diff < self.min_interarrival_sec:
                self.min_interarrival_sec = time_diff

        self.last_seen = log_time
        self.last_host = record.get('host_name')
        self.total_logs += 1
        self.raw_logs.append(record)

        uri = record.get('uri_path')
        if uri:
            self.unique_uris.add(uri)
            self.total_uri_depth += str(uri).count('/')

            ext = self._get_extension(uri)
            if ext in self.STATIC_EXTS:
                self.static_asset_count += 1
            elif ext in self.SUSPICIOUS_EXTS:
                self.suspicious_ext_count += 1

        ua = record.get('user_agent')
        if ua: self.unique_uas.add(ua)

        if record.get('layer1_flagged'):
            self.l1_alert_count += 1
            for alert in record.get('layer1_alerts', []):
                self.l1_alert_types.add(alert)

        method = record.get('http_method')
        if method == 'POST':
            self.post_count += 1
        elif method and method not in self.STANDARD_METHODS:
            self.rare_method_count += 1

        status = record.get('status_code')
        if status is not None:
            status_int = int(status)
            self.unique_statuses.add(status_int)
            if status_int == 404:
                self.error_404 += 1
            elif status_int == 403:
                self.error_403 += 1
            elif status_int >= 500:
                self.error_50x += 1

        bytes_sent = record.get('bytes_sent', 0)
        self.bytes_sent_total += bytes_sent
        if bytes_sent > self.max_resp_bytes:
            self.max_resp_bytes = bytes_sent

    def extract_data(self, geo_reader=None):
        duration_sec = (self.last_seen - self.start_time).total_seconds()
        safe_duration = max(1.0, duration_sec)

        is_external = 0
        geo_country = "LOCAL"

        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if not ip_obj.is_private:
                is_external = 1
                if geo_reader:
                    try:
                        geo_response = geo_reader.city(self.ip)
                        geo_country = geo_response.country.iso_code if geo_response.country.iso_code else "UNKNOWN"
                    except geoip2.errors.AddressNotFoundError:
                        geo_country = "UNKNOWN"
        except ValueError:
            is_external = 1
            geo_country = "UNKNOWN"

        start_hour = self.start_time.hour
        is_off_hours = 1 if (start_hour < 6 or start_hour > 18) else 0

        # Create a unique session ID for this specific chunk, but retain the parent ID for linking
        session_id = f"{self.ip}_{self.start_time.strftime('%Y%m%d%H%M%S')}"
        min_arrival = 0.0 if self.min_interarrival_sec == float('inf') else self.min_interarrival_sec
        avg_depth = self.total_uri_depth / self.total_logs if self.total_logs > 0 else 0

        features = {
            "session_id": session_id,
            "parent_tracking_id": self.parent_tracking_id,
            "source_ip": self.ip,
            "geo_country": geo_country,
            "is_external_ip": is_external,
            "is_off_hours": is_off_hours,
            "session_duration_sec": round(duration_sec, 2),
            "total_requests": self.total_logs,
            "req_per_min": round(self.total_logs / (safe_duration / 60.0), 2),
            "min_interarrival_sec": round(min_arrival, 4),
            "avg_uri_depth": round(avg_depth, 2),
            "error_404_rate": round(self.error_404 / self.total_logs, 4),
            "error_403_rate": round(self.error_403 / self.total_logs, 4),
            "error_50x_rate": round(self.error_50x / self.total_logs, 4),
            "post_rate": round(self.post_count / self.total_logs, 4),
            "rare_method_rate": round(self.rare_method_count / self.total_logs, 4),
            "unique_path_ratio": round(len(self.unique_uris) / self.total_logs, 4),
            "static_asset_ratio": round(self.static_asset_count / self.total_logs, 4),
            "suspicious_ext_rate": round(self.suspicious_ext_count / self.total_logs, 4),
            "status_diversity": len(self.unique_statuses),
            "unique_uas": len(self.unique_uas),
            "avg_payload_bytes": round(self.bytes_sent_total / self.total_logs, 2),
            "max_resp_bytes": self.max_resp_bytes,
            "l1_alert_count": self.l1_alert_count,
            "l1_alert_types": "|".join(self.l1_alert_types)
        }

        timeline_object = {
            "session_id": session_id,
            "parent_tracking_id": self.parent_tracking_id,
            "source_ip": self.ip,
            "start_time": self.start_time.isoformat(),
            "end_time": self.last_seen.isoformat(),
            "total_events": self.total_logs,
            "timeline": self.raw_logs
        }

        return features, timeline_object


class StatefulStreamingEngine:
    def __init__(self, timeout_minutes=15, max_session_hours=2, max_events_per_session=3000,
                 geo_db_path="GeoLite2-City.mmdb"):
        self.timeout_seconds = timeout_minutes * 60
        self.max_session_seconds = max_session_hours * 3600
        self.max_events = max_events_per_session

        self.active_sessions = {}
        self.global_watermark = None

        self.completed_features = []
        self.completed_timelines = []

        self.geo_reader = None
        try:
            self.geo_reader = geoip2.database.Reader(geo_db_path)
            print(f"[+] Successfully loaded GeoIP Database: {geo_db_path}")
        except FileNotFoundError:
            print(f"[-] Warning: GeoIP Database not found at {geo_db_path}. Geo-country will default to UNKNOWN.")

    def _parse_time(self, time_str):
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))

    def _find_correlated_ip(self, log_time, host_name, time_window=2.0):
        best_ip = None
        smallest_diff = float('inf')

        for ip, session in self.active_sessions.items():
            if session.last_host == host_name:
                diff = (log_time - session.last_seen).total_seconds()
                if 0 <= diff <= time_window:
                    if diff < smallest_diff:
                        smallest_diff = diff
                        best_ip = ip
        return best_ip

    def _flush_session(self, ip):
        features, timeline = self.active_sessions[ip].extract_data(geo_reader=self.geo_reader)
        self.completed_features.append(features)
        self.completed_timelines.append(timeline)
        del self.active_sessions[ip]

    def _garbage_collect(self):
        if not self.global_watermark: return
        stale_ips = [ip for ip, session in self.active_sessions.items()
                     if (self.global_watermark - session.last_seen).total_seconds() > self.timeout_seconds]
        for ip in stale_ips:
            self._flush_session(ip)

    def process_stream(self, input_ndjson, output_csv, output_json):
        print(
            f"[*] Starting Dual-Output Sessionizer (Gap: {self.timeout_seconds / 60} mins, Max Span: {self.max_session_seconds / 3600} hrs)...")
        total_logs = 0

        with open(input_ndjson, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                total_logs += 1
                record = json.loads(line)

                try:
                    log_time = self._parse_time(record['@timestamp'])
                except Exception:
                    continue

                ip = record.get('source_ip')

                if not ip or ip == '-':
                    if record.get('event_source') in ['apache_error', 'apache_error_stderr']:
                        ip = self._find_correlated_ip(log_time, record.get('host_name'))

                    if not ip:
                        continue

                if not self.global_watermark or log_time > self.global_watermark:
                    self.global_watermark = log_time

                if total_logs % 20000 == 0:
                    print(f"  -> Processed {total_logs:,} logs. Active sessions in RAM: {len(self.active_sessions)}")
                    self._garbage_collect()

                if ip in self.active_sessions:
                    session = self.active_sessions[ip]
                    idle_time = (log_time - session.last_seen).total_seconds()
                    absolute_time = (log_time - session.start_time).total_seconds()

                    if idle_time > self.timeout_seconds:
                        # Natural expiration (User went idle). Start a completely new session.
                        self._flush_session(ip)
                        self.active_sessions[ip] = UserSession(ip, log_time)
                    elif absolute_time > self.max_session_seconds or session.total_logs >= self.max_events:
                        # Forced boundary split. Retain the parent_tracking_id to link the chunks.
                        parent_id = session.parent_tracking_id
                        self._flush_session(ip)
                        self.active_sessions[ip] = UserSession(ip, log_time, parent_tracking_id=parent_id)

                    self.active_sessions[ip].update(record, log_time)
                else:
                    self.active_sessions[ip] = UserSession(ip, log_time)
                    self.active_sessions[ip].update(record, log_time)

        for ip in list(self.active_sessions.keys()):
            self._flush_session(ip)

        if self.geo_reader:
            self.geo_reader.close()

        print(f"\n[+] REACHED END OF FILE. Total lines read: {total_logs:,}")
        print(f"[+] Built {len(self.completed_features):,} distinct timelines.")
        self._export_data(output_csv, output_json)

    def _export_data(self, csv_path, json_path):
        if not self.completed_features: return
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.completed_features[0].keys())
            writer.writeheader()
            writer.writerows(self.completed_features)

        with open(json_path, 'w', encoding='utf-8') as f:
            for timeline in self.completed_timelines:
                f.write(json.dumps(timeline) + "\n")

        print(f"[+] Exported ML Features to: {csv_path}")
        print(f"[+] Exported Full Timelines to: {json_path}")


if __name__ == '__main__':
    INPUT_FILE = "../webserver_module_AIT/layer1_tagged_timeline.json"
    OUTPUT_CSV = "ml_features.csv"
    OUTPUT_JSON = "session_timelines.json"

    engine = StatefulStreamingEngine(timeout_minutes=10, max_session_hours=2, max_events_per_session=3000)
    engine.process_stream(INPUT_FILE, OUTPUT_CSV, OUTPUT_JSON)