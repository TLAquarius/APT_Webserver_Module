from filter_layer.sqli_detector import SQLiDetector
from filter_layer.xss_detector import XSSDetector
from filter_layer.os_injection import OSCommandInjectionDetector
from filter_layer.path_traversal import PathTraversalDetector
from filter_layer.ssrf import SSRFDetector
from filter_layer.scanner_detector import ScannerDetector
from filter_layer.protocol_detector import ProtocolManipulationDetector


class Layer1UnifiedEngine:
    """
    Master wrapper for all Layer 1 deterministic filters.
    Processes parsed JSON/Dictionary records and appends Elasticsearch-ready threat tags.
    """

    def __init__(self):
        # Removed print statements to keep console clean for UI logs
        self.sqli = SQLiDetector()
        self.xss = XSSDetector()
        self.rce = OSCommandInjectionDetector()
        self.lfi = PathTraversalDetector()
        self.ssrf = SSRFDetector()
        self.scanner = ScannerDetector()
        self.protocol = ProtocolManipulationDetector()

    def evaluate_record(self, record):
        import urllib.parse
        import base64
        import re

        alerts = set()

        if record.get('event_source') in ['apache_error', 'apache_error_stderr']:
            raw_msg = str(record.get('raw_message', ''))
            if self.rce.inspect_error(raw_msg):
                alerts.add("RCE_Execution_Output")

            alert_list = list(alerts)
            record['layer1_flagged'] = len(alert_list) > 0
            record['layer1_alerts'] = alert_list
            return record

        uri_path = str(record.get('uri_path', ''))
        uri_query = str(record.get('uri_query', ''))
        user_agent = str(record.get('user_agent', ''))
        referer = str(record.get('referer', ''))

        # NEW: Extract request_body if it was provided by the parser
        request_body = str(record.get('request_body', ''))

        if uri_path in ("None", "nan"): uri_path = ""
        if uri_query in ("None", "nan"): uri_query = ""
        if user_agent in ("None", "nan"): user_agent = ""
        if referer in ("None", "nan"): referer = ""
        if request_body in ("None", "nan"): request_body = ""

        current_uri = f"{uri_path} {uri_query}"
        for _ in range(5):
            prev = current_uri
            current_uri = urllib.parse.unquote(current_uri)
            if prev == current_uri:
                break
        decoded_uri = current_uri

        # NEW: Inject request_body into the combined payload
        combined_payload = f"{decoded_uri} {request_body} {user_agent} {referer}"
        expanded_payload = combined_payload

        # -------------------------------------------------------------
        # BASE64 HEURISTIC EXTRACTOR (Kept intact)
        # -------------------------------------------------------------
        b64_patterns = []
        padded_b64 = re.findall(r'\b[A-Za-z0-9+/]{12,}(?:==|=)', decoded_uri)
        b64_patterns.extend(padded_b64)
        long_b64 = re.findall(r'\b[A-Za-z0-9+/]{40,}\b', decoded_uri)
        b64_patterns.extend(long_b64)
        json_b64 = re.findall(r'WyJ[A-Za-z0-9+/]+', decoded_uri)
        b64_patterns.extend(json_b64)
        b64_patterns = list(set(b64_patterns))

        for b64_str in b64_patterns:
            try:
                pad_len = (4 - len(b64_str) % 4) % 4
                padded_str = b64_str + "=" * pad_len
                decoded_bytes = base64.b64decode(padded_str)
                decoded_text = decoded_bytes.decode('ascii', errors='ignore')
                if re.search(r'[a-zA-Z0-9_/\- ]{3,}', decoded_text):
                    expanded_payload += f" {decoded_text} "
            except Exception:
                pass

        hex_patterns = re.findall(r'\b0x([a-fA-F0-9]{8,})\b', decoded_uri)
        for hex_str in hex_patterns:
            try:
                decoded_hex = bytes.fromhex(hex_str).decode('ascii', errors='ignore')
                if re.search(r'[a-zA-Z0-9_/\- ]{3,}', decoded_hex):
                    expanded_payload += f" {decoded_hex} "
            except Exception:
                pass

        sanitized_payload = expanded_payload.lower().replace("'", "").replace('"', '').replace('[', '').replace(']', '')

        # 2. COMBINED PAYLOAD ROUTING
        if self.sqli.inspect_payload(sanitized_payload): alerts.add("SQLi")
        if self.xss.inspect_payload(sanitized_payload): alerts.add("XSS")
        if self.rce.inspect_payload(sanitized_payload): alerts.add("RCE")
        if self.lfi.inspect_payload(sanitized_payload): alerts.add("LFI")
        if self.ssrf.inspect_payload(sanitized_payload): alerts.add("SSRF")
        if self.protocol.inspect_payload(sanitized_payload): alerts.add("Protocol_Anomaly")
        if self.scanner.inspect_payload(user_agent): alerts.add("Scanner_Bot")

        alert_list = list(alerts)
        record['layer1_flagged'] = len(alert_list) > 0
        record['layer1_alerts'] = alert_list

        return record