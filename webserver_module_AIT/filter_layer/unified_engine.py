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
        print("[*] Initializing Layer 1 Unified Engine...")
        self.sqli = SQLiDetector()
        self.xss = XSSDetector()
        self.rce = OSCommandInjectionDetector()
        self.lfi = PathTraversalDetector()
        self.ssrf = SSRFDetector()
        self.scanner = ScannerDetector()
        self.protocol = ProtocolManipulationDetector()
        print("[+] All 7 Deterministic Modules Loaded.")

    def evaluate_record(self, record):
        import urllib.parse
        import base64
        import re

        alerts = set()

        # NEW: Route error logs immediately to the OSCommandInjectionDetector's error scanner
        # This catches the RCE execution output (stderr dumps) that we integrated into the parser!
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

        if uri_path in ("None", "nan"): uri_path = ""
        if uri_query in ("None", "nan"): uri_query = ""
        if user_agent in ("None", "nan"): user_agent = ""
        if referer in ("None", "nan"): referer = ""

        # ENHANCEMENT: Implement central recursive URL decoding to replace the removed logic in detectors
        # This decodes up to 5 times to defeat evasion, but only does it ONCE per log line.
        current_uri = f"{uri_path} {uri_query}"
        for _ in range(5):
            prev = current_uri
            current_uri = urllib.parse.unquote(current_uri)
            if prev == current_uri:
                break
        decoded_uri = current_uri

        # Base payload now uses the deeply decoded URI
        combined_payload = f"{decoded_uri} {user_agent} {referer}"
        expanded_payload = combined_payload

        # -------------------------------------------------------------
        # CONSTRAINED BASE64 HEURISTIC EXTRACTOR (FP Reduction)
        # -------------------------------------------------------------
        # We only extract Base64 if it meets one of these threat profiles:
        # 1. It explicitly ends in padding (== or =) indicating formal encoding.
        # 2. It is suspiciously long (>= 40 chars) which usually indicates a serialized payload or full script.
        # 3. It is wrapped in JSON brackets (e.g., %5BWyJ...%5D) indicating an array payload.

        b64_patterns = []

        # Profile 1: Explicitly Padded Base64 (The classic signature)
        padded_b64 = re.findall(r'\b[A-Za-z0-9+/]{12,}(?:==|=)', decoded_uri)
        b64_patterns.extend(padded_b64)

        # Profile 2: Unpadded, but suspiciously long (usually a full script)
        long_b64 = re.findall(r'\b[A-Za-z0-9+/]{40,}\b', decoded_uri)
        b64_patterns.extend(long_b64)

        # Profile 3: Unpadded, but wrapped in URL-encoded JSON brackets (WyJ...XQ)
        # This specifically targets the attacker's web shell payload format in the AIT dataset
        json_b64 = re.findall(r'WyJ[A-Za-z0-9+/]+', decoded_uri)
        b64_patterns.extend(json_b64)

        # Deduplicate the found patterns
        b64_patterns = list(set(b64_patterns))

        for b64_str in b64_patterns:
            try:
                pad_len = (4 - len(b64_str) % 4) % 4
                padded_str = b64_str + "=" * pad_len

                decoded_bytes = base64.b64decode(padded_str)
                # Decode as ASCII, strictly ignoring non-printable binary garbage that causes FPs
                decoded_text = decoded_bytes.decode('ascii', errors='ignore')

                # Only append if the decoded text actually looks like readable English/Code
                # This prevents binary garbage from triggering the 'id' or 'cat' regex
                if re.search(r'[a-zA-Z0-9_/\- ]{3,}', decoded_text):
                    expanded_payload += f" {decoded_text} "
            except Exception:
                pass

        # Hexadecimal Extractor
        hex_patterns = re.findall(r'\b0x([a-fA-F0-9]{8,})\b', decoded_uri)
        for hex_str in hex_patterns:
            try:
                decoded_hex = bytes.fromhex(hex_str).decode('ascii', errors='ignore')
                if re.search(r'[a-zA-Z0-9_/\- ]{3,}', decoded_hex):
                    expanded_payload += f" {decoded_hex} "
            except Exception:
                pass

        # JSON & Quote Sanitization
        sanitized_payload = expanded_payload.lower().replace("'", "").replace('"', '').replace('[', '').replace(']', '')
        # -------------------------------------------------------------

        # 2. COMBINED PAYLOAD ROUTING
        # UPDATED: Changed all inspect_uri and inspect_ua to inspect_payload to match unified interface.
        # REMOVED: The second empty string argument ("") since the interface now takes a single payload.
        if self.sqli.inspect_payload(sanitized_payload):
            alerts.add("SQLi")
        if self.xss.inspect_payload(sanitized_payload):
            alerts.add("XSS")
        if self.rce.inspect_payload(sanitized_payload):
            alerts.add("RCE")

        # 3. URI-SPECIFIC ROUTING
        if self.lfi.inspect_payload(sanitized_payload):
            alerts.add("LFI")
        if self.ssrf.inspect_payload(sanitized_payload):
            alerts.add("SSRF")
        if self.protocol.inspect_payload(sanitized_payload):
            alerts.add("Protocol_Anomaly")

        # 4. HEADER-SPECIFIC ROUTING
        if self.scanner.inspect_payload(user_agent):
            alerts.add("Scanner_Bot")

        # 5. MUTATE AND RETURN RECORD
        alert_list = list(alerts)
        record['layer1_flagged'] = len(alert_list) > 0
        record['layer1_alerts'] = alert_list

        return record