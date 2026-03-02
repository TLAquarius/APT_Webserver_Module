import numpy as np


class SessionFeatureExtractor:
    FEATURE_COLUMNS = [
        # --- BEHAVIOR (ML) ---
        'duration', 'total_requests', 'requests_per_sec',
        'rate_4xx', 'rate_5xx',
        'unique_path_ratio', 'unique_path_count',
        'avg_uri_entropy', 'max_uri_entropy',
        'avg_payload_entropy', 'max_payload_entropy',
        'max_req_bytes', 'avg_req_bytes',

        # --- NEW: EXFILTRATION & DIVERSITY (ML) ---
        'avg_resp_bytes', 'max_resp_bytes', 'total_resp_bytes', 'resp_req_ratio',
        'status_diversity',
        'suspicious_ext_ratio', 'static_ratio',
        'min_interarrival_time',

        # --- CONTEXT (Layer 3) ---
        'start_hour', 'hour_deviation',
        'is_rare_country', 'is_tool_ua',

        # --- SIGNAL (Layer 1) ---
        'rule_match_count',
        'sqli_count', 'xss_count', 'traversal_count'
    ]

    def __init__(self, dominant_country="VN", peak_hour=14):
        self.dominant_country = dominant_country
        self.peak_hour = peak_hour

        # Define extensions to calculate the enumeration ratios
        self.suspicious_exts = {'.php', '.asp', '.aspx', '.jsp', '.cgi', '.bak', '.old', '.sql', '.env', '.log', '.tar',
                                '.gz', '.zip'}
        self.static_exts = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf', '.eot',
                            '.map'}

    def extract_vector(self, s: dict) -> dict:
        def safe_div(a, b): return a / b if b > 0 else 0.0

        duration = (s['last_seen'] - s['start_time']).total_seconds()
        safe_duration = max(duration, 1.0)
        total = s['event_count']

        is_rare = 1.0 if s['country'] != self.dominant_country else 0.0
        hour = s['start_time'].hour
        hour_dist = min(abs(hour - self.peak_hour), 24 - abs(hour - self.peak_hour))
        is_tool = 1.0 if s['ua_type'] in ['tool', 'bot', 'crawler'] else 0.0

        # Extension Enumeration Math
        unique_exts_count = len(s.get('exts', [])) if s.get('exts') else 1.0
        suspicious_count = len([ext for ext in s.get('exts', []) if ext in self.suspicious_exts])
        static_count = len([ext for ext in s.get('exts', []) if ext in self.static_exts])

        return {
            'duration': float(duration),
            'total_requests': float(total),
            'requests_per_sec': total / safe_duration,
            'rate_4xx': safe_div(s['count_4xx'], total),
            'rate_5xx': safe_div(s['count_5xx'], total),
            'unique_path_ratio': safe_div(len(s['paths']), total),
            'unique_path_count': float(len(s['paths'])),
            'avg_uri_entropy': safe_div(s['sum_uri_ent'], total),
            'max_uri_entropy': float(s['max_uri_ent']),
            'avg_payload_entropy': safe_div(s['sum_pl_ent'], total),
            'max_payload_entropy': float(s['max_pl_ent']),

            'max_req_bytes': float(s['max_req_bytes']),
            'avg_req_bytes': safe_div(s['sum_req_bytes'], total),

            # --- NEW: EXFILTRATION & DIVERSITY FEATURES ---
            'avg_resp_bytes': safe_div(s['sum_resp_bytes'], total),
            'max_resp_bytes': float(s['max_resp_bytes']),
            'total_resp_bytes': float(s['sum_resp_bytes']),
            'resp_req_ratio': safe_div(s['sum_resp_bytes'], s['sum_req_bytes']),

            'status_diversity': float(len(s.get('status_set', []))),

            'suspicious_ext_ratio': safe_div(suspicious_count, unique_exts_count),
            'static_ratio': safe_div(static_count, unique_exts_count),

            'min_interarrival_time': float(s.get('min_interarrival', 0.0)),

            # --- CONTEXT ---
            'start_hour': float(hour),
            'hour_deviation': float(hour_dist),
            'is_rare_country': is_rare,
            'is_tool_ua': is_tool,

            # --- SIGNAL ---
            'rule_match_count': float(s['rule_matches']),
            'sqli_count': float(s.get('sqli_count', 0)),
            'xss_count': float(s.get('xss_count', 0)),
            'traversal_count': float(s.get('traversal_count', 0)),
            'evidence_uris': str(s.get('evidence_uris', []))
        }