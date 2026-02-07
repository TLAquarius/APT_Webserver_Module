import numpy as np

class SessionFeatureExtractor:
    FEATURE_COLUMNS = [
        # --- BEHAVIOR (ML) ---
        'duration', 'total_requests', 'requests_per_sec',
        'rate_4xx', 'rate_5xx',
        'unique_path_ratio', 'unique_path_count',
        'avg_uri_entropy', 'max_uri_entropy',
        'avg_payload_entropy', 'max_payload_entropy',

        # --- CONTEXT (Manual Logic - Layer 3) ---
        'start_hour', 'hour_deviation',
        'is_rare_country',
        'is_tool_ua',

        # --- SIGNAL (Layer 1) ---
        'rule_match_count'
    ]

    def __init__(self, dominant_country="VN", peak_hour=14):
        self.dominant_country = dominant_country
        self.peak_hour = peak_hour

    def extract_vector(self, s: dict) -> dict:
        def safe_div(a, b): return a / b if b > 0 else 0.0

        duration = (s['last_seen'] - s['start_time']).total_seconds()
        # CRITICAL FIX: Prevent RPS spikes for single-request sessions
        safe_duration = max(duration, 1.0)
        total = s['event_count']

        # --- CONTEXT LOGIC ---
        is_rare = 1.0 if s['country'] != self.dominant_country else 0.0

        # Simple Distance from peak hour (0-12)
        hour = s['start_time'].hour
        hour_dist = min(abs(hour - self.peak_hour), 24 - abs(hour - self.peak_hour))

        is_tool = 1.0 if s['ua_type'] in ['tool', 'bot', 'crawler'] else 0.0

        return {
            # --- BEHAVIOR ---
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

            # --- CONTEXT ---
            'start_hour': float(hour),
            'hour_deviation': float(hour_dist),
            'is_rare_country': is_rare,
            'is_tool_ua': is_tool,

            # --- SIGNAL ---
            'rule_match_count': float(s['rule_matches'])
        }