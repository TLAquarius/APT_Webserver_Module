import math
import re
import os
import collections
from datetime import timedelta
from typing import Dict, Optional
from urllib.parse import unquote_plus
from functools import lru_cache

from parsing.schema import WebLogEvent

try:
    import geoip2.database

    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class LogEnricher:
    STATIC_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf', '.eot', '.map'}

    def __init__(self, geo_db_path="data/GeoLite2-City.mmdb"):
        self.geo_reader = None
        if GEOIP_AVAILABLE and os.path.exists(geo_db_path):
            self.geo_reader = geoip2.database.Reader(geo_db_path)

    @lru_cache(maxsize=16384)
    def _get_country(self, ip: str) -> str:
        if not self.geo_reader or not ip:
            return "XX"
        try:
            res = self.geo_reader.city(ip)
            return res.country.iso_code or "XX"
        except:
            return "XX"

    def is_static(self, path: str) -> bool:
        return path.lower().endswith(tuple(self.STATIC_EXTS)) if path else False

    def enrich_event(self, event: WebLogEvent) -> dict:
        raw_payload = (event.query_string or "") + (event.request_body or "")

        full_payload_decoded = unquote_plus(raw_payload)
        decoded_path = unquote_plus(event.request_path)

        uri_entropy = self._calc_entropy(event.request_path)
        payload_entropy = self._calc_entropy(raw_payload)

        ext = self._get_ext(decoded_path)
        ua_type = self._classify_ua(event.user_agent)
        country = self._get_country(event.source_ip)

        return {
            "timestamp": event.event_time,
            "ip": event.source_ip,
            "session_id": event.session_id,
            "path": decoded_path,
            "full_payload": full_payload_decoded,
            "uri_entropy": uri_entropy,
            "payload_entropy": payload_entropy,
            "req_bytes": event.request_bytes or 0,
            "resp_bytes": event.response_bytes or 0,
            "status_code": event.status_code,
            "ext": ext,
            "ua_type": ua_type,
            "country": country,
            "label": event.label
        }

    @lru_cache(maxsize=100000)
    def _calc_entropy(self, text: str) -> float:
        if not text: return 0.0
        length = len(text)
        counts = collections.Counter(text).values()
        return -sum((c / length) * math.log2(c / length) for c in counts)

    def _get_ext(self, path: str) -> str:
        if '.' not in path: return ""
        last = path.split('.')[-1].split('/')[0]
        return f".{last.lower()}" if len(last) <= 4 and last.isalnum() else ""

    def _classify_ua(self, ua: Optional[str]) -> str:
        if not ua: return "unknown"
        ua = ua.lower()
        if any(x in ua for x in ["googlebot", "bingbot", "ahrefs", "yandex"]): return "crawler"
        if any(x in ua for x in ["bot", "spider", "crawl"]): return "bot"
        if any(x in ua for x in ["mobile", "android", "iphone", "ipad"]): return "mobile"
        if any(x in ua for x in ["curl", "python", "wget", "go-http", "nmap", "sqlmap"]): return "tool"
        if any(x in ua for x in ["mozilla", "chrome", "safari", "edge"]): return "browser"
        return "unknown"


class OwaspRuleEngine:
    def __init__(self):
        self.sqli_re = re.compile(
            r"union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into\s+.*\s+values|drop\s+(table|database)|waitfor\s+delay|exec(\s|\+)+(xp|sp)_|(or|and)\s+['0-9]+=['0-9]+|--|;\s*$",
            re.I)
        self.xss_re = re.compile(r"<script|javascript:|on\w+\s*=|alert\(|<img\s+.*?onerror|&#|%3cscript", re.I)
        self.traversal_re = re.compile(r"\.\./|%2e%2e%2f|/etc/passwd|c:\\windows|cmd\.exe|/bin/sh", re.I)

    def evaluate(self, enriched: dict) -> dict:
        content = enriched['path'] + " " + enriched['full_payload']
        if not content.strip():
            return {"is_sqli": False, "is_xss": False, "is_traversal": False}

        content_lower = content.lower()
        is_sqli, is_xss, is_traversal = False, False, False

        if any(c in content_lower for c in ("'", "select", "union", "insert", "drop", "--", ";")):
            is_sqli = bool(self.sqli_re.search(content))

        if any(c in content_lower for c in ("<", ">", "script", "alert", "onerror", "%3c", "&#")):
            is_xss = bool(self.xss_re.search(content))

        if any(c in content_lower for c in (".", "%2e", "etc", "windows", "bin")):
            is_traversal = bool(self.traversal_re.search(content))

        return {"is_sqli": is_sqli, "is_xss": is_xss, "is_traversal": is_traversal}


class Sessionizer:
    def __init__(self, timeout_mins=30, max_duration_mins=60):
        self.timeout = timedelta(minutes=timeout_mins)
        self.max_duration = timedelta(minutes=max_duration_mins)
        self.active = {}

    def process_event(self, enriched: dict, rules: dict):
        key = enriched['session_id'] if enriched.get('session_id') else enriched['ip']
        ts = enriched['timestamp']

        if key in self.active:
            s = self.active[key]
            is_idle = (ts - s['last_seen']) > self.timeout
            is_too_long = (ts - s['start_time']) > self.max_duration

            if is_idle or is_too_long:
                yield s
                self._create(key, enriched, rules)
            else:
                self._update(s, enriched, rules)
        else:
            self._create(key, enriched, rules)

    def flush(self):
        for session in self.active.values(): yield session
        self.active.clear()

    def _create(self, key, e, rules):
        self.active[key] = {
            "key": key, "ip": e['ip'],
            "start_time": e['timestamp'], "last_seen": e['timestamp'],
            "event_count": 1,
            "min_interarrival": 0.0,
            "sum_req_bytes": e['req_bytes'], "max_req_bytes": e['req_bytes'],
            "sum_resp_bytes": e['resp_bytes'], "max_resp_bytes": e['resp_bytes'],
            "count_4xx": 1 if 400 <= e['status_code'] < 500 else 0,
            "count_5xx": 1 if 500 <= e['status_code'] < 600 else 0,
            "status_set": {e['status_code']},
            "sum_uri_ent": e['uri_entropy'], "max_uri_ent": e['uri_entropy'],
            "sum_pl_ent": e['payload_entropy'], "max_pl_ent": e['payload_entropy'],
            "rule_matches": 1 if any(rules.values()) else 0,
            "sqli_count": 1 if rules.get('is_sqli') else 0,
            "xss_count": 1 if rules.get('is_xss') else 0,
            "traversal_count": 1 if rules.get('is_traversal') else 0,
            "flags": {k for k, v in rules.items() if v},

            # --- FIXED: Initialize the evidence_uris list! ---
            "evidence_uris": [e['path']],

            "paths": {e['path']}, "exts": {e['ext']},
            "ua_type": e['ua_type'], "country": e['country'], "label": e['label']
        }

    def _update(self, s, e, rules):
        delta = (e['timestamp'] - s['last_seen']).total_seconds()
        if s['event_count'] == 1:
            s['min_interarrival'] = delta
        else:
            s['min_interarrival'] = min(s['min_interarrival'], delta)

        s['last_seen'] = e['timestamp']
        s['event_count'] += 1
        s['sum_req_bytes'] += e['req_bytes']
        s['max_req_bytes'] = max(s['max_req_bytes'], e['req_bytes'])
        s['sum_resp_bytes'] += e['resp_bytes']
        s['max_resp_bytes'] = max(s['max_resp_bytes'], e['resp_bytes'])

        if 400 <= e['status_code'] < 500: s['count_4xx'] += 1
        if 500 <= e['status_code'] < 600: s['count_5xx'] += 1
        s['status_set'].add(e['status_code'])

        s['sum_uri_ent'] += e['uri_entropy']
        s['max_uri_ent'] = max(s['max_uri_ent'], e['uri_entropy'])
        s['sum_pl_ent'] += e['payload_entropy']
        s['max_pl_ent'] = max(s['max_pl_ent'], e['payload_entropy'])

        rule_hit = any(rules.values())
        if rule_hit:
            s['rule_matches'] += 1
            s['flags'].update({k for k, v in rules.items() if v})

        if rules.get('is_sqli'): s['sqli_count'] += 1
        if rules.get('is_xss'): s['xss_count'] += 1
        if rules.get('is_traversal'): s['traversal_count'] += 1

        # --- FIXED: Append suspicious paths to evidence_uris! ---
        if rule_hit and e['path'] not in s['evidence_uris']:
            if len(s['evidence_uris']) < 5:
                s['evidence_uris'].append(e['path'])
        elif len(s['evidence_uris']) < 3 and e['path'] not in s['evidence_uris']:
            s['evidence_uris'].append(e['path'])

        s['paths'].add(e['path'])
        s['exts'].add(e['ext'])
        if e['label'] != 'unknown' and e['label'] != 'Normal': s['label'] = 'Anomalous'