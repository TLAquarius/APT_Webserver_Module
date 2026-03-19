import json
import pandas as pd
from collections import defaultdict
import math
import os
from datetime import datetime
from typing import Callable
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import joblib


class MarkovSequentialEngine:
    def __init__(self, config=None):
        self.transition_counts = defaultdict(lambda: defaultdict(int))
        self.state_counts = defaultdict(int)

        # Thêm scaler để chuẩn hóa điểm số về 0-100
        self.score_scaler = MinMaxScaler(feature_range=(0, 100))
        self.baseline_scores = []  # Dùng để fit scaler lúc train

        default_config = {
            "auth_keywords": ['login', 'log-in', 'auth', 'signin', 'wp-login'],
            "admin_keywords": ['admin', 'manager', 'dashboard', 'setup', 'config'],
            "static_exts": ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.woff', '.woff2', '.svg'],
            "sensitive_exts": ['.bak', '.sql', '.env', '.old', '.log', '.git', '.sh', '.zip', '.tar.gz', '.inc', '.php']
        }
        self.config = config if config else default_config

        self.AUTH_KEYWORDS = set(self.config['auth_keywords'])
        self.ADMIN_KEYWORDS = set(self.config['admin_keywords'])
        self.STATIC_EXTS = set(self.config['static_exts'])
        self.SENSITIVE_EXTS = set(self.config['sensitive_exts'])

    def _parse_time(self, time_str):
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))

    def _get_time_bin(self, delta_seconds):
        if delta_seconds < 0.1:
            return "[MACHINE_SPEED]"
        elif delta_seconds <= 300.0:
            return "[HUMAN_SPEED]"
        else:
            return "[SESSION_RESUME]"

    def _get_state(self, log):
        event_source = log.get('event_source')
        if event_source == 'apache_error_stderr': return "UNHANDLED_STDERR"
        if event_source == 'apache_error': return "SERVER_INTERNAL_ERROR"

        method = log.get('http_method', 'UNKNOWN')
        raw_status = log.get('status_code')
        try:
            status = int(raw_status) if raw_status is not None else 200
        except ValueError:
            status = 200

        uri = str(log.get('uri_path', '')).lower()
        query = str(log.get('uri_query', ''))

        if 400 <= status < 500:
            return "CLIENT_ERR"
        elif status >= 500:
            return "SERVER_ERR"
        if any(kw in uri for kw in self.AUTH_KEYWORDS): return "AUTH_ACTION"
        if any(kw in uri for kw in self.ADMIN_KEYWORDS): return "ADMIN_ACTION"

        ext = "." + uri.split('.')[-1] if '.' in uri else ""
        if ext in self.STATIC_EXTS: return "STATIC_ASSET"
        if ext in self.SENSITIVE_EXTS: return "SENSITIVE_FILE_ACCESS"
        if method in ("POST", "PUT", "DELETE"): return "FORM_SUBMISSION"
        if query and len(query) > 0 and query not in ("-", "nan"): return "DYNAMIC_QUERY"

        return "GENERIC_GET"

    def _get_transition_prob(self, current_state, next_composite_state):
        total_transitions = self.state_counts.get(current_state, 0)
        if total_transitions == 0: return 0.00001
        count = self.transition_counts[current_state].get(next_composite_state, 0)
        return (count + 1) / (total_transitions + len(self.state_counts))

    def _calculate_raw_score(self, timeline):
        """Tính điểm thô (càng cao càng bất thường)"""
        if len(timeline) < 2: return 0.0, "TOO_SHORT"

        log_prob = 0.0
        raw_states = []

        for i in range(len(timeline) - 1):
            current_log = timeline[i]
            next_log = timeline[i + 1]

            try:
                t1 = self._parse_time(current_log.get('@timestamp'))
                t2 = self._parse_time(next_log.get('@timestamp'))
                delta = max(0.0, (t2 - t1).total_seconds())
            except Exception:
                delta = 1.0

            time_bin = self._get_time_bin(delta)
            current_state = self._get_state(current_log)
            next_raw_state = self._get_state(next_log)

            if i == 0: raw_states.append(current_state)
            raw_states.append(next_raw_state)

            next_composite_state = f"{time_bin}_{next_raw_state}"
            p = self._get_transition_prob(current_state, next_composite_state)
            log_prob += math.log(p)

        avg_log_prob = log_prob / (len(timeline) - 1)

        loop_penalty = 0
        if raw_states.count("CLIENT_ERR") > 10:
            err_transitions = sum(1 for i in range(len(raw_states) - 1) if
                                  raw_states[i] == "CLIENT_ERR" and raw_states[i + 1] == "CLIENT_ERR")
            loop_ratio = err_transitions / len(raw_states)
            loop_penalty = loop_ratio * 50

        # Điểm thô: Trị tuyệt đối của log_prob (càng âm thì trị tuyệt đối càng lớn -> càng dị thường) + hình phạt
        raw_score = abs(avg_log_prob) + loop_penalty
        seq_summary = " -> ".join(list(dict.fromkeys(raw_states[:5])))
        return raw_score, seq_summary

    def train_baseline(self, timelines_json: str, max_transition_weight=5, status_callback: Callable = None):
        if status_callback: status_callback("Markov Chain: Updating sequence baseline...", 75)

        # 1. Cập nhật đếm trạng thái (Học Model)
        with open(timelines_json, 'r', encoding='utf-8') as f:
            for line in f:
                session = json.loads(line.strip())
                timeline = session.get('timeline', [])
                if not timeline or len(timeline) < 2: continue

                session_transitions = defaultdict(int)
                for i in range(len(timeline) - 1):
                    current_log = timeline[i]
                    next_log = timeline[i + 1]

                    try:
                        t1 = self._parse_time(current_log.get('@timestamp'))
                        t2 = self._parse_time(next_log.get('@timestamp'))
                        delta = max(0.0, (t2 - t1).total_seconds())
                    except Exception:
                        delta = 1.0

                    time_bin = self._get_time_bin(delta)
                    current_state = self._get_state(current_log)
                    next_raw_state = self._get_state(next_log)
                    next_composite_state = f"{time_bin}_{next_raw_state}"
                    transition_key = f"{current_state} -> {next_composite_state}"

                    if session_transitions[transition_key] < max_transition_weight:
                        self.transition_counts[current_state][next_composite_state] += 1
                        self.state_counts[current_state] += 1
                        session_transitions[transition_key] += 1

        # 2. Chấm điểm lại chính dữ liệu train để fit Scaler
        raw_scores = []
        with open(timelines_json, 'r', encoding='utf-8') as f:
            for line in f:
                session = json.loads(line.strip())
                timeline = session.get('timeline', [])
                score, _ = self._calculate_raw_score(timeline)
                if score > 0: raw_scores.append(score)

        if raw_scores:
            self.score_scaler.fit(np.array(raw_scores).reshape(-1, 1))

    def save_model(self, model_path: str):
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model_data = {
            "state_counts": dict(self.state_counts),
            "transition_counts": {k: dict(v) for k, v in self.transition_counts.items()}
        }
        with open(model_path, 'w', encoding='utf-8') as f:
            json.dump(model_data, f)

        # Lưu scaler
        scaler_path = model_path.replace('.json', '_scaler.joblib')
        joblib.dump(self.score_scaler, scaler_path)

    def load_model(self, model_path: str) -> bool:
        if not os.path.exists(model_path): return False

        with open(model_path, 'r', encoding='utf-8') as f:
            model_data = json.load(f)

        self.state_counts = defaultdict(int, model_data.get("state_counts", {}))
        self.transition_counts = defaultdict(lambda: defaultdict(int))
        for k, v in model_data.get("transition_counts", {}).items():
            self.transition_counts[k] = defaultdict(int, v)

        scaler_path = model_path.replace('.json', '_scaler.joblib')
        if os.path.exists(scaler_path):
            self.score_scaler = joblib.load(scaler_path)

        return True

    def score_sessions(self, timelines_json: str, output_csv: str, status_callback: Callable = None):
        if status_callback: status_callback("Markov Chain: Calculating sequence threat scores...", 85)
        results = []
        raw_scores = []

        with open(timelines_json, 'r', encoding='utf-8') as f:
            for line in f:
                session = json.loads(line.strip())
                session_id = session['session_id']
                parent_id = session.get('parent_tracking_id', session_id)
                timeline = session.get('timeline', [])

                raw_score, seq_summary = self._calculate_raw_score(timeline)
                raw_scores.append(raw_score)
                results.append({
                    "session_id": session_id,
                    "parent_tracking_id": parent_id,
                    "sequence_summary": seq_summary
                })

        # Chuẩn hóa về thang 0-100
        if raw_scores:
            normalized_scores = self.score_scaler.transform(np.array(raw_scores).reshape(-1, 1)).flatten()
            normalized_scores = np.clip(normalized_scores, 0, 100)  # Ép trong khoảng 0-100
        else:
            normalized_scores = [0.0] * len(results)

        for i, res in enumerate(results):
            res["markov_threat_score"] = round(normalized_scores[i], 2)

        df = pd.DataFrame(results,
                          columns=["session_id", "parent_tracking_id", "markov_threat_score", "sequence_summary"])
        df = df.sort_values(by='markov_threat_score', ascending=False)
        df.to_csv(output_csv, index=False)