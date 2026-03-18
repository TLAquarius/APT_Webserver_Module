import json
import pandas as pd
import os
from collections import defaultdict
from typing import Callable


class DataCorrelator:
    # Đã thêm tham số models_dir
    def __init__(self, stat_csv, seq_csv, timelines_json, output_ndjson,
                 models_dir="./webserver_module_AIT/module_data/Default_Tenant/models"):
        self.stat_csv = stat_csv
        self.seq_csv = seq_csv
        self.timelines_json = timelines_json
        self.output_ndjson = output_ndjson
        self.models_dir = models_dir

        self.alert_config = self._load_alert_config()

    def _load_alert_config(self):
        config_path = os.path.join(self.models_dir, "alert_config.json")
        default_config = {"suspicious_threshold": 50, "critical_threshold": 80}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return default_config

    def _determine_final_threat(self, stat_score, seq_score, has_l1_alert):
        # WAF phát hiện -> Luôn CRITICAL
        if has_l1_alert: return "CRITICAL"

        sus_thresh = self.alert_config.get("suspicious_threshold", 50)
        crit_thresh = self.alert_config.get("critical_threshold", 80)

        max_ai_score = max(stat_score, seq_score)

        if max_ai_score >= crit_thresh:
            return "CRITICAL"
        elif max_ai_score >= sus_thresh:
            return "SUSPICIOUS"
        else:
            return "NORMAL"

    def run_correlation(self, status_callback: Callable = None):
        if status_callback: status_callback("Correlator: Fusing ML scores and raw timelines...", 85)

        try:
            df_stat = pd.read_csv(self.stat_csv)
            df_seq = pd.read_csv(self.seq_csv)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Error loading Layer 2/3 scores: {e}")

        df_merged = pd.merge(df_stat, df_seq, on=['session_id', 'parent_tracking_id'], how='inner')

        if df_merged.empty:
            open(self.output_ndjson, 'w').close()
            return

        parent_groups = defaultdict(list)
        for _, row in df_merged.iterrows():
            parent_id = row['parent_tracking_id']
            parent_groups[parent_id].append(row.to_dict())

        if status_callback: status_callback("Correlator: Evaluating thresholds and Compressing noise...", 90)
        self._build_case_files(parent_groups)

        if status_callback: status_callback("Correlator: Incident Reports generated successfully.", 95)

    def _compress_timeline(self, raw_timeline):
        compressed = []
        if not raw_timeline: return compressed

        current_event = raw_timeline[0]
        repeat_count = 1

        for i in range(1, len(raw_timeline)):
            next_event = raw_timeline[i]
            is_same = False

            if current_event.get('layer1_flagged') or next_event.get('layer1_flagged'):
                is_same = False
            elif current_event.get('event_source') == 'apache_access' and next_event.get(
                    'event_source') == 'apache_access':
                same_uri = current_event.get('uri_path') == next_event.get('uri_path')
                same_status = current_event.get('status_code') == next_event.get('status_code')
                is_same = same_uri and same_status
            elif current_event.get('event_source') == 'apache_error' and next_event.get(
                    'event_source') == 'apache_error':
                is_same = current_event.get('error_message') == next_event.get('error_message')

            if is_same:
                repeat_count += 1
            else:
                if repeat_count > 5:
                    compressed.append({
                        "event_type": "COMPRESSED_BULK_ACTION",
                        "count": repeat_count,
                        "uri_path": current_event.get('uri_path', 'ERROR_LOG_NO_URI'),
                        "status_code": current_event.get('status_code', 'ERROR'),
                        "start_time": current_event.get('@timestamp'),
                        "end_time": raw_timeline[i - 1].get('@timestamp'),
                        "summary": f"Automated repetition detected {repeat_count} times."
                    })
                else:
                    for j in range(i - repeat_count, i):
                        compressed.append(raw_timeline[j])
                current_event = next_event
                repeat_count = 1

        if repeat_count > 5:
            compressed.append({
                "event_type": "COMPRESSED_BULK_ACTION",
                "count": repeat_count,
                "uri_path": current_event.get('uri_path', 'ERROR_LOG_NO_URI'),
                "status_code": current_event.get('status_code', 'ERROR'),
                "start_time": current_event.get('@timestamp'),
                "end_time": raw_timeline[-1].get('@timestamp'),
                "summary": f"Automated repetition detected {repeat_count} times."
            })
        else:
            for j in range(len(raw_timeline) - repeat_count, len(raw_timeline)):
                compressed.append(raw_timeline[j])
        return compressed

    def _build_case_files(self, parent_groups):
        raw_timelines = {}
        with open(self.timelines_json, 'r', encoding='utf-8') as f:
            for line in f:
                session_data = json.loads(line.strip())
                raw_timelines[session_data['session_id']] = session_data['timeline']

        case_files = []

        for parent_id, session_chunks in parent_groups.items():
            full_timeline = []
            max_stat_score = 0
            max_markov_score = 0
            has_l1_alert = False
            sequence_summaries = []

            for chunk in session_chunks:
                session_id = chunk['session_id']
                if chunk.get('statistical_threat_score', 0) > max_stat_score:
                    max_stat_score = chunk['statistical_threat_score']
                if chunk.get('markov_threat_score', 0) > max_markov_score:
                    max_markov_score = chunk['markov_threat_score']

                sequence_summaries.append(chunk.get('sequence_summary', ''))
                if session_id in raw_timelines:
                    full_timeline.extend(raw_timelines[session_id])

            for event in full_timeline:
                if event.get('layer1_flagged'):
                    has_l1_alert = True
                    break

            final_threat_level = self._determine_final_threat(max_stat_score, max_markov_score, has_l1_alert)

            full_timeline = sorted(full_timeline, key=lambda x: x.get('@timestamp', ''))
            compressed_timeline = self._compress_timeline(full_timeline)
            source_ip = parent_id.split("_")[0] if "_" in parent_id else parent_id

            case_file = {
                "incident_tracking_id": parent_id,
                "source_ip": source_ip,
                "overall_threat_level": final_threat_level,
                "max_statistical_score": max_stat_score,
                "max_markov_score": max_markov_score,
                "sequence_chain": " | ".join(sequence_summaries),
                "total_raw_events": len(full_timeline),
                "total_compressed_events": len(compressed_timeline),
                "timeline": compressed_timeline
            }
            case_files.append(case_file)

        os.makedirs(os.path.dirname(self.output_ndjson), exist_ok=True)
        with open(self.output_ndjson, 'w', encoding='utf-8') as f:
            for case in case_files:
                f.write(json.dumps(case) + "\n")