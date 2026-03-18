import json
import pandas as pd
import os
from collections import defaultdict


class DataCorrelator:
    def __init__(self, stat_csv, seq_csv, timelines_json, output_ndjson):
        self.stat_csv = stat_csv
        self.seq_csv = seq_csv
        self.timelines_json = timelines_json
        self.output_ndjson = output_ndjson

    def run_correlation(self):
        print("[*] Starting Layer 3 Data Fusion & Correlation (Full Log Management Mode)...")

        try:
            df_stat = pd.read_csv(self.stat_csv)
            df_seq = pd.read_csv(self.seq_csv)
        except FileNotFoundError as e:
            print(f"[-] Error loading Layer 2 scores: {e}")
            return

        # 1. Fuse the Data
        df_merged = pd.merge(df_stat, df_seq, on=['session_id', 'parent_tracking_id'], how='inner')

        if df_merged.empty:
            print("[-] No data to correlate.")
            open(self.output_ndjson, 'w').close()
            return

        print(f"[*] Fused {len(df_merged)} total session chunks. Preparing all for the dashboard...")

        # 2. Group by Parent Tracking ID to prepare for timeline stitching
        parent_groups = defaultdict(list)
        for _, row in df_merged.iterrows():
            parent_id = row['parent_tracking_id']
            parent_groups[parent_id].append(row.to_dict())

        # 3. Extract and Stitch Timelines for EVERY session
        self._build_case_files(parent_groups)

    def _compress_timeline(self, raw_timeline):
        """
        Run-Length Encoding (RLE) to compress automated bot noise.
        Fixed: Correctly handles distinction between access logs and error logs.
        Safeguard: Never compresses WAF-flagged alerts.
        """
        compressed = []
        if not raw_timeline: return compressed

        current_event = raw_timeline[0]
        repeat_count = 1

        for i in range(1, len(raw_timeline)):
            next_event = raw_timeline[i]

            is_same = False

            # SAFEGUARD: Never compress Layer 1 WAF Alerts so the Evaluator can see them
            if current_event.get('layer1_flagged') or next_event.get('layer1_flagged'):
                is_same = False

            # Access Log Compression (Match URI and Status)
            elif current_event.get('event_source') == 'apache_access' and next_event.get(
                    'event_source') == 'apache_access':
                same_uri = current_event.get('uri_path') == next_event.get('uri_path')
                same_status = current_event.get('status_code') == next_event.get('status_code')
                is_same = same_uri and same_status

            # Error Log Compression (Match exact Error Message)
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
        print("[*] Stitching fragmented sessions and compressing timelines...")

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
            final_threat_level = "NORMAL"
            sequence_summaries = []

            for chunk in session_chunks:
                session_id = chunk['session_id']

                # Still calculate the max threat level so the dashboard can color-code the row
                if chunk['statistical_threat_score'] > max_stat_score:
                    max_stat_score = chunk['statistical_threat_score']
                    final_threat_level = chunk['statistical_threat_level']

                if chunk['markov_threat_score'] > max_markov_score:
                    max_markov_score = chunk['markov_threat_score']

                sequence_summaries.append(chunk.get('sequence_summary', ''))

                if session_id in raw_timelines:
                    full_timeline.extend(raw_timelines[session_id])

            full_timeline = sorted(full_timeline, key=lambda x: x.get('@timestamp', ''))
            compressed_timeline = self._compress_timeline(full_timeline)

            case_file = {
                "incident_tracking_id": parent_id,
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

        print(f"[+] Successfully generated {len(case_files)} total Session Files (Alerts + Normal Traffic).")
        print(f"[+] Exported to {self.output_ndjson}")


if __name__ == '__main__':
    # FIXED: Read the LIVE scores (which contains all 255 sessions including the attacker)
    STAT_CSV = "../behaviour_layer/machine_learning/scores/statistical_scores_live.csv"
    SEQ_CSV = "../behaviour_layer/machine_learning/scores/sequential_scores.csv"
    TIMELINES_JSON = "../behaviour_layer/session_timelines.json"

    OUTPUT_NDJSON = "./incident_reports.ndjson"

    correlator = DataCorrelator(STAT_CSV, SEQ_CSV, TIMELINES_JSON, OUTPUT_NDJSON)
    correlator.run_correlation()