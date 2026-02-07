import json
import re
import pandas as pd
from datetime import datetime
from collections import Counter

# CONFIGURATION
LOG_FILE = "web_server_v4.log"
BASELINE_FILE = "system_baselines.json"
GROUND_TRUTH_FILE = "ground_truth.json"


def load_baselines():
    try:
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Baseline file '{BASELINE_FILE}' not found. Run baseline_trainer.py first.")
        return {}


def parse_log_line(line):
    # Regex to parse the V4 log format
    regex = r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>.*?)\] "(?P<method>\S+) (?P<uri>\S+).*?" (?P<status>\d+) (?P<req_bytes>\d+) (?P<res_bytes>\d+) (?P<duration>\d+)'
    match = re.search(regex, line)
    if match:
        data = match.groupdict()
        data['res_bytes'] = int(data['res_bytes'])
        data['duration'] = int(data['duration'])

        clean_time = data['time'].strip()
        try:
            dt = datetime.strptime(clean_time, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            # Fallback if format differs slightly
            return None

        data['hour'] = dt.hour
        data['timestamp_obj'] = dt
        return data
    return None


def scan_logs():
    print("[-] Loading Baselines...")
    baselines = load_baselines()
    if not baselines: return []

    detected_anomalies = []

    print(f"[-] Scanning {LOG_FILE}...")

    try:
        with open(LOG_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                record = parse_log_line(line)
                if not record: continue

                uri = record['uri']
                user = record['user']

                # === Check 1: Resource Anomaly (Level 2) ===
                if uri in baselines["level_2_resources"]:
                    rules = baselines["level_2_resources"][uri]

                    # Rule A: Exfiltration (Too Big)
                    if record['res_bytes'] > rules['max_safe_bytes']:
                        detected_anomalies.append({
                            "line": line_num,
                            "type": "RESOURCE_ANOMALY (SIZE_HIGH)",
                            "detail": f"URI {uri} sent {record['res_bytes']}b (Limit: {rules['max_safe_bytes']:.0f}b)",
                            "confidence": "High"
                        })
                        continue

                    # Rule B: C2 Beaconing (Too Small)
                    # Note: We check > 0 to ensure it's not just a failed connection
                    if record['res_bytes'] < rules['min_safe_bytes'] and record['res_bytes'] > 0:
                        detected_anomalies.append({
                            "line": line_num,
                            "type": "RESOURCE_ANOMALY (SIZE_LOW)",
                            "detail": f"URI {uri} sent {record['res_bytes']}b (Expected Min: {rules['min_safe_bytes']:.0f}b)",
                            "confidence": "Medium"
                        })
                        continue

                    # Rule C: Time Anomaly (Too Slow)
                    if record['duration'] > rules['max_safe_duration']:
                        detected_anomalies.append({
                            "line": line_num,
                            "type": "RESOURCE_ANOMALY (TIME_HIGH)",
                            "detail": f"URI {uri} took {record['duration']}ms (Limit: {rules['max_safe_duration']:.0f}ms)",
                            "confidence": "Medium"
                        })
                        continue

                # === Check 2: Behavior Anomaly (Level 4) ===
                if user in baselines["level_4_users"]:
                    profile = baselines["level_4_users"][user]

                    # Rule D: Unusual Time
                    is_valid_time = False
                    for h in profile['valid_hours']:
                        diff = abs(record['hour'] - h)
                        if diff > 12: diff = 24 - diff
                        if diff <= 4:
                            is_valid_time = True
                            break

                    if not is_valid_time:
                        detected_anomalies.append({
                            "line": line_num,
                            "type": "BEHAVIOR_ANOMALY (UNUSUAL_TIME)",
                            "detail": f"User {user} active at {record['hour']}:00.",
                            "confidence": "Low"
                        })

                    # Rule E: Personal Spike
                    if record['res_bytes'] > profile['max_personal_bytes']:
                        detected_anomalies.append({
                            "line": line_num,
                            "type": "BEHAVIOR_ANOMALY (PERSONAL_SPIKE)",
                            "detail": f"User {user} sent {record['res_bytes']}b. Personal Max: {profile['max_personal_bytes']:.0f}b",
                            "confidence": "Medium"
                        })
    except FileNotFoundError:
        print(f"[!] Log file '{LOG_FILE}' not found. Run webserver_generator.py first.")
        return []

    return detected_anomalies


def validate_results(detections):
    print("\n[-] Validating detections against Ground Truth...")
    try:
        with open(GROUND_TRUTH_FILE, "r") as f:
            truth = json.load(f)
    except FileNotFoundError:
        print(f"[!] {GROUND_TRUTH_FILE} not found. Cannot calculate accuracy.")
        return

    # Create a map for fast lookup: { line_number: attack_details }
    truth_map = {item['line_number']: item for item in truth}

    true_attack_lines = set(truth_map.keys())
    detected_lines = {item['line'] for item in detections}

    true_positives = true_attack_lines.intersection(detected_lines)
    false_positives = detected_lines - true_attack_lines
    missed_attacks = true_attack_lines - detected_lines

    # --- 1. PRINT SUMMARY STATS ---
    print("=" * 60)
    print(f"TOTAL ATTACKS INJECTED: {len(true_attack_lines)}")
    print(f"TOTAL ALERTS TRIGGERED: {len(detected_lines)}")
    print("=" * 60)
    print(f"[+] TRUE POSITIVES (Caught): {len(true_positives)}")
    print(f"[-] FALSE POSITIVES (Noise): {len(false_positives)}")
    print(f"[-] MISSED ATTACKS:          {len(missed_attacks)}")
    print("=" * 60)

    if len(true_attack_lines) > 0:
        score = (len(true_positives) / len(true_attack_lines)) * 100
        print(f"FINAL ACCURACY SCORE: {score:.1f}%")
        if len(detected_lines) > 0:
            precision = (len(true_positives) / len(detected_lines)) * 100
            print(f"PRECISION:            {precision:.1f}%")

    # --- 2. DEEP DIVE: MATCHING LOGIC (The "Actual Check") ---
    print("\n[+] DETAILED CROSS-CHECK (What did we catch?):")
    # We loop through detections to see if they align with ground truth types
    match_count = 0
    for d in detections:
        line = d['line']
        if line in true_attack_lines:
            if match_count < 10:  # Only show first 10 matches to keep output clean
                real_attack = truth_map[line].get('attack_type', 'Unknown Attack')
                my_detection = d['type']
                print(f"   [MATCH Line {line}] Real: {real_attack} <--> Detected as: {my_detection}")
            match_count += 1

    if match_count > 10:
        print(f"   ... and {match_count - 10} more matches.")

    # --- 3. DEBUG: MISSED ATTACKS ---
    if len(missed_attacks) > 0:
        print("\n[DEBUG] Analysis of Missed Attacks:")
        missed_types = []
        for line in missed_attacks:
            missed_types.append(truth_map[line].get('attack_type', 'Unknown'))

        for attack_type, count in Counter(missed_types).items():
            print(f"   > Missed {count} logs of type: {attack_type}")


if __name__ == "__main__":
    alerts = scan_logs()
    validate_results(alerts)