import json
import re
import pandas as pd
from datetime import datetime
from collections import Counter

LOG_FILE = "web_server_v4.log"
BASELINE_FILE = "system_baselines.json"
GROUND_TRUTH_FILE = "ground_truth.json"


def load_baselines():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def parse_log_line(line):
    regex = r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>.*?)\] "(?P<method>\S+) (?P<uri>\S+).*?" (?P<status>\d+) (?P<req_bytes>\d+) (?P<res_bytes>\d+) (?P<duration>\d+)'
    match = re.search(regex, line)
    if match:
        data = match.groupdict()
        data['res_bytes'] = int(data['res_bytes'])
        data['duration'] = int(data['duration'])

        clean_time = data['time'].strip()
        dt = datetime.strptime(clean_time, "%d/%b/%Y:%H:%M:%S")

        data['hour'] = dt.hour
        data['timestamp_obj'] = dt
        return data
    return None


def scan_logs():
    print("[-] Loading Baselines...")
    baselines = load_baselines()
    detected_anomalies = []

    print(f"[-] Scanning {LOG_FILE}...")

    with open(LOG_FILE, "r") as f:
        for line_num, line in enumerate(f, 1):
            record = parse_log_line(line)
            if not record: continue

            uri = record['uri']
            user = record['user']

            # Check 1: Resource Anomaly (Level 2)
            if uri in baselines["level_2_resources"]:
                rules = baselines["level_2_resources"][uri]

                # Rule A: Exfiltration (Too Big)
                if record['res_bytes'] > rules['max_safe_bytes']:
                    detected_anomalies.append({
                        "line": line_num, "type": "RESOURCE_ANOMALY (SIZE_HIGH)",
                        "detail": f"URI {uri} sent {record['res_bytes']}b (Limit: {rules['max_safe_bytes']:.0f}b)",
                        "confidence": "High"
                    })
                    continue

                    # Rule B: C2 Beaconing (Too Small)
                # FIX: Check > 0 to catch 1-byte attacks. Reduced buffer allows this to work.
                if record['res_bytes'] < rules['min_safe_bytes'] and record['res_bytes'] > 0:
                    detected_anomalies.append({
                        "line": line_num, "type": "RESOURCE_ANOMALY (SIZE_LOW)",
                        "detail": f"URI {uri} sent {record['res_bytes']}b (Expected Min: {rules['min_safe_bytes']:.0f}b)",
                        "confidence": "Medium"
                    })
                    continue

                # Rule C: Time Anomaly (Too Slow)
                if record['duration'] > rules['max_safe_duration']:
                    detected_anomalies.append({
                        "line": line_num, "type": "RESOURCE_ANOMALY (TIME_HIGH)",
                        "detail": f"URI {uri} took {record['duration']}ms (Limit: {rules['max_safe_duration']:.0f}ms)",
                        "confidence": "Medium"
                    })
                    continue

            # Check 2: Behavior Anomaly (Level 4)
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
                        "line": line_num, "type": "BEHAVIOR_ANOMALY (UNUSUAL_TIME)",
                        "detail": f"User {user} active at {record['hour']}:00.",
                        "confidence": "Low"
                    })

                # Rule E: Personal Spike
                if record['res_bytes'] > profile['max_personal_bytes']:
                    detected_anomalies.append({
                        "line": line_num, "type": "BEHAVIOR_ANOMALY (PERSONAL_SPIKE)",
                        "detail": f"User {user} sent {record['res_bytes']}b. Personal Max: {profile['max_personal_bytes']:.0f}b",
                        "confidence": "Medium"
                    })

    return detected_anomalies


def validate_results(detections):
    print("\n[-] Validating detections against Ground Truth...")
    try:
        with open(GROUND_TRUTH_FILE, "r") as f:
            truth = json.load(f)
    except FileNotFoundError:
        return

    true_attack_lines = {item['line_number'] for item in truth}
    detected_lines = {item['line'] for item in detections}

    true_positives = true_attack_lines.intersection(detected_lines)
    false_positives = detected_lines - true_attack_lines
    missed_attacks = true_attack_lines - detected_lines

    print("=" * 60)
    print(f"TOTAL ATTACKS:       {len(true_attack_lines)}")
    print(f"TOTAL ALERTS:        {len(detected_lines)}")
    print("=" * 60)
    print(f"[+] TRUE POSITIVES:  {len(true_positives)}")
    print(f"[-] FALSE POSITIVES: {len(false_positives)}")
    print(f"[-] MISSED:          {len(missed_attacks)}")
    print("=" * 60)

    if len(true_attack_lines) > 0:
        score = (len(true_positives) / len(true_attack_lines)) * 100
        print(f"FINAL ACCURACY SCORE: {score:.1f}%")
        if len(detected_lines) > 0:
            precision = (len(true_positives) / len(detected_lines)) * 100
            print(f"PRECISION:            {precision:.1f}%")

    if len(missed_attacks) > 0:
        print("\n[DEBUG] Analysis of Missed Attacks:")
        missed_types = []
        for t in truth:
            if t['line_number'] in missed_attacks:
                missed_types.append(t['attack_type'])

        for attack_type, count in Counter(missed_types).items():
            print(f"   > Missed {count} logs of type: {attack_type}")


if __name__ == "__main__":
    alerts = scan_logs()
    validate_results(alerts)