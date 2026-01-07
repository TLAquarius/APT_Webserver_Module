import json
import re
import pandas as pd
from datetime import datetime

# CONFIGURATION
LOG_FILE = "web_server_v4.log"
BASELINE_FILE = "system_baselines.json"
GROUND_TRUTH_FILE = "ground_truth.json"  # To verify if we were right


def load_baselines():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def parse_log_line(line):
    # Regex to parse the V4 log format
    regex = r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>.*?)\] "(?P<method>\S+) (?P<uri>\S+).*?" (?P<status>\d+) (?P<req_bytes>\d+) (?P<res_bytes>\d+) (?P<duration>\d+)'
    match = re.search(regex, line)
    if match:
        data = match.groupdict()
        # Convert types
        data['res_bytes'] = int(data['res_bytes'])
        data['duration'] = int(data['duration'])

        # --- FIX START ---
        # 1. Strip the trailing space
        clean_time = data['time'].strip()
        # 2. Parse without the %z (Timezone)
        dt = datetime.strptime(clean_time, "%d/%b/%Y:%H:%M:%S")
        # --- FIX END ---

        data['hour'] = dt.hour
        data['timestamp_obj'] = dt
        return data
    return None


def scan_logs():
    print("[-] Loading Baselines...")
    baselines = load_baselines()

    # We will track our detections here
    detected_anomalies = []

    print(f"[-] Scanning {LOG_FILE} against Security Baselines...")

    with open(LOG_FILE, "r") as f:
        for line_num, line in enumerate(f, 1):
            record = parse_log_line(line)
            if not record: continue

            uri = record['uri']
            user = record['user']

            # === CHECK 1: RESOURCE ANOMALY (Level 2) ===
            # Does this URI exist in our baseline?
            if uri in baselines["level_2_resources"]:
                rules = baselines["level_2_resources"][uri]

                # Rule A: Data Exfiltration Check (Size)
                if record['res_bytes'] > rules['max_safe_bytes']:
                    detected_anomalies.append({
                        "line": line_num,
                        "type": "RESOURCE_ANOMALY (SIZE)",
                        "detail": f"URI {uri} sent {record['res_bytes']} bytes (Limit: {rules['max_safe_bytes']:.0f})",
                        "confidence": "High"
                    })
                    continue  # Stop checking this line if already flagged

                # Rule B: DoS / SQLi Check (Time)
                if record['duration'] > rules['max_safe_duration']:
                    detected_anomalies.append({
                        "line": line_num,
                        "type": "RESOURCE_ANOMALY (TIME)",
                        "detail": f"URI {uri} took {record['duration']} ms (Limit: {rules['max_safe_duration']:.0f})",
                        "confidence": "Medium"
                    })
                    continue

            # === CHECK 2: TEMPORAL ANOMALY (Level 4) ===
            # (Simplified: Just checking if it's "Late Night" for this demo)
            # In a real system, you'd check baselines['level_4_users'][user]['valid_hours']
            if record['hour'] < 5 or record['hour'] > 23:
                # Reduce noise: Only alert if it's a known user, not anonymous
                if user != "-":
                    detected_anomalies.append({
                        "line": line_num,
                        "type": "BEHAVIOR_ANOMALY (TIME)",
                        "detail": f"User {user} active at {record['hour']}:00 hours (Unusual time)",
                        "confidence": "Low"
                    })

    return detected_anomalies


def validate_results(detections):
    print("\n[-] Validating detections against Ground Truth (The Cheat Sheet)...")

    try:
        with open(GROUND_TRUTH_FILE, "r") as f:
            truth = json.load(f)
    except FileNotFoundError:
        print("[!] No ground truth file found. Cannot calculate accuracy.")
        return

    # Convert truth to a set of line numbers for fast lookup
    true_attack_lines = {item['line_number'] for item in truth}
    detected_lines = {item['line'] for item in detections}

    # Calculate Stats
    true_positives = true_attack_lines.intersection(detected_lines)
    false_positives = detected_lines - true_attack_lines
    missed_attacks = true_attack_lines - detected_lines

    print("=" * 60)
    print(f"TOTAL ATTACKS INJECTED: {len(true_attack_lines)}")
    print(f"TOTAL ALERTS TRIGGERED: {len(detected_lines)}")
    print("=" * 60)
    print(f"[+] TRUE POSITIVES (Caught): {len(true_positives)}")
    print(f"[-] FALSE POSITIVES (Noise): {len(false_positives)}")
    print(f"[-] MISSED ATTACKS:          {len(missed_attacks)}")
    print("=" * 60)

    if len(true_attack_lines) > 0:
        detection_rate = (len(true_positives) / len(true_attack_lines)) * 100
        print(f"FINAL DETECTION SCORE: {detection_rate:.1f}%")

    # Print a few examples
    print("\n[Example Alerts]")
    for alert in detections[:3]:
        print(f"Line {alert['line']}: [{alert['type']}] {alert['detail']}")


if __name__ == "__main__":
    alerts = scan_logs()
    validate_results(alerts)