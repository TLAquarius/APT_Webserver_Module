import pandas as pd
import numpy as np
import json
import re

# FILES
LOG_FILE = "web_server_v4.log"
GROUP_FILE = "user_groups.csv"
OUTPUT_JSON = "system_baselines.json"


# --- HELPER: ROBUST STATISTICS ---
def calculate_limit(series, multiplier=3.0):
    """
    Returns the Upper Limit using Median + (3 * MAD).
    This ensures actual attacks in the training data don't skew the baseline.
    """
    if len(series) < 5: return float(series.max()) * 1.5  # Fallback for rare data

    median = series.median()
    mad = (series - median).abs().median()

    if mad == 0:  # If data is very stable (std dev ~ 0)
        mad = series.std() if series.std() > 0 else (median * 0.1)
        if mad == 0: mad = 1.0

    limit = median + (multiplier * mad)
    return float(limit)


def train_baselines():
    print("[-] Training System Baselines...")

    # 1. LOAD DATA
    # Load Raw Logs for Level 1 & 2
    log_regex = r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>.*?)\] "(?P<method>\S+) (?P<uri>\S+).*?" (?P<status>\d+) (?P<req_bytes>\d+) (?P<res_bytes>\d+) (?P<duration>\d+)'
    log_data = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            match = re.search(log_regex, line)
            if match:
                log_data.append(match.groupdict())

    logs_df = pd.DataFrame(log_data)
    logs_df['time'] = logs_df['time'].str.strip()
    logs_df['time'] = pd.to_datetime(logs_df['time'], format="%d/%b/%Y:%H:%M:%S")
    logs_df['res_bytes'] = logs_df['res_bytes'].astype(int)
    logs_df['duration'] = logs_df['duration'].astype(int)

    # Load Groups for Level 3
    groups_df = pd.read_csv(GROUP_FILE)

    baselines = {
        "level_1_system": {},
        "level_2_resources": {},
        "level_3_groups": {}
    }

    # --- LEVEL 1: SYSTEM PULSE (Global Traffic) ---
    print("[-] Calculating Level 1: Global Pulse...")
    # Resample to 1-minute buckets
    traffic_per_min = logs_df.set_index('time').resample('1min')['ip'].count()

    baselines["level_1_system"] = {
        "max_global_rpm": calculate_limit(traffic_per_min, multiplier=3.5),
        "description": "If total system traffic exceeds this RPM, suspect DDoS."
    }

    # --- LEVEL 2: RESOURCE PROFILING (Per URL) ---
    print("[-] Calculating Level 2: URL Personalities...")
    for uri, group in logs_df.groupby('uri'):
        if len(group) < 20: continue  # Skip rare pages

        baselines["level_2_resources"][uri] = {
            "max_safe_bytes": calculate_limit(group['res_bytes']),
            "max_safe_duration": calculate_limit(group['duration']),
            "description": "Exceeding bytes = Exfiltration. Exceeding duration = SQLi/DoS."
        }

    # --- LEVEL 3: PEER GROUP PROFILES (Cluster Thresholds) ---
    print("[-] Calculating Level 3: Group Behaviors...")
    for cluster_id, group in groups_df.groupby('cluster_group'):
        cluster_id = str(cluster_id)  # JSON keys must be strings

        baselines["level_3_groups"][cluster_id] = {
            "max_safe_rpm": calculate_limit(group['avg_rpm']),
            "max_safe_daily_bytes": calculate_limit(group['total_bytes_sent']),
            "max_safe_error_rate": calculate_limit(group['error_rate_pct'], multiplier=2.0),
            "avg_rpm_baseline": float(group['avg_rpm'].median()),  # For reference
            "description": f"Thresholds for User Group {cluster_id}"
        }

    # SAVE TO FILE
    with open(OUTPUT_JSON, "w") as f:
        json.dump(baselines, f, indent=4)

    print(f"[+] Training Complete. Intelligence saved to '{OUTPUT_JSON}'")
    print(
        f"[+] Created baselines for {len(baselines['level_2_resources'])} URIs and {len(baselines['level_3_groups'])} User Groups.")


if __name__ == "__main__":
    train_baselines()