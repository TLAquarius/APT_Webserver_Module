import pandas as pd
import numpy as np
import json
import re
import warnings

warnings.filterwarnings('ignore')

LOG_FILE = "web_server_v4.log"
GROUP_FILE = "user_groups.csv"
OUTPUT_JSON = "system_baselines.json"


def calculate_bounds(series, multiplier=3.5, min_buffer_abs=0):
    if len(series) < 5:
        return float(series.min()) * 0.5, float(series.max()) * 2.0

    median = series.median()
    mad = (series - median).abs().median()

    # --- CRITICAL FIX ---
    # Previous bug: Falling back to .std() allowed attacks in the training data
    # to inflate the baseline.
    # New Logic: If data is stable (MAD=0), assume a strict 5% variance limit.
    if mad == 0:
        mad = median * 0.05  # Assume 5% natural variance
        if mad == 0: mad = 1.0

    final_buffer = max(multiplier * mad, min_buffer_abs)

    # Ensure lower limit doesn't drop below 0
    return float(max(0, median - final_buffer)), float(median + final_buffer)


def train_baselines():
    print("[-] Training System Baselines (With Smart Hour Filtering)...")

    # ... (Loading Logic remains the same) ...
    # [Paste your existing loading code here]
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

    groups_df = pd.read_csv(GROUP_FILE)

    baselines = {
        "level_1_system": {},
        "level_2_resources": {},
        "level_3_groups": {},
        "level_4_users": {}
    }

    # ... (Level 1, 2, 3 code remains the same) ...
    # [Paste Level 1, 2, 3 code here - no changes needed]
    traffic_per_min = logs_df.set_index('time').resample('1min')['ip'].count()
    _, max_rpm = calculate_bounds(traffic_per_min, multiplier=4.0, min_buffer_abs=20)
    baselines["level_1_system"] = {"max_global_rpm": max_rpm}

    for uri, group in logs_df.groupby('uri'):
        if len(group) < 10: continue
        min_bytes, max_bytes = calculate_bounds(group['res_bytes'], multiplier=5.0, min_buffer_abs=100)
        min_time, max_time = calculate_bounds(group['duration'], multiplier=5.0, min_buffer_abs=100)
        baselines["level_2_resources"][uri] = {
            "min_safe_bytes": min_bytes, "max_safe_bytes": max_bytes,
            "min_safe_duration": min_time, "max_safe_duration": max_time
        }

    for cluster_id, group in groups_df.groupby('cluster_group'):
        cluster_id = str(cluster_id)
        _, max_bytes = calculate_bounds(group['total_bytes_sent'], multiplier=3.0, min_buffer_abs=100000)
        baselines["level_3_groups"][cluster_id] = {"max_safe_daily_bytes": max_bytes}

    # --- LEVEL 4: INDIVIDUAL USERS (UPDATED) ---
    print("[-] Level 4: Learning Core Working Hours...")
    for user, group in logs_df[logs_df['user'] != '-'].groupby('user'):
        # 1. Count traffic per hour (0-23)
        hourly_counts = group['time'].dt.hour.value_counts()

        # 2. Calculate the threshold (e.g., must be > 10% of their average hourly traffic)
        # This removes the "3 AM" noise where they only had 1 or 2 requests
        avg_traffic = hourly_counts.mean()
        threshold = avg_traffic * 0.15

        # 3. Only keep hours that meet the threshold
        core_hours = hourly_counts[hourly_counts > threshold].index.tolist()
        active_hours = sorted(core_hours)

        _, max_personal_bytes = calculate_bounds(group['res_bytes'], multiplier=8.0, min_buffer_abs=50000)

        baselines["level_4_users"][user] = {
            "valid_hours": active_hours,
            "max_personal_bytes": max_personal_bytes
        }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(baselines, f, indent=4)

    print(f"[+] Training Complete.")


if __name__ == "__main__":
    train_baselines()