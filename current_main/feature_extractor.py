import pandas as pd
import numpy as np
import re
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

INPUT_LOG = "web_server_v4.log"
OUTPUT_CSV = "user_behavior_features.csv"


# --- 1. PARSING & NORMALIZATION (ECS MAPPING) ---
def parse_logs(file_path):
    print(f"[-] Loading and Parsing {file_path}...")

    # Regex captures raw fields
    regex = r'(?P<source_ip>\S+) - (?P<user_id>\S+) \[(?P<timestamp>.*?)\] "(?P<http_method>\S+) (?P<url_path>\S+).*?" (?P<http_status>\d+) (?P<http_request_bytes>\d+) (?P<http_response_bytes>\d+) (?P<event_duration>\d+).*? (?P<session_id>\S+)'

    data = []
    with open(file_path, "r") as f:
        for line in f:
            match = re.search(regex, line)
            if match:
                data.append(match.groupdict())

    df = pd.DataFrame(data)

    # Type Conversion (Standardizing format)
    df['timestamp'] = df['timestamp'].str.strip()
    df['timestamp'] = pd.to_datetime(df['timestamp'], format="%d/%b/%Y:%H:%M:%S")
    df['http_request_bytes'] = df['http_request_bytes'].astype(int)  # Bytes In
    df['http_response_bytes'] = df['http_response_bytes'].astype(int)  # Bytes Out
    df['event_duration'] = df['event_duration'].astype(int)  # ms
    df['http_status'] = df['http_status'].astype(int)

    return df


# --- 2. FEATURE ENGINEERING (CALCULATING THE BASELINE METRICS) ---
def extract_features(df):
    print("[-] Extracting Behavioral Features...")

    # We group by 'user_id' to build the Peer Profiles.
    # (In a real scenario, you might also group by 'source_ip' or 'session_id')
    grouped = df[df['user_id'] != '-'].groupby('user_id')

    features_list = []

    for user, group in grouped:
        # A. VOLUMETRIC FEATURES (The "How Much")
        total_reqs = len(group)
        total_bytes_out = group['http_response_bytes'].sum()
        total_bytes_in = group['http_request_bytes'].sum()

        # B. VELOCITY FEATURES (The "How Fast")
        # Calculate duration of activity in minutes
        start_time = group['timestamp'].min()
        end_time = group['timestamp'].max()
        active_mins = (end_time - start_time).total_seconds() / 60.0
        if active_mins < 1: active_mins = 1  # Avoid div by zero

        rpm = total_reqs / active_mins  # Requests Per Minute

        # C. RESOURCE FEATURES (The "What")
        distinct_pages = group['url_path'].nunique()

        # Error Rate: Count 4xx and 5xx status codes
        error_count = group[group['http_status'] >= 400].shape[0]
        error_rate = (error_count / total_reqs) * 100

        # Read/Write Ratio (GET vs POST)
        post_count = group[group['http_method'] == 'POST'].shape[0]
        get_count = group[group['http_method'] == 'GET'].shape[0]
        # Ratio: High value = Data Entry/Uploads. Low value = Browsing.
        rw_ratio = post_count / max(1, get_count)

        # D. TEMPORAL FEATURES (The "When")
        # Mean hour of activity (Simple approach)
        avg_hour = group['timestamp'].dt.hour.mean()

        # Pack into a feature vector
        features_list.append({
            "user_id": user,
            "total_requests": total_reqs,
            "total_bytes_sent": total_bytes_out,
            "total_bytes_received": total_bytes_in,
            "avg_rpm": round(rpm, 2),
            "distinct_pages": distinct_pages,
            "error_rate_pct": round(error_rate, 2),
            "write_read_ratio": round(rw_ratio, 3),
            "avg_active_hour": round(avg_hour, 1)
        })

    return pd.DataFrame(features_list)


# --- EXECUTION ---
if __name__ == "__main__":
    # 1. Load Raw Logs
    raw_df = parse_logs(INPUT_LOG)

    # 2. Engineer Features
    features_df = extract_features(raw_df)

    # 3. Save to CSV
    features_df.to_csv(OUTPUT_CSV, index=False)

    print(f"[+] Success! Extracted features for {len(features_df)} users.")
    print(f"[+] Saved to: {OUTPUT_CSV}")
    print("\n--- PREVIEW OF EXTRACTED FEATURES ---")
    print(features_df.head().to_string())