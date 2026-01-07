import random
import json
import uuid
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# Configuration
TOTAL_RECORDS = 10000
ATTACK_RATIO = 0.03  # 3% of traffic is malicious
START_TIME = datetime.now() - timedelta(days=3)
LOG_FILE = "web_server_v4.log"
LABEL_FILE = "ground_truth.json"

# --- NETWORK PROFILE ---
PORTS = [443, 80]

# --- BASELINE DEFINITIONS (The "Normal" Behavior) ---
ENDPOINTS = {
    "/index.html": {"method": "GET", "avg_bytes": 1500, "std_bytes": 100, "avg_ms": 50, "std_ms": 20},
    "/login.php": {"method": "POST", "avg_bytes": 350, "std_bytes": 20, "avg_ms": 120, "std_ms": 40},
    "/dashboard": {"method": "GET", "avg_bytes": 5000, "std_bytes": 500, "avg_ms": 200, "std_ms": 50},
    "/api/search": {"method": "GET", "avg_bytes": 800, "std_bytes": 200, "avg_ms": 300, "std_ms": 100},
    "/admin/config": {"method": "GET", "avg_bytes": 1200, "std_bytes": 50, "avg_ms": 80, "std_ms": 10},
    "/assets/style.css": {"method": "GET", "avg_bytes": 12000, "std_bytes": 0, "avg_ms": 30, "std_ms": 5},
}

# --- ATTACK DEFINITIONS (Breaking the Baseline) ---
ATTACKS = [
    {
        "type": "SLOW_SQL_INJECTION",
        "uri": "/login.php",
        "method": "POST",
        "tactic": "Time Anomaly",
        "desc": "Database sleep command execution",
        "duration_multiplier": 50.0,
        "size_multiplier": 1.0
    },
    {
        "type": "DATA_EXFILTRATION",
        "uri": "/api/search",
        "method": "GET",
        "tactic": "Size Anomaly",
        "desc": "Database table dump (large response)",
        "duration_multiplier": 1.5,
        "size_multiplier": 50.0
    },
    {
        "type": "C2_HEARTBEAT",
        "uri": "/assets/style.css",
        "method": "GET",
        "tactic": "Size Anomaly (Small)",
        "desc": "Malware checking in (unexpectedly small response for a CSS file)",
        "duration_multiplier": 1.0,
        "size_multiplier": 0.001  # Response is tiny (just an 'OK'), but CSS should be big
    }
]

USERS = ["admin", "alice", "bob", "manager", "-", "-", "-", "-"]


def get_log_time(current_time):
    # Log traffic is heavier during the day
    if 8 <= current_time.hour <= 18:
        gap = random.randint(1, 10)
    else:
        gap = random.randint(30, 300)
    return current_time + timedelta(seconds=gap)


def generate_record(timestamp, is_attack=False):
    ip = fake.ipv4()
    session_id = str(uuid.uuid4())[:8]
    user = random.choice(USERS)
    port = 443

    label_info = None  # Default is clean

    # 1. Select Endpoint & Baseline
    if is_attack:
        scenario = random.choice(ATTACKS)
        uri = scenario["uri"]
        method = scenario["method"]
        baseline = ENDPOINTS[uri]

        # Calculate Attack Values
        bytes_sent = int(baseline["avg_bytes"] * scenario["size_multiplier"])
        duration_ms = int(baseline["avg_ms"] * scenario["duration_multiplier"])
        status = 200

        # Record the truth for the label file
        label_info = {
            "attack_type": scenario["type"],
            "tactic": scenario["tactic"],
            "description": scenario["desc"],
            "expected_size": baseline["avg_bytes"],
            "actual_size": bytes_sent,
            "expected_duration": baseline["avg_ms"],
            "actual_duration": duration_ms
        }

    else:
        # Normal Traffic
        uri = random.choice(list(ENDPOINTS.keys()))
        baseline = ENDPOINTS[uri]
        method = baseline["method"]

        # Calculate Normal Values (Gaussian)
        bytes_sent = int(random.gauss(baseline["avg_bytes"], baseline["std_bytes"]))
        duration_ms = int(random.gauss(baseline["avg_ms"], baseline["std_ms"]))
        status = 200

    # Safety checks to prevent negative numbers
    bytes_sent = max(10, bytes_sent)
    duration_ms = max(5, duration_ms)

    req_bytes = random.randint(100, 1000)
    referer = "-"
    user_agent = fake.user_agent()

    # Log Format
    log_line = f'{ip} - {user} [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {uri} HTTP/1.1" {status} {req_bytes} {bytes_sent} {duration_ms} "{referer}" "{user_agent}" {session_id}'

    return log_line, label_info


def main():
    print(f"[*] Generating {TOTAL_RECORDS} records...")
    print(f"[*] Output: {LOG_FILE}")
    print(f"[*] Labels: {LABEL_FILE}")

    current_time = START_TIME
    ground_truth = []

    with open(LOG_FILE, "w") as f_log:
        for i in range(TOTAL_RECORDS):
            current_time = get_log_time(current_time)

            # Inject attack
            is_attack = random.random() < ATTACK_RATIO

            line, attack_metadata = generate_record(current_time, is_attack)

            # If it was an attack, save to ground truth list
            if attack_metadata:
                ground_truth.append({
                    "line_number": i + 1,
                    "timestamp": current_time.isoformat(),
                    "log_content": line,
                    **attack_metadata  # Unpack the details
                })

            f_log.write(line + "\n")

            if (i + 1) % 2000 == 0:
                print(f"    Generated {i + 1}...")

    # Write the Ground Truth file
    with open(LABEL_FILE, "w") as f_label:
        json.dump(ground_truth, f_label, indent=4)

    print(f"[+] Complete. Injected {len(ground_truth)} attacks.")



if __name__ == "__main__":
    main()