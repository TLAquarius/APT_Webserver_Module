import pandas as pd
import json
from collections import defaultdict

# CONFIG (Switch to 'zaker' when ready)
DATASET = "csic"
ALERTS_FILE = f"data/{DATASET}_alerts.csv"
FORENSICS_FILE = f"data/{DATASET}_forensics.jsonl"
OUTPUT_REPORT = f"data/{DATASET}_campaign_report.txt"


def build_campaigns():
    print(f"[TIMELINE] Building Campaigns for {DATASET.upper()}...")

    # 1. Load Alerts
    alerts = pd.read_csv(ALERTS_FILE)
    # Filter for non-Normal
    suspicious_alerts = alerts[alerts['verdict'] != 'Normal']

    if suspicious_alerts.empty:
        print("[INFO] No alerts found. Nothing to report.")
        return

    # Create Lookup: Session Key -> Alert Details
    # Cast key to string to avoid int/str mismatch issues
    alert_map = {str(row['session_key']): row for _, row in suspicious_alerts.iterrows()}

    print(f"  > Loaded {len(suspicious_alerts)} alerts.")

    # 2. Load Forensics & Group by IP
    campaigns = defaultdict(list)

    try:
        with open(FORENSICS_FILE, 'r') as f:
            for line in f:
                rec = json.loads(line)
                key = str(rec['session_key'])

                # Only keep this session if it triggered an alert
                if key in alert_map:
                    # Attach the alert metadata to the forensic record
                    rec['alert_meta'] = alert_map[key]
                    campaigns[rec['ip']].append(rec)
    except FileNotFoundError:
        print(f"[ERROR] Forensics file {FORENSICS_FILE} not found.")
        return

    print(f"  > Grouped into {len(campaigns)} IP Campaigns.")

    # 3. Generate Report
    with open(OUTPUT_REPORT, 'w', encoding='utf-8') as f:
        for ip, sessions in campaigns.items():
            f.write(f"{'=' * 80}\n")
            f.write(f"  ATTACKER CAMPAIGN: {ip}\n")
            f.write(f"  Total Sessions: {len(sessions)}\n")
            f.write(f"{'=' * 80}\n\n")

            # Sort sessions by start time
            sessions.sort(key=lambda s: s['timeline'][0]['ts'])

            for s in sessions:
                meta = s['alert_meta']
                f.write(
                    f"  [SESSION {s['session_key']}] Verdict: {meta['verdict']} | Reason: {meta['reason']} | Risk: {meta['risk']}\n")
                f.write(f"  Timeline:\n")

                for event in s['timeline']:
                    # Marker for high risk events
                    mark = "[!]" if event['risk'] == 'High' else "   "
                    f.write(f"    {mark} {event['ts']} | {event['method']} {event['path']} ({event['status']})\n")
                f.write("\n")

            # LLM Prompt Stub
            f.write(f"  [LLM PROMPT]\n")
            f.write(f"  Analyze this campaign from IP {ip}. It contains {len(sessions)} alert sessions.\n")
            f.write("  Identify the attack stages and recommend mitigation.\n\n")

    print(f"[DONE] Report saved to {OUTPUT_REPORT}")


if __name__ == "__main__":
    build_campaigns()