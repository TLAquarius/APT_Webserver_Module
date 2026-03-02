import json
import requests
import sys

API_URL = "http://127.0.0.1:8000/api/v1/ingest/bulk"


def run_bulk_ingestion(file_path):
    print(f"[*] Reading alerts from {file_path}...")
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Ensure it's a list
        alerts = data if isinstance(data, list) else [data]

        payload = {
            "module_source": "web_server",
            "alerts": alerts
        }

        print(f"[*] Sending {len(alerts)} alerts to SIEM...")
        response = requests.post(API_URL, json=payload)

        if response.status_code == 200:
            result = response.json()
            print(f"[DONE] Successfully indexed {result['indexed']} alerts in milliseconds!")
        else:
            print(f"[!] Server Error: {response.text}")

    except FileNotFoundError:
        print(f"[ERROR] Could not find {file_path}. Did you run detect_anomalies.py?")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "data/csic_alerts.json"
    run_bulk_ingestion(target_file)