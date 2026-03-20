import json
from datetime import datetime

def export_anomaly_to_json(test_df, host_table = None, output_path="output/anomaly_report.json"):

    anomalies = test_df[test_df["y_pred"] == -1]

    ai_prompt = (
        "You are a network security expert. "
        "Based on the network flow logs and detected anomalies, "
        "identify suspicious hosts, assess their risk levels, "
        "and classify potential APT activities. "
        "Provide detailed explanations for each host and traffic flow."
    )

    report = {
        "report_metadata": {
            "generated_at": datetime.utcnow().isoformat(),
            "total_records": len(test_df),
            "total_anomalies": len(anomalies),
            "anomaly_ratio": round(len(anomalies) / len(test_df), 6),
            "feature_space": list(test_df.columns)
        },
        "ai_prompt": ai_prompt,
        "anomalies": []
    }

    if host_table is not None:
        report["host_risk_summary"] = []

        for _, row in host_table.iterrows():
            host_record = {
                "source_ip": row["Source IP"],
                "total_flows": int(row["total_flows"]),
                "anomaly_flows": int(row["anomaly_flows"]),
                "anomaly_ratio": float(row["anomaly_ratio"]),
                "unique_destinations": int(row["unique_dest"]),
                "active_duration_seconds": float(row["active_duration"]),
                "risk_score": float(row["risk_score"]),
                "apt_flag": int(row["apt_flag"])
            }
            report["host_risk_summary"].append(host_record)

    for _, row in anomalies.iterrows():
        record = {
            "network_context": {
                "source_ip": row.get("Source IP"),
                "destination_ip": row.get("Destination IP"),
                "source_port": row["Source Port"],
                "destination_port": row["Destination Port"],
                "nat_source_port": row["NAT Source Port"],
                "nat_destination_port": row["NAT Destination Port"],
                "action": row.get("Action")
            },
            "traffic_features": {
                "total_bytes": row["Bytes"],
                "bytes_sent": row["Bytes Sent"],
                "bytes_received": row["Bytes Received"],
                "total_packets": row["Packets"],
                "packets_sent": row["pkts_sent"],
                "packets_received": row["pkts_received"],
                "duration_seconds": row["Elapsed Time (sec)"]
            },
            "behavioral_features": {
                "byte_ratio": row["byte_ratio"],
                "packet_ratio": row["packet_ratio"],
                "bytes_per_packet": row["bytes_per_packet"],
                "connection_intensity": row["connection_intensity"]
            },
            "model_output": {
                "prediction": int(row["y_pred"]),
                "ground_truth": int(row["y_true"]) if "y_true" in row else None,
                "is_anomaly": True
            }
        }
        report["anomalies"].append(record)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[+] JSON report for AI saved to {output_path}")