import os
import pandas as pd
from parser.parser_class import WebServerLogParser  # Assuming you saved the class in log_parser.py

if __name__ == '__main__':
    # 1. Update this path to where your extracted 'gather' folder is located
    GATHER_DIR = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"

    # The 3 web servers involved in the APT simulation
    TARGET_HOSTS = ["webserver", "intranet_server", "cloud_share"]

    temp_storage = "temp_parsed_chunks.ndjson"
    output_ndjson = "russellmitchell_enterprise_web_timeline.json"

    # Initialize your optimized parser
    print("=== Starting AIT-LDS Enterprise Web Log Ingestion ===")
    parser = WebServerLogParser(chunk_size=50000)

    # 2. Loop through each server and feed the logs to the parser
    for host in TARGET_HOSTS:
        apache_dir = os.path.join(GATHER_DIR, host, "logs", "apache2")

        if not os.path.exists(apache_dir):
            print(f"[!] Warning: Directory not found for {host}: {apache_dir}")
            continue

        print(f"\n[*] Scanning directory for {host}...")

        for filename in os.listdir(apache_dir):
            filepath = os.path.join(apache_dir, filename)

            # Skip directories, empty files, and compressed .gz files
            if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0 or filepath.endswith('.gz'):
                continue

            if "access" in filename:
                parser.parse_access_log(
                    filepath=filepath,
                    host_name=host,
                    stream_to_disk=True,
                    temp_out=temp_storage
                )
            elif "error" in filename:
                parser.parse_error_log(
                    filepath=filepath,
                    host_name=host,
                    stream_to_disk=True,
                    temp_out=temp_storage
                )

    # 3. Compile the Timeline
    print("\n[*] Sorting multi-server timeline and loading to Pandas DataFrame...")
    df_timeline = parser.get_timeline_dataframe(from_disk=True, temp_out=temp_storage)

    # 4. Verify the Output
    if not df_timeline.empty:
        print(f"\n[+] SUCCESS: Created a unified timeline with {len(df_timeline)} events.")

        print("\n--- Sample Cross-Server Timeline Data ---")
        # ADDED: 'event_source' and 'raw_message' to easily spot the new error logs in the console
        display_cols = ['@timestamp', 'host_name', 'event_source', 'source_ip', 'http_method', 'status_code', 'raw_message']
        existing_cols = [col for col in display_cols if col in df_timeline.columns]
        print(df_timeline[existing_cols].head(15).to_string())

        # =====================================================================
        # 4.5. DATASET PROFILING & DEBUGGING (NEW BLOCK)
        # =====================================================================
        print("\n[*] Generating dataset profile & distinct value files...")
        debug_dir = "../debug_output"
        os.makedirs(debug_dir, exist_ok=True)

        # A. Profile Distinct Source IPs
        if 'source_ip' in df_timeline.columns:
            ip_counts = df_timeline['source_ip'].value_counts().reset_index()
            ip_counts.columns = ['source_ip', 'occurrence_count']
            ip_counts.to_csv(os.path.join(debug_dir, "distinct_ips.csv"), index=False)
            print(f"  -> Saved {len(ip_counts)} distinct IPs to {debug_dir}/distinct_ips.csv")

        # B. Profile Distinct URIs (Paths)
        if 'uri_path' in df_timeline.columns:
            uri_counts = df_timeline['uri_path'].value_counts().reset_index()
            uri_counts.columns = ['uri_path', 'occurrence_count']
            uri_counts.to_csv(os.path.join(debug_dir, "distinct_uris.csv"), index=False)
            print(f"  -> Saved {len(uri_counts)} distinct URIs to {debug_dir}/distinct_uris.csv")

        # C. Profile Distinct User-Agents (dropping NaNs from error logs first)
        if 'user_agent' in df_timeline.columns:
            ua_counts = df_timeline['user_agent'].dropna().value_counts().reset_index()
            ua_counts.columns = ['user_agent', 'occurrence_count']
            ua_counts.to_csv(os.path.join(debug_dir, "distinct_user_agents.csv"), index=False)
            print(f"  -> Saved {len(ua_counts)} distinct User-Agents to {debug_dir}/distinct_user_agents.csv")

        # D. Profile Distinct HTTP Methods (Helps spot WEBDAV attacks or OPTIONS abuse)
        if 'http_method' in df_timeline.columns:
            method_counts = df_timeline['http_method'].dropna().value_counts().reset_index()
            method_counts.columns = ['http_method', 'occurrence_count']
            method_counts.to_csv(os.path.join(debug_dir, "distinct_methods.csv"), index=False)
            print(f"  -> Saved {len(method_counts)} distinct HTTP Methods to {debug_dir}/distinct_methods.csv")

            # E. Profile Time Distribution (Grouped by Hour)
            if '@timestamp' in df_timeline.columns:
                # Create a temporary column that rounds the time down to the nearest Hour
                df_timeline['date_hour'] = df_timeline['@timestamp'].dt.floor('h')

                # Count how many requests happened in each hour, sorted chronologically
                time_counts = df_timeline['date_hour'].value_counts().sort_index().reset_index()
                time_counts.columns = ['date_hour', 'request_count']

                time_distribution_file = os.path.join(debug_dir, "time_distribution.csv")
                time_counts.to_csv(time_distribution_file, index=False)

                print(f"  -> Saved time distribution (by hour) to {time_distribution_file}")

                # Print a quick preview to the console
                print("\n--- Quick Time Distribution Preview (Top 5 Busiest Hours) ---")
                print(time_counts.sort_values(by='request_count', ascending=False).head(5).to_string(index=False))
        # =====================================================================

        # 5. Export to JSON for Layer 1 to use later
        print(f"\n[*] Exporting to final SIEM-ready JSON: {output_ndjson}...")
        parser.export_to_ndjson(output_ndjson, from_disk=True, temp_out=temp_storage)
    else:
        print("[!] Timeline is empty. Check your GATHER_DIR path.")

    # Cleanup temp file
    if os.path.exists(temp_storage):
        os.remove(temp_storage)
        print("\n[*] Cleaned up temporary chunks. Parsing complete.")