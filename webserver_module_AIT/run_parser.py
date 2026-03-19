import os
import pandas as pd
# Hãy sửa đường dẫn import theo đúng thư mục của bạn
from parser.parser_class import WebServerLogParser

if __name__ == '__main__':
    # 1. THAY ĐỔI ĐƯỜNG DẪN NÀY ĐẾN FOLDER GATHER CỦA AIT V2.0
    GATHER_DIR = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"

    TARGET_HOSTS = ["webserver", "intranet_server", "cloud_share"]
    temp_storage = "test_temp_parsed_chunks.ndjson"
    output_ndjson = "test_parsed_timeline.json"

    # Xóa file temp cũ nếu có
    if os.path.exists(temp_storage): os.remove(temp_storage)

    print("=== STARTING STRICT PARSER FOR EVALUATION ===")
    parser = WebServerLogParser(chunk_size=50000)

    for host in TARGET_HOSTS:
        apache_dir = os.path.join(GATHER_DIR, host, "logs", "apache2")
        if not os.path.exists(apache_dir):
            continue

        print(f"\n[*] Scanning logs for host: {host}...")
        for filename in os.listdir(apache_dir):
            filepath = os.path.join(apache_dir, filename)

            if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0 or filepath.endswith('.gz'):
                continue

            try:
                # Tự động nhận diện định dạng và loại log (access hay error)
                log_format, log_type = WebServerLogParser.auto_detect_format(filepath)
                print(f"  -> Processing {filename} [Format: {log_format}]")

                # Gọi process_log_file với host_name
                parser.process_log_file(
                    filepath=filepath,
                    log_format=log_format,
                    log_type=log_type,
                    host_name=host,
                    stream_to_disk=True,
                    temp_out=temp_storage
                )
            except Exception as e:
                print(f"  [!] Skipped {filename}: {e}")

    print("\n[*] Sorting timeline chronologically...")
    df_timeline = parser.get_timeline_dataframe(from_disk=True, temp_out=temp_storage)

    if not df_timeline.empty:
        print(f"\n[+] SUCCESS: Parsed {len(df_timeline)} total events.")
        parser.export_to_ndjson(output_ndjson, from_disk=True, temp_out=temp_storage)
        print(f"[+] Exported final timeline to {output_ndjson}")
    else:
        print("[-] Timeline is empty. Check GATHER_DIR.")

    if os.path.exists(temp_storage):
        os.remove(temp_storage)