import os
import glob
from datetime import datetime, timezone

from utils import setup_directories, SAMPLE_DIR
from siem_connector import connect_siem, push_to_siem
from core_analyzer import analyze_email

def run_pipeline():
    setup_directories()
    eml_files = glob.glob(os.path.join(SAMPLE_DIR, "*.eml"))
    
    if not eml_files:
        print(f"[!] Không có file .eml nào trong {SAMPLE_DIR} để phân tích.")
        return
        
    es_client = connect_siem()
    if not es_client:
        print("[!] Không thể kết nối SIEM, dừng tiến trình.")
        return

    print(f"\n[*] Bắt đầu quét {len(eml_files)} email và đẩy lên SIEM...")
    
    for file_path in eml_files:
        report = analyze_email(file_path)
        
        if report:
            report['@timestamp'] = datetime.now(timezone.utc).isoformat()
            report['sender'] = report['email_info'].get('From', 'Unknown')
            report['action'] = report['verdict'].get('recommended_action', 'UNKNOWN')
            report['total_risk_score'] = report['verdict'].get('final_score', 0)
            report['reasons'] = report['verdict'].get('reasons', [])
            
            push_to_siem(es_client, "apt-email-alerts", report)

    print("\n[+] HOÀN TẤT TOÀN BỘ QUÁ TRÌNH PHÂN TÍCH!")

if __name__ == "__main__":
    run_pipeline()