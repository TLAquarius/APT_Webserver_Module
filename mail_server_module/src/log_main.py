import os
from siem_connector import connect_siem, push_to_siem
from log_parser import parse_log_line
from rules.rule_auth import check_brute_force, check_password_spraying, check_off_hours_login
from rules.rule_smtp import check_smtp_enumeration, check_relay_attempt
from rules.rule_spam import check_mass_outbound_spam
from rules.rule_ueba import check_impossible_travel, check_new_ip_login

def process_log_file(file_path):
    es_client = connect_siem()
    if not es_client: return

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            # Lớp 0: Tiền xử lý
            log_data = parse_log_line(line)
            if not log_data: 
                continue # Bỏ qua dòng rác

            # Khai báo danh sách các công cụ quét (có thể thêm bớt dễ dàng)
            detectors = [
                check_brute_force, 
                check_password_spraying, 
                check_off_hours_login,
                check_smtp_enumeration,
                check_relay_attempt,
                check_mass_outbound_spam,
                check_impossible_travel,
                check_new_ip_login
            ]
            
            # Chạy qua từng phễu
            for detector_func in detectors:
                alert = detector_func(log_data)
                
                if alert:
                    # Gắn thêm thời gian chuẩn trước khi đẩy lên Kibana
                    alert["@timestamp"] = log_data['timestamp'].isoformat()
                    push_to_siem(es_client, "apt-log-alerts", alert)
                    print(f"[!] Bắt được cảnh báo: {alert['alert_type']} từ IP {alert['source_ip']}")

if __name__ == "__main__":
    # Danh sách các "mỏ dữ liệu" cần khai thác
    log_sources = [
        "data/auth.log", 
        "data/mail.log"
    ]
    
    print("[*] KHỞI ĐỘNG HỆ THỐNG SIEM PHÂN TÍCH LOG...")
    for file_path in log_sources:
        print(f"\n[+] Đang nạp và phân tích: {file_path}")
        process_log_file(file_path)
        
    print("\n[+] HOÀN TẤT QUÉT TẤT CẢ FILE LOG!")