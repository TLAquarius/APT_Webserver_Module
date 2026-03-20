import os
import time
from apt_parser import parse_eml_file
from vt_scanner import check_ioc_virustotal
from yara_scanner import scan_file_with_yara
from cuckoo_scanner import submit_to_cuckoo, wait_for_cuckoo_report
from decision_maker import calculate_final_decision
from ml_analyzer import analyze_email_content

def analyze_email(file_path):
    """Bóc tách email và tổng hợp các module phân tích"""
    file_name = os.path.basename(file_path)
    print(f"\n{'='*60}")
    print(f"BẮT ĐẦU PHÂN TÍCH: {file_name}")
    print(f"{'='*60}")

    email_data = parse_eml_file(file_path)
    if "error" in email_data:
        print(f"[!] Lỗi: {email_data['error']}")
        return None

    scan_results = {"urls": [], "attachments": [], "ml_scan": {}}

    print("\n[2] Đang phân tích ngữ nghĩa văn bản bằng AI (NLP)...")
    ml_result = analyze_email_content(email_data.get("body_text", ""))
    scan_results["ml_scan"] = ml_result

    if email_data['extracted_urls']:
        print("\n[3] Đang quét các URL trên VirusTotal...")
        for url in email_data['extracted_urls']:
            time.sleep(15) 
            vt_report = check_ioc_virustotal(url, "url")
            scan_results["urls"].append({"url": url, "report": vt_report})

    if email_data['attachments']:
        print("\n[4] Đang phân tích file đính kèm đa lớp...")
        for attachment in email_data['attachments']:
            att_path = attachment['saved_path']
            sha256_hash = attachment['hashes']['sha256']
            
            yara_report = scan_file_with_yara(att_path)
            time.sleep(15)
            vt_report = check_ioc_virustotal(sha256_hash, "hash")

            cuckoo_report = {"status": "Not Scanned", "message": "Bỏ qua"}
            if attachment['size_bytes'] < 10 * 1024 * 1024: 
                task_id = submit_to_cuckoo(att_path)
                if task_id:
                    cuckoo_report = wait_for_cuckoo_report(task_id)

            scan_results["attachments"].append({
                "filename": attachment['filename'],
                "hash": sha256_hash,
                "yara_scan": yara_report,
                "virustotal_scan": vt_report,
                "cuckoo_scan": cuckoo_report
            })

    decision = calculate_final_decision(scan_results)
    print(f"\n[5] TÍNH ĐIỂM & RA QUYẾT ĐỊNH: [{decision['recommended_action']}] (Điểm: {decision['final_score']})")

    return {
        "file_name": file_name,
        "email_info": email_data['headers'],
        "threat_intelligence": scan_results,
        "verdict": decision
    }