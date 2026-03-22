def calculate_final_decision(scan_results):
    """
    Hàm tính tổng điểm rủi ro và ra quyết định hành động cho Mail Server
    """
    total_score = 0
    reasons = []

    # 1. ĐÁNH GIÁ CÁC ĐƯỜNG LINK (URLs)
    for url_data in scan_results.get("urls", []):
        vt_report = url_data.get("report", {})
        if vt_report.get("status") == "Malicious":
            # Mỗi engine phát hiện cộng 5 điểm, tối đa 50 điểm cho 1 URL
            vt_score = vt_report.get("malicious_score", 0)
            score_add = min(vt_score * 5, 50) 
            total_score += score_add
            reasons.append(f"[URL] VirusTotal phát hiện link độc hại ({vt_score} engines): {url_data['url']} (+{score_add} điểm)")

    # 2. ĐÁNH GIÁ FILE ĐÍNH KÈM
    for att in scan_results.get("attachments", []):
        filename = att.get("filename", "Unknown")
        
        # a. Đánh giá từ YARA Rules
        yara_report = att.get("yara_scan", {})
        if yara_report.get("status") == "Malicious":
            total_score += 60
            matched_rules = ", ".join(yara_report.get("matched_rules", []))
            reasons.append(f"[FILE] YARA phát hiện vi phạm luật '{matched_rules}' trong file {filename} (+60 điểm)")

        # b. Đánh giá từ VirusTotal (Hash)
        vt_report = att.get("virustotal_scan", {})
        if vt_report.get("status") == "Malicious":
            vt_score = vt_report.get("malicious_score", 0)
            score_add = min(vt_score * 5, 50)
            total_score += score_add
            reasons.append(f"[FILE] VirusTotal phát hiện mã độc ({vt_score} engines) ở file {filename} (+{score_add} điểm)")

        # c. Đánh giá từ Cuckoo Sandbox
        cuckoo_report = att.get("cuckoo_scan", {})
        if cuckoo_report.get("status") != "Not Scanned" and "Error" not in cuckoo_report.get("status", ""):
            c_score = cuckoo_report.get("cuckoo_score", 0)
            score_add = int(c_score * 10) # Chuyển đổi thang 10 sang thang 100
            if score_add > 0:
                total_score += score_add
                reasons.append(f"[FILE] Cuckoo Sandbox đánh giá hành vi rủi ro {c_score}/10 cho file {filename} (+{score_add} điểm)")

    # 3. RA QUYẾT ĐỊNH (ACTION)
    action = "ACCEPT"
    severity = "LOW (An toàn)"
    
    if total_score >= 50:
        action = "REJECT"
        severity = "CRITICAL (Nguy hiểm cao)"
    elif total_score >= 20:
        action = "QUARANTINE"
        severity = "MEDIUM (Đáng ngờ)"
        
    return {
        "final_score": total_score,
        "severity": severity,
        "recommended_action": action,
        "reasons": reasons
    }