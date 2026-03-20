def check_email_auth(msg):
    """Trích xuất kết quả xác thực SPF, DKIM, DMARC từ Header"""
    auth_results = msg.get_all('Authentication-Results', [])
    received_spf = msg.get_all('Received-SPF', [])
    
    auth_data = {
        "spf": "None/Unknown",
        "dkim": "None/Unknown",
        "dmarc": "None/Unknown"
    }
    
    all_auth_headers = " ".join(auth_results + received_spf).lower()
    
    if all_auth_headers:
        # Kiểm tra SPF
        if "spf=pass" in all_auth_headers: auth_data["spf"] = "Pass"
        elif "spf=fail" in all_auth_headers or "spf=softfail" in all_auth_headers: auth_data["spf"] = "Fail"
        
        # Kiểm tra DKIM
        if "dkim=pass" in all_auth_headers: auth_data["dkim"] = "Pass"
        elif "dkim=fail" in all_auth_headers: auth_data["dkim"] = "Fail"
        
        # Kiểm tra DMARC
        if "dmarc=pass" in all_auth_headers: auth_data["dmarc"] = "Pass"
        elif "dmarc=fail" in all_auth_headers: auth_data["dmarc"] = "Fail"
        
    return auth_data
# Mở file src/auth_checker.py và thêm hàm này vào:

def check_reply_to_anomaly(msg):
    """
    Kiểm tra sự bất thường giữa người gửi (From) và nơi nhận phản hồi (Reply-To)
    Đây là kỹ thuật kinh điển của tấn công BEC.
    """
    from_header = msg.get('From', '').lower()
    reply_to_header = msg.get('Reply-To', '').lower()

    # Trích xuất địa chỉ email thực sự từ chuỗi "Tên Hiển Thị <email@domain.com>"
    import re
    def extract_email(header_string):
        match = re.search(r'<([^>]+)>', header_string)
        return match.group(1) if match else header_string.strip()

    from_email = extract_email(from_header)
    reply_to_email = extract_email(reply_to_header) if reply_to_header else None

    # Nếu có cấu hình Reply-To và nó KHÁC với đuôi tên miền của người gửi
    if reply_to_email and reply_to_email != from_email:
        from_domain = from_email.split('@')[-1] if '@' in from_email else ""
        reply_domain = reply_to_email.split('@')[-1] if '@' in reply_to_email else ""
        
        # Nếu gửi từ email công ty nhưng bảo Reply về @gmail, @yahoo...
        if from_domain != reply_domain:
            return {
                "is_anomalous": True,
                "message": f"[BEC ALERT] Cảnh báo: Email gửi từ '{from_email}' nhưng yêu cầu phản hồi về '{reply_to_email}'!"
            }
            
    return {"is_anomalous": False, "message": "Reply-To hợp lệ hoặc không sử dụng."}