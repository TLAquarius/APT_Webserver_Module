import email
from email import policy
import os
import re

# Import từ các file phụ tá chúng ta vừa tạo
from utils import setup_directories, calculate_hash, URL_REGEX, QUARANTINE_DIR
from auth_checker import check_email_auth

def parse_eml_file(file_path):
    """Bóc tách một file .eml và trả về dữ liệu dạng Dictionary"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f, policy=policy.default)
    except Exception as e:
        return {"error": f"Không thể đọc file {file_path}: {e}"}

    email_data = {
        "file_name": os.path.basename(file_path),
        "headers": {
            "from": msg.get('From', ''),
            "to": msg.get('To', ''),
            "subject": msg.get('Subject', ''),
            "date": msg.get('Date', ''),
            "message_id": msg.get('Message-ID', '')
        },
        "authentication": check_email_auth(msg),
        "extracted_urls": [],
        "attachments": [],
        "body_text": ""
    }

    urls_set = set()

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        filename = part.get_filename()

        # Xử lý nội dung văn bản
        if content_type in ['text/plain', 'text/html'] and filename is None:
            try:
                body_text = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                urls = re.findall(URL_REGEX, body_text)
                urls_set.update(urls)
                
                if content_type == 'text/plain':
                    email_data["body_text"] += body_text + "\n"
                elif content_type == 'text/html' and not email_data["body_text"]:
                    clean_text = re.sub(r'<[^>]+>', ' ', body_text)
                    email_data["body_text"] += clean_text + "\n"
            except Exception:
                pass

        # Xử lý File đính kèm
        elif filename:
            safe_filename = f"{msg.get('Message-ID', 'unknown').strip('<>')}_{filename}"
            safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in "._- ")
            filepath = os.path.join(QUARANTINE_DIR, safe_filename)
            
            with open(filepath, 'wb') as f:
                f.write(part.get_payload(decode=True))
                
            md5, sha256 = calculate_hash(filepath)
            
            email_data["attachments"].append({
                "filename": filename,
                "saved_path": filepath,
                "size_bytes": os.path.getsize(filepath),
                "hashes": {
                    "md5": md5,
                    "sha256": sha256
                }
            })

    email_data["extracted_urls"] = list(urls_set)
    email_data["body_text"] = email_data["body_text"].strip() 
    
    return email_data