import os
import hashlib

# CẤU HÌNH ĐƯỜNG DẪN CHUNG
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE_DIR, "data", "sample_emails")
QUARANTINE_DIR = os.path.join(BASE_DIR, "data", "quarantine_attachments")

URL_REGEX = r'(https?://[^\s<"\']+)'

def setup_directories():
    """Đảm bảo các thư mục cần thiết luôn tồn tại"""
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

def calculate_hash(file_path):
    """Tính toán mã băm MD5 và SHA256 của file"""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)
            
    return md5_hash.hexdigest(), sha256_hash.hexdigest()