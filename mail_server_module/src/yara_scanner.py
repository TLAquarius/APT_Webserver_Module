import yara
import os

# Đường dẫn tới file luật YARA
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_PATH = os.path.join(BASE_DIR, "rules", "yara_rules", "basic_apt.yar")

def scan_file_with_yara(file_path):
    """Quét file bằng luật YARA nội bộ"""
    try:
        if not os.path.exists(RULES_PATH):
            return {"status": "Error", "message": "Không tìm thấy file luật YARA."}

        # Biên dịch luật
        rules = yara.compile(filepath=RULES_PATH)
        
        # Tiến hành quét file
        matches = rules.match(file_path)
        
        if matches:
            # Lấy tên các luật đã bắt trúng
            matched_rule_names = [match.rule for match in matches]
            return {
                "status": "Malicious",
                "engine": "YARA (Local)",
                "matched_rules": matched_rule_names,
                "message": f"CẢNH BÁO: Vi phạm luật {', '.join(matched_rule_names)}"
            }
        else:
            return {
                "status": "Clean",
                "engine": "YARA (Local)",
                "message": "Không phát hiện mã độc tĩnh."
            }
            
    except Exception as e:
        return {"status": "Error", "message": f"Lỗi YARA Scanner: {str(e)}"}

# Test thử nghiệm module độc lập
if __name__ == "__main__":
    print("[*] Đang test YARA Scanner...")
    # Bạn có thể trỏ tới một file bất kỳ trong thư mục quarantine để test
    # print(scan_file_with_yara("../data/quarantine_attachments/file_test.exe"))