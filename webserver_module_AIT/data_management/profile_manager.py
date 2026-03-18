import os
import json
import hashlib
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Import Parser để dùng tính năng nhận diện tự động
from parser.parser_class import WebServerLogParser

class DuplicateFileError(Exception):
    pass

class ProfileManager:
    def __init__(self, base_data_dir: str = "./webserver_module_AIT/module_data"):
        self.base_data_dir = base_data_dir
        os.makedirs(self.base_data_dir, exist_ok=True)

        self.time_pattern = re.compile(
            r"\[(\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+\-]\d{4})?)\]|"
            r"\[([A-Z][a-z]{2}\s[A-Z][a-z]{2}\s\d{1,2}\s\d{2}:\d{2}:\d{2}.*?\d{4})\]"
        )

    def get_all_profiles(self) -> List[str]:
        try:
            return [d for d in os.listdir(self.base_data_dir)
                    if os.path.isdir(os.path.join(self.base_data_dir, d))]
        except Exception:
            return []

    def create_profile(self, profile_name: str) -> bool:
        safe_name = "".join(c for c in profile_name if c.isalnum() or c in ('_', '-')).strip()
        if not safe_name: raise ValueError("Invalid profile name.")

        profile_path = os.path.join(self.base_data_dir, safe_name)
        if os.path.exists(profile_path): return False

        os.makedirs(os.path.join(profile_path, "raw_logs"), exist_ok=True)
        os.makedirs(os.path.join(profile_path, "models"), exist_ok=True)
        os.makedirs(os.path.join(profile_path, "results"), exist_ok=True)

        with open(os.path.join(profile_path, "metadata.json"), 'w', encoding='utf-8') as f:
            json.dump([], f)
        return True

    def _calculate_md5(self, file_bytes: bytes) -> str:
        return hashlib.md5(file_bytes).hexdigest()

    def _load_metadata(self, profile_name: str) -> List[Dict]:
        path = os.path.join(self.base_data_dir, profile_name, "metadata.json")
        if not os.path.exists(path): return []
        with open(path, 'r', encoding='utf-8') as f:
            try: return json.load(f)
            except json.JSONDecodeError: return []

    def _save_metadata(self, profile_name: str, metadata: List[Dict]):
        path = os.path.join(self.base_data_dir, profile_name, "metadata.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)

    def _extract_time_boundaries(self, physical_path: str) -> Tuple[Optional[str], Optional[str]]:
        first_time_str = last_time_str = None
        try:
            with open(physical_path, 'rb') as f:
                for _ in range(50):
                    line = f.readline().decode('utf-8', errors='ignore')
                    if not line: break
                    match = self.time_pattern.search(line)
                    if match:
                        first_time_str = match.group(1) or match.group(2)
                        break

                f.seek(0, os.SEEK_END)
                offset = max(0, f.tell() - 2048)
                f.seek(offset)
                for line in reversed(f.readlines()):
                    match = self.time_pattern.search(line.decode('utf-8', errors='ignore'))
                    if match:
                        last_time_str = match.group(1) or match.group(2)
                        break
            return first_time_str, last_time_str
        except Exception as e:
            return None, None

    def ingest_file(self, profile_name: str, uploaded_file, operation_mode: str, time_window=None) -> Dict:
        """Kiểm duyệt, băm MD5, Nhận diện Auto-detect và Lưu dữ liệu"""
        if profile_name not in self.get_all_profiles():
            raise ValueError(f"Profile '{profile_name}' does not exist.")

        file_bytes = uploaded_file.read()
        file_hash = self._calculate_md5(file_bytes)

        metadata = self._load_metadata(profile_name)
        for record in metadata:
            if record.get("file_hash") == file_hash:
                raise DuplicateFileError(f"File '{uploaded_file.name}' đã tồn tại (Trùng MD5).")

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp_str}_{uploaded_file.name}"
        physical_path = os.path.join(self.base_data_dir, profile_name, "raw_logs", safe_filename)

        uploaded_file.seek(0)
        with open(physical_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        # =======================================================
        # 🟢 GỌI AUTO-DETECT TỪ PARSER NGAY SAU KHI LƯU FILE
        # =======================================================
        try:
            log_format, log_type = WebServerLogParser.auto_detect_format(physical_path)
        except Exception as e:
            # Nếu không phải log hợp lệ, xóa file rác khỏi ổ cứng để tiết kiệm dung lượng
            os.remove(physical_path)
            raise ValueError(f"Từ chối file '{uploaded_file.name}': {e}")

        min_time, max_time = self._extract_time_boundaries(physical_path)

        file_record = {
            "file_id": f"log_{file_hash[:8]}_{timestamp_str}",
            "original_name": uploaded_file.name,
            "physical_path": physical_path,
            "file_type": log_type,        # Điền tự động từ Auto-detect
            "log_format": log_format,     # Điền tự động từ Auto-detect
            "operation_mode": operation_mode,
            "file_hash": file_hash,
            "size_bytes": len(file_bytes),
            "upload_time": datetime.now().isoformat(),
            "min_timestamp_str": min_time,
            "max_timestamp_str": max_time,
            "time_window_filter": [dt.isoformat() for dt in time_window] if time_window else None,
            "status": "pending_orchestration"
        }

        metadata.append(file_record)
        self._save_metadata(profile_name, metadata)

        return file_record