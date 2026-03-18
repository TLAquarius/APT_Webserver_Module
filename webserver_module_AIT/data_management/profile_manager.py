import os
import json
import hashlib
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple


class DuplicateFileError(Exception):
    """Custom exception raised when a file has already been uploaded."""
    pass


class ProfileManager:
    """
    Manages tenants (profiles), raw file ingestion, deduplication (MD5),
    and fast temporal metadata extraction for the Webserver AIT module.
    """

    def __init__(self, base_data_dir: str = "./module_data"):
        self.base_data_dir = base_data_dir
        os.makedirs(self.base_data_dir, exist_ok=True)

        # Regex supports both Access Log (e.g. 10/Oct/2000:13:55:36)
        # and Error Log (e.g. Thu Oct 11 15:30:22 2000) formats.
        self.time_pattern = re.compile(
            r"\[(\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+\-]\d{4})?)\]|"
            r"\[([A-Z][a-z]{2}\s[A-Z][a-z]{2}\s\d{1,2}\s\d{2}:\d{2}:\d{2}.*?\d{4})\]"
        )

    def get_all_profiles(self) -> List[str]:
        """Returns a list of all existing profile names."""
        try:
            return [d for d in os.listdir(self.base_data_dir)
                    if os.path.isdir(os.path.join(self.base_data_dir, d))]
        except Exception:
            return []

    def create_profile(self, profile_name: str) -> bool:
        """Creates the standardized folder structure for a new profile."""
        safe_name = "".join(c for c in profile_name if c.isalnum() or c in ('_', '-')).strip()
        if not safe_name:
            raise ValueError("Invalid profile name.")

        profile_path = os.path.join(self.base_data_dir, safe_name)

        if os.path.exists(profile_path):
            return False

        os.makedirs(os.path.join(profile_path, "raw_logs"), exist_ok=True)
        os.makedirs(os.path.join(profile_path, "models"), exist_ok=True)
        os.makedirs(os.path.join(profile_path, "results"), exist_ok=True)

        metadata_path = os.path.join(profile_path, "metadata.json")
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump([], f)

        return True

    def _calculate_md5(self, file_bytes: bytes) -> str:
        return hashlib.md5(file_bytes).hexdigest()

    def _load_metadata(self, profile_name: str) -> List[Dict]:
        metadata_path = os.path.join(self.base_data_dir, profile_name, "metadata.json")
        if not os.path.exists(metadata_path):
            return []
        with open(metadata_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def _save_metadata(self, profile_name: str, metadata: List[Dict]):
        metadata_path = os.path.join(self.base_data_dir, profile_name, "metadata.json")
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)

    def _extract_time_boundaries(self, physical_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Fast heuristic extraction of start and end timestamps.
        Uses defensive multi-line reading and 2KB chunking for Unicode safety.
        """
        first_time_str = None
        last_time_str = None

        try:
            with open(physical_path, 'rb') as f:
                # 1. Read up to first 50 lines to bypass empty headers (From Design 2)
                for _ in range(50):
                    line = f.readline().decode('utf-8', errors='ignore')
                    if not line:
                        break
                    match = self.time_pattern.search(line)
                    if match:
                        first_time_str = match.group(1) or match.group(2)
                        break

                # 2. Seek to end, read last 2048 bytes to safely catch last line (From Design 2)
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                offset = max(0, file_size - 2048)
                f.seek(offset)

                last_lines = f.readlines()
                for line in reversed(last_lines):
                    decoded_line = line.decode('utf-8', errors='ignore')
                    match = self.time_pattern.search(decoded_line)
                    if match:
                        last_time_str = match.group(1) or match.group(2)
                        break

            return first_time_str, last_time_str

        except Exception as e:
            print(f"Warning: Could not extract time range from {physical_path}: {e}")
            return None, None

    def ingest_file(self,
                    profile_name: str,
                    uploaded_file,
                    log_type: str,
                    operation_mode: str,
                    log_format: str,
                    time_window: Optional[Tuple[datetime, datetime]] = None) -> Dict:
        """
        Validates, deduplicates, saves securely, extracts temporal bounds, and registers.
        """
        if profile_name not in self.get_all_profiles():
            raise ValueError(f"Profile '{profile_name}' does not exist.")

        file_bytes = uploaded_file.read()
        file_hash = self._calculate_md5(file_bytes)

        metadata = self._load_metadata(profile_name)
        for record in metadata:
            if record.get("file_hash") == file_hash:
                raise DuplicateFileError(f"File '{uploaded_file.name}' is a duplicate in this profile.")

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp_str}_{uploaded_file.name}"
        physical_path = os.path.join(self.base_data_dir, profile_name, "raw_logs", safe_filename)

        uploaded_file.seek(0)
        with open(physical_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        min_time, max_time = self._extract_time_boundaries(physical_path)

        file_record = {
            "file_id": f"log_{file_hash[:8]}_{timestamp_str}",
            "original_name": uploaded_file.name,
            "physical_path": physical_path,
            "file_type": log_type,
            "log_format": log_format,
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