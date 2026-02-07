import csv
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import urlparse

from .base_parser import BaseLogParser
from .schema import WebLogEvent


class CSICCSVParser(BaseLogParser):

    def parse(self, filepath: str) -> Iterable[WebLogEvent]:
        # Synthetic time generator: Start at a fixed date for reproducibility
        current_time = datetime(2025, 1, 1, 10, 0, 0)

        with open(filepath, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Increment time by 1 second per request to simulate traffic flow
                current_time += timedelta(seconds=1)

                # 1. Clean the URL (remove HTTP/1.1 suffix if present)
                raw_url_field = row.get("URL", "").strip()
                # Split by space to discard " HTTP/1.1" at the end
                clean_url = raw_url_field.split(" ")[0]
                parsed_url = urlparse(clean_url)

                # 2. Extract Label (CSIC puts it in the first empty column or 'classification')
                # Check for empty string key (common in this CSV) or specific header
                label_val = row.get("", row.get("classification", "unknown"))
                if not label_val:
                    label_val = "unknown"

                yield WebLogEvent(
                    event_time=current_time,
                    source_ip="127.0.0.1",  # Placeholder for CSIC
                    http_method=row.get("Method", "GET"),
                    request_path=parsed_url.path,
                    query_string=parsed_url.query or None,
                    status_code=200,  # Placeholder (CSIC is request-only)

                    # --- MAPPING THE PAYLOAD ---
                    request_body=row.get("content"),  # This is the POST payload

                    response_bytes=None,
                    request_bytes=_safe_int(row.get("lenght")),  # Note: Keep 'lenght' typo if in CSV
                    user_agent=row.get("User-Agent"),
                    referrer=row.get("Referer"),
                    session_id=row.get("cookie"),
                    user_id=None,
                    log_source="csic_2010",
                    label=label_val
                )


def _safe_int(value):
    if not value:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None