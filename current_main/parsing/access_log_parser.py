import re
from datetime import datetime
from typing import Iterable
from urllib.parse import urlparse

from .base_parser import BaseLogParser
from .schema import WebLogEvent

# Regex designed for Zaker/Standard Apache format
# Example: 54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] "GET /url HTTP/1.1" 200 123 ...
APACHE_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d{3}|-) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<agent>[^"]*)"'
)


class ApacheAccessParser(BaseLogParser):

    def parse(self, filepath: str) -> Iterable[WebLogEvent]:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = APACHE_REGEX.match(line)
                if not match:
                    continue

                data = match.groupdict()
                parsed_url = urlparse(data["url"])

                # Handle "-" for empty bytes/status
                r_bytes = data["bytes"]
                r_bytes_int = int(r_bytes) if r_bytes.isdigit() else None

                status_code = int(data["status"]) if data["status"].isdigit() else 0

                yield WebLogEvent(
                    event_time=datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z"),
                    source_ip=data["ip"],
                    http_method=data["method"],
                    request_path=parsed_url.path,
                    query_string=parsed_url.query or None,
                    status_code=status_code,

                    # --- HANDLING MISSING DATA ---
                    request_body=None,  # Apache access logs do not have the body

                    response_bytes=r_bytes_int,
                    request_bytes=None,
                    user_agent=data["agent"] if data["agent"] != "-" else None,
                    referrer=data["referrer"] if data["referrer"] != "-" else None,
                    session_id=None,
                    user_id=None,
                    log_source="zaker_2019",
                    label="unknown"  # Real logs are unlabeled
                )