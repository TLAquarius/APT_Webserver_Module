from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class WebLogEvent:
    event_time: datetime
    source_ip: str
    http_method: str
    request_path: str
    query_string: Optional[str]
    status_code: int

    request_body: Optional[str] = None

    response_bytes: Optional[int] = None
    request_bytes: Optional[int] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None

    log_source: str = "unknown"
    label: str = "unknown"