import re
from datetime import datetime

DOVECOT_REGEX = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+(?:dovecot:\s+imap-login:|auth:\s+pam_unix\(dovecot:auth\):)\s+"
    r"(?P<action>[^;:]+|authentication failure).*?"
    r"(?:user=<(?P<user>[^>]*)>|ruser=(?P<ruser>\S+)).*?"
    r"(?:rip=(?P<ip>[\d\.]+)|rhost=(?P<rhost>[\d\.]+))"
)

POSTFIX_REGEX = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+postfix/smtpd\[\d+\]:\s+(?P<action>NOQUEUE: reject|connect|disconnect).*?"
    r"(?:from unknown\[(?P<ip>[\d\.]+)\])?.*?(?:(?P<reason>User unknown|Relay access denied))?"
)

# Thêm Mới: Bắt các log hệ thống bình thường (CRON, sshd) để AI làm Baseline
SYSTEM_REGEX = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+(?P<process>CRON\[\d+\]|sshd\[\d+\]|systemd.*?):\s+"
    r"(?P<action>.*)"
)

def parse_log_line(line):
    match = DOVECOT_REGEX.search(line)
    if match:
        data = match.groupdict()
        data['service'] = 'dovecot'
        data['user'] = data.get('user') or data.get('ruser') or 'unknown'
        data['ip'] = data.get('ip') or data.get('rhost') or 'unknown'
    else:
        match = POSTFIX_REGEX.search(line)
        if match:
            data = match.groupdict()
            data['service'] = 'postfix'
            data['user'] = 'unknown'
            data['ip'] = data.get('ip') or 'unknown'
        else:
            match = SYSTEM_REGEX.search(line)
            if match:
                data = match.groupdict()
                data['service'] = 'system'  # Khai báo đây là log hệ thống
                data['user'] = 'local_system'
                data['ip'] = '127.0.0.1'
            else:
                return None # Lúc này mới thực sự bỏ qua rác

    full_time_str = f"2024 {data['time']}"
    data['timestamp'] = datetime.strptime(full_time_str, "%Y %b %d %H:%M:%S")
    return data