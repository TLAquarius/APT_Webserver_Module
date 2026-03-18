import re


# Removed urllib.parse as UnifiedEngine handles URL decoding now to prevent Redundant CPU Overhead


class OSCommandInjectionDetector:
    """
    Tier 1 Deterministic Detector for OS Command Injection (RCE).
    Uses contextual correlation (Separators + Binaries) with Negative Lookaheads.
    Includes advanced signatures for direct Web Shell execution and Reverse Shells.
    """
    # ADDED stderr_patterns to __slots__ to handle error logs
    # REMOVED decode_threshold as decoding is now centralized in Layer1UnifiedEngine
    __slots__ = ['name', 'patterns', 'stderr_patterns', '_prefilter']

    def __init__(self):
        self.name = "OS Command Injection Detector"

        self.patterns = [
            # 1. UNIVERSAL CHAINING (With Negative Lookahead for FP reduction)
            re.compile(
                r'(?i)(?:[;&|\n\r]|`|\$\()[\s\+\$]*\b(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|gcc|hostname|sleep|ping|echo|base64|tail|head|grep|find|dir|ipconfig|powershell|cmd|tasklist|awk|sed|nslookup|dig)\b(?!\s*=)'),

            # 2. PATH & ENV INJECTION
            re.compile(r'(?i)(?:/[a-z0-9_-]+)*/(?:bin|sbin|etc|usr|var|tmp|windows|system32)/[a-z0-9_-]+'),

            # 3. BLIND & SUB-SHELL EXECUTION
            re.compile(r'(?i)(?:`[^`]{2,20}`|\$\([^)]+\))'),

            # 4. IO REDIRECTION & LOGICAL OPERATORS
            re.compile(r'(?i)(?:[0-9]?[><]{1,2}\s*[a-z0-9_\-\./]+|\|\||&&)'),

            # -----------------------------------------------------------------
            # NEW: WEBSHELL / STANDALONE COMMANDS (No Separator Required)
            # Detects high-severity commands executed directly via webshell inputs.
            # -----------------------------------------------------------------
            re.compile(
                r'(?i)\b(?:whoami|uname\s+-[ar]|cat\s+/(?:etc|proc|var)/[a-z0-9_-]+|netstat\s+-[a-z]+|id|ifconfig|ip\s+addr)\b(?!\s*=)'),
            # -----------------------------------------------------------------
            # NEW: REVERSE TCP/UDP SHELLS
            # Catches the exact syntax used to bind a shell back to the attacker.
            # -----------------------------------------------------------------
            re.compile(r'(?i)(?:/dev/tcp/[0-9\.]+|/dev/udp/[0-9\.]+|nc\s+-e|bash\s+-i|bash\s+-c)')
        ]

        # NEW: Error log execution output signatures (stderr outputs)
        self.stderr_patterns = [
            re.compile(r'(?i)(?:TERM environment variable not set|No LSB modules are available)'),
            re.compile(r'(?i)(?:Resolving github\.com|Connecting to.*?\|:443\.\.\. connected)'),  # wget/curl outputs
            re.compile(r'(?i)(?:command not found|sh: 1:|bash: line 1:)'),  # Failed execution
            re.compile(r'(?i)(?:uid=\d+\(.*\) gid=\d+\(.*\) groups=\d+\(.*\))')  # 'id' command output
        ]

        # CRITICAL UPDATE: Added standalone command triggers so the prefilter doesn't
        # accidentally drop web shell payloads decoded by the Unified Engine!
        self._prefilter = (
            ';', '&', '|', '`', '$', '>', '<', '/', '%', '\n',
            'whoami', 'uname', 'cat ', 'netstat', 'id', 'ifconfig', 'ip ', 'nc ', 'bash'
        )

    # UPDATED: Renamed inspect_uri to inspect_payload to fix interface mismatch
    # REMOVED: uri_path and uri_query arguments, now accepts a single unified payload string
    def inspect_payload(self, payload):
        """
        Analyzes the centralized, pre-decoded payload string for RCE payloads.
        Returns: Boolean (True if an attack is detected).
        """
        if not payload:
            return False

        payload_lower = payload.lower()
        if not any(x in payload_lower for x in self._prefilter):
            return False

        # Apply OS-specific evasion normalizations (URL decoding is already handled by UnifiedEngine)
        if '${ifs}' in payload_lower or '$ifs$9' in payload_lower:
            payload_lower = re.sub(r'(?i)\$\{ifs\}|\$ifs\$9', ' ', payload_lower)

        payload_lower = payload_lower.replace('\x00', '')

        for p in self.patterns:
            if p.search(payload_lower):
                return True

        return False

    # NEW: Specific method for handling raw error/stderr logs
    def inspect_error(self, raw_message):
        """Specifically scans raw Apache Error logs / stderr dumps for execution artifacts."""
        if not raw_message:
            return False

        # Fast-fail for common normal Apache errors to save CPU
        if "AH00163:" in raw_message or "AH00094:" in raw_message:
            return False

        for p in self.stderr_patterns:
            if p.search(raw_message):
                return True
        return False