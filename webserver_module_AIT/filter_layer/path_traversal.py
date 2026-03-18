import re
# Removed urllib.parse as UnifiedEngine handles URL decoding now to prevent Redundant CPU Overhead


class PathTraversalDetector:
    """
    Tier 1 Deterministic Detector for Path Traversal and LFI.
    Employs structural pattern matching to identify directory escapes
    and unauthorized file access on pre-normalized payloads.
    """
    # REMOVED decode_threshold as decoding is centralized in Layer1UnifiedEngine
    __slots__ = ['name', 'patterns']

    def __init__(self):
        self.name = "Path Traversal Detector"

        self.patterns = [
            # 1. Structural Traversal: Catch relative climbs (../ or ..\)
            re.compile(r'(?i)(?:\.{2,}[/\\]+|[/\\]+\.{2,})'),

            # 2. System Roots: High-value Linux/Windows core directories
            re.compile(r'(?i)(?:/etc/|/proc/|/root/|/\.ssh/|boot\.ini|/windows/system32|/usr/local/bin)'),

            # 3. Application Stack: Common targets in web environments (XAMPP, WAMP, Apache)
            re.compile(r'(?i)(?:/xampp/|/wamp/|/apache2?/|/phpmyadmin/|/logs?/|config\.inc\.php|php\.ini|\.viminfo)'),

            # 4. Protocols & Wrappers: Used in advanced LFI to execute or exfiltrate data
            re.compile(r'(?i)(?:php://|file://|expect://|zip://|data://|phar://)')
        ]

    # REMOVED: _normalize method. URL decoding is handled by Layer1UnifiedEngine.
    # Specific evasion replacements are preserved and moved directly to inspect_payload.

    # UPDATED: Renamed inspect_uri to inspect_payload to fix interface mismatch
    # REMOVED: uri_path and uri_query arguments, now accepts a single unified payload string
    def inspect_payload(self, payload):
        """
        Primary entry point. Analyzes the centralized payload for malicious intent.
        Returns: Boolean (True if attack detected).
        """
        if not payload:
            return False

        curr = str(payload).lower()

        # Normalize common obfuscations found during benchmark failure analysis
        curr = curr.replace('%c0%ae', '.').replace('%c0%af', '/')
        curr = curr.replace('%25c1%259c', '/')
        curr = curr.replace('%uff0e', '.').replace('%u2216', '\\')

        # Deterministic Scan: Pattern matching against the compiled regex suite
        for p in self.patterns:
            if p.search(curr):
                return True

        # Structural Scan: Detect Null Byte injection (%00 or decoded \x00)
        if '%00' in curr or '\x00' in curr:
            return True

        return False