import re

class ScannerDetector:
    """
    Tier 1 Deterministic Detector for Malicious Bots and Vulnerability Scanners.
    Optimized strictly for Exploit Frameworks and Scripting Libraries,
    intentionally bypassing marketing/SEO scrapers to maintain a near-zero FP rate.
    """
    __slots__ = ['name', 'patterns', '_seo_allowlist']

    def __init__(self):
        self.name = "Scanner & Bot Detector"

        # 1. SEO & SOCIAL MEDIA ALLOWLIST (Fast-Fail)
        # Prevents blocking of legitimate search engine indexers and social link previews
        self._seo_allowlist = re.compile(
            r'(?i)(?:googlebot|bingbot|twitterbot|linkedinbot|duckduckbot|slurp|yandexbot)'
        )

        self.patterns = [
            # 2. KNOWN VULNERABILITY SCANNERS & EXPLOIT TOOLS
            # The loudest tools often found in reconnaissance datasets
            re.compile(r'(?i)(?:sqlmap|nikto|nmap|nuclei|nessus|acunetix|dirbuster|gobuster|wfuzz|masscan|zgrab|projectdiscovery|commix|wpscan|hydra|medusa|burp|ffuf|patator)'),
            # 3. GENERIC HTTP LIBRARIES & SCRIPTING TOOLS
            # Humans use browsers; automated exploit scripts use these raw network libraries.
            re.compile(r'(?i)(?:python-requests|go-http-client|curl/|wget/|urllib|\bruby\b|\bphp\b|httpclient|postman)'),

            # 4. EXPLOIT SIGNATURES IN HEADERS
            # Catching specific malware families or embedded injection attempts
            re.compile(r'(?i)(?:zmeu|morfeus|jndi:|log4j|hello-world|susie)')
        ]

    # UPDATED: Renamed inspect_ua to inspect_payload to conform to the standardized Layer 1 interface.
    def inspect_payload(self, payload):
        """
        Analyzes the User-Agent string (passed as payload).
        Returns: Boolean (True if a malicious scanner/bot is detected).
        """
        # 1. The "Empty UA" Anomaly
        if not payload or payload.strip() in ('', '-'):
            return True

        # 2. Legitimate Bot Allowlist Bypass
        if self._seo_allowlist.search(payload):
            return False

        # 3. Malicious Pattern Match
        for p in self.patterns:
            if p.search(payload):
                return True

        return False