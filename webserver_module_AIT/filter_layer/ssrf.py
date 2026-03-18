import re

class SSRFDetector:
    """
    Tier 1 Deterministic Detector for Server-Side Request Forgery (SSRF).
    Targets high-confidence Indicators of Compromise (IoCs) including
    Cloud Metadata IP theft, Protocol Smuggling, and Obfuscated Loopbacks.
    """
    # REMOVED decode_threshold as decoding is centralized in Layer1UnifiedEngine
    __slots__ = ['name', 'patterns', '_prefilter']

    def __init__(self):
        self.name = "SSRF Detector"

        self.patterns = [
            # 1. CLOUD METADATA THEFT (AWS, GCP, Azure, Alibaba)
            re.compile(
                r'(?i)\b(?:169\.254\.169\.254|169\.254\.169\.253|metadata\.google\.internal|100\.100\.100\.200)\b'),

            # 2. METADATA ENDPOINTS & HEADERS
            # Catching the specific paths or injected headers used to bypass basic IP blocks
            re.compile(r'(?i)(?:latest/meta-data|metadata-flavor:\s*google|x-aws-ec2-metadata-token)'),

            # 3. DANGEROUS SCHEMES (Protocol Smuggling)
            # Legitimate applications use HTTP/HTTPS. These protocols indicate RCE or LFI escalation.
            re.compile(r'(?i)(?:gopher|dict|file|ldap|sftp|tftp|ws|wss)://'),

            # 4. LOCALHOST & OBFUSCATED LOOPBACKS
            # Catches: 127.0.0.1, 127.1, 0x7f000001 (Hex), 2130706433 (Dec), 0177.0.0.1 (Oct), [::1], 0.0.0.0
            re.compile(
                r'(?i)\b(?:localhost|127\.(?:0\.)*[0-1]|2130706433|0x7f000001|0177\.(?:0\.)*1|\[?::1\]?|0\.0\.0\.0)\b')
        ]

        # Fast-Fail Prefilter: Trigger strings to avoid running regex on clean URLs
        self._prefilter = (
            ':', '169.', '127.', 'localhost', '0x', '::1', 'file',
            'dict', 'gopher', 'meta', '2130706433', '0.0.0.0', '100.'
        )

    def inspect_payload(self, payload):
        """
        Primary scanning function on the centralized payload.
        Returns: Boolean (True if an SSRF pattern is detected).
        """
        if not payload:
            return False

        # FIX: Lowercase the payload BEFORE the prefilter check to prevent case-sensitivity evasion
        payload_lower = str(payload).lower()

        if not any(x in payload_lower for x in self._prefilter):
            return False

        # Apply specific evasion normalization (strip null bytes)
        payload_clean = payload_lower.replace('\x00', '')

        for p in self.patterns:
            if p.search(payload_clean):
                return True

        return False