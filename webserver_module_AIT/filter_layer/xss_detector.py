import re
import html
# Removed urllib.parse as UnifiedEngine handles URL decoding now to prevent Redundant CPU Overhead


class XSSDetector:
    """
    Tier 1 Deterministic Detector for Cross-Site Scripting (XSS).
    Uses HTML Entity normalization and structural
    regex to identify malicious script injections in URIs.
    """
    # REMOVED decode_threshold as decoding is centralized in Layer1UnifiedEngine
    __slots__ = ['name', 'patterns']

    def __init__(self):
        self.name = "XSS Detector"

        self.patterns = [
            # TIER 1: Structural Tags (OWASP-style)
            # Detects tags used to execute or embed external content
            re.compile(r'(?i)<(?:script|iframe|object|embed|applet|meta|link|style|base|form|svg|math|marquee).*?>'),

            # TIER 2: Event Handlers (PortSwigger Bypass Prevention)
            # Broadly catches HTML5 events: onerror, onload, onmouseover, etc.
            re.compile(r'(?i)\bon[a-z]{3,20}\s*='),

            # TIER 3: Pseudo-Protocols
            # Detects execution via URI schemes in attributes like src/href
            re.compile(r'(?i)(?:javascript|vbscript|data|mocha|livescript):'),

            # TIER 4: JS Execution Signatures
            # Catching core execution functions and Proof of Concept calls
            re.compile(r'(?i)(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function|atob)\s*[\(\`\s]'),

            # TIER 5: Fragment Breakout
            # Detects attempts to close existing attributes/tags to inject new ones
            re.compile(r'(?i)["\']\s*(?:>\s*<|/?>|onerror|onload)')
        ]

    def _normalize(self, payload):
        """
        Deep Normalization Pipeline:
        1. HTML Entity Decoding (e.g., &#x3c; -> <)
        2. Evasion noise removal (Null bytes and excessive whitespace)
        (Note: URL decoding is handled centrally by Layer1UnifiedEngine)
        """
        if not payload:
            return ""

        curr = str(payload)

        for depth in range(1, 4):
            prev = curr
            # Decode HTML entities
            curr = html.unescape(curr)

            # Strip null bytes and non-printable noise often used for evasion
            curr = re.sub(r'[\x00\s]+', '', curr)

            if prev == curr:
                break

        return curr.lower()

    # UPDATED: Renamed inspect_uri to inspect_payload to fix interface mismatch
    # REMOVED: uri_path and uri_query arguments, now accepts a single unified payload string
    def inspect_payload(self, payload):
        """
        Analyzes the centralized payload string for XSS indicators.
        Returns: Boolean (True if an attack is detected).
        """
        norm_payload = self._normalize(payload)

        # Unified scan across the payload
        for p in self.patterns:
            if p.search(norm_payload):
                return True

        return False