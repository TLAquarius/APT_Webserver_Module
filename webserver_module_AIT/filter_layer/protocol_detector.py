import re


class ProtocolManipulationDetector:
    """
    Tier 1 Deterministic Detector for Protocol & Syntax Manipulations.
    Catches CRLF Injection (Response Splitting), Open Redirects,
    and Server-Side Template Injection (SSTI / Log4j).
    """
    __slots__ = ['name', 'patterns', '_prefilter']

    def __init__(self):
        self.name = "Protocol Manipulation Detector"

        self.patterns = [
            # 1. CRLF INJECTION (HTTP Response Splitting & Log Forging)
            # Looks for encoded newlines followed immediately by dangerous HTTP headers
            re.compile(r'(?i)(?:%0d|%0a|\r|\n).*?(?:set-cookie|location|content-|x-[a-z0-9_-]+)\s*:'),
            # Looks for double newlines (used to split the HTTP body and inject HTML)
            re.compile(r'(?:%0d|%0a|\r|\n){2,}'),

            # 2. OPEN REDIRECTS
            # Catches external schemes injected into common routing parameters.
            # (Note: In a real enterprise deployment, add your company domain to the negative lookahead)
            re.compile(
                r'(?i)(?:url|next|redirect|redirect_uri|return|return_to|goto|dest|destination)\s*=\s*(?:http://|https://|//)(?![a-zA-Z0-9.-]*\.(?:trusted-domain\.com))'),

            # 3. SSTI & EXPRESSION LANGUAGE (Log4Shell, Jinja, Twig, Spring)
            # Broad structural catch for template evaluation brackets
            re.compile(r'(?i)(?:\$\{.*?\}|\{\{.*?\}\}|<%.*?%>|\[%.*?%\])')
        ]

        # Fast-Fail Prefilter
        self._prefilter = ('%0d', '%0a', '\r', '\n', 'http', '//', '${', '{{', '<%', '[%')

    # UPDATED: Renamed inspect_uri to inspect_payload to fix interface mismatch
    # REMOVED: uri_path and uri_query arguments, now accepts a single unified payload string
    def inspect_payload(self, payload):
        """
        Analyzes the centralized payload for protocol anomalies.
        Returns: Boolean (True if an anomaly is detected).
        """
        if not payload:
            return False

        # Critical Fix: Lowercase the payload string so the prefilter catches %0D and HTTP://
        combined = str(payload).lower()

        # Fast-Fail Check
        if not any(x in combined for x in self._prefilter):
            return False

        # REMOVED: urllib.parse.unquote(combined) because decoding is handled centrally by Layer1UnifiedEngine
        for p in self.patterns:
            if p.search(combined):
                return True

        return False