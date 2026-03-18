import re
# Removed urllib.parse as UnifiedEngine handles URL decoding now to prevent Redundant CPU Overhead


class SQLiDetector:
    """
    Deterministic SQL Injection Detection Engine.
    Engineered for high-throughput web server log analysis.
    Utilizes a Hybrid Architecture: Payload Normalization -> Heuristic Dictionaries -> Structural Regex.
    """

    # __slots__ prevents Python from creating dynamic dictionaries, saving RAM per log line
    __slots__ = ['name', 'dangerous_functions', 'command_chains', 'tautology_patterns', 'owasp_patterns']

    def __init__(self):
        self.name = "Hybrid Normalized-CRS WAF"

        # 1. Dictionary (Substring matching is O(1)/O(N) - Fastest check)
        self.dangerous_functions = [
            'information_schema', '@@version', 'version()',
            'system_user', 'database()', 'user()',
            'pg_sleep', 'waitfor delay', 'benchmark(',
            'load_file(', 'into outfile', 'into dumpfile',
            'sleep(', 'extractvalue(', 'updatexml(', 'group_concat(',
            'xp_cmdshell', 'exec(', 'randomblob(', 'substring('
        ]

        # 2. Command Chains (Pre-compiled for speed)
        chains = [
            r'union\s+select', r'union\s+all\s+select', r'insert\s+into',
            r'drop\s+table', r'delete\s+from', r'update\s+.+?\s+set',
            r'order\s+by', r'group\s+by', r'having\s+\d+'
        ]
        self.command_chains = [re.compile(c, re.IGNORECASE) for c in chains]

        # 3. Tautology logic (Pre-compiled)
        tautologies = [
            r'(\d+)\s*=\s*\1',
            r'([\'"])(.*?)\1\s*=\s*\1\2\1',
            r'(?i)\bor\s+true\b',
            r'(?i)\bor\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?',
            r'(?i)\bor\s+[\'"]?x[\'"]?\s*=\s*[\'"]?x[\'"]?',
            r'(?i)\bor\s+[\'"]?a[\'"]?\s*=\s*[\'"]?a[\'"]?',
            r'(?i)\blike\s+[\'"]%?[\'"]?',
            r'[\'"]\s*(?:#|--|/\*)',
            r'\)\s*or\s*\('
        ]
        self.tautology_patterns = [re.compile(t) for t in tautologies]

        # 4. OWASP Core Rule Set Structural Patterns (Heavy Regex - Evaluated last)
        self.owasp_patterns = [
            re.compile(
                r'(?i)(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*?\b(?:from|into|table|where|set)\b)'),
            re.compile(r'(?i)\b(?:and|or)\b\s+(?:\d+|[\'"]\w+[\'"])\s*[=<>]\s*(?:\d+|[\'"]\w+[\'"])')
        ]

    def _normalize(self, payload):
        """
        Defeats WAF evasion techniques by stripping obfuscation before rule evaluation.
        (Note: URL decoding is handled centrally by Layer1UnifiedEngine. This only handles SQL semantics).
        """
        if not payload:
            return ""

        normalized = str(payload).lower()
        # 1. Extract logic hidden inside MySQL conditional comments
        normalized = re.sub(r'/\*!\d+(.*?)\*/', r' \1 ', normalized)
        # 2. Remove standard inline SQL comments used to break signatures
        normalized = re.sub(r'/\*.*?\*/', ' ', normalized)
        # 3. Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        return normalized.strip()

    # UPDATED: Renamed inspect_uri to inspect_payload to fix interface mismatch
    # REMOVED: uri_query argument, now accepts a single unified payload string
    def inspect_payload(self, payload):
        """
        Analyzes a centralized payload string for SQL Injection payloads.
        Returns: True if SQLi is detected, False otherwise.
        """
        if not payload or str(payload) == 'nan':
            return False

        # Run SQL-specific Normalization Pipeline
        normalized_payload = self._normalize(payload)

        # --- Tiered Inspection Pipeline ---
        # Tier 1: Substring Dictionary
        for func in self.dangerous_functions:
            if func in normalized_payload:
                return True

        # Tier 2: Structural Chains
        for pattern in self.command_chains:
            if pattern.search(normalized_payload):
                return True

        # Tier 3: Tautologies
        for pattern in self.tautology_patterns:
            if pattern.search(normalized_payload):
                return True

        # Tier 4: OWASP Syntax
        for pattern in self.owasp_patterns:
            if pattern.search(normalized_payload):
                return True

        return False