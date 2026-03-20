class OWASPMapper:
    """
    Maps a feature dict (from FeatureExtractor) to an OWASP Top 10 2021 category
    and a corresponding APT kill chain phase.

    Improvements over original:
    - Distinguishes SQL Injection, XSS, Command Injection, and Null Byte as
      separate attack types instead of collapsing everything into "A03:2021".
    - Adds Buffer Overflow, Encoding Attack, and Path Traversal categories.
    - Never returns "Unknown" — falls back to "A09:2021 - Anomalous Request"
      so every flagged record has a meaningful label for your report.
    - Maps each OWASP category to an APT kill chain phase to connect HTTP-layer
      detections to your thesis's APT timeline model.
    """

    # Maps (owasp_code, description) → apt_phase
    APT_PHASE_MAP = {
        "A03:2021 - SQL Injection":         "collection",           # data exfiltration via DB
        "A03:2021 - XSS":                   "initial_access",       # client-side payload delivery
        "A03:2021 - Command Injection":     "execution",            # remote code execution
        "A03:2021 - Null Byte Injection":   "execution",            # file system manipulation
        "A01:2021 - Path Traversal":        "privilege_escalation", # accessing restricted files
        "A07:2021 - Encoding Attack":       "defense_evasion",      # bypassing WAF/IDS
        "A05:2021 - Buffer Overflow":       "execution",            # memory corruption
        "A09:2021 - Anomalous Request":     "reconnaissance",       # scanning / probing
    }

    def map(self, feature: dict) -> dict:
        """
        Parameters
        ----------
        feature : dict from FeatureExtractor.extract()

        Returns
        -------
        {
            "owasp":     str,   e.g. "A03:2021 - SQL Injection"
            "apt_phase": str,   e.g. "collection"
            "confidence": float  0.0–1.0 rough confidence based on signal strength
        }
        """
        category, confidence = self._classify(feature)
        apt_phase = self.APT_PHASE_MAP.get(category, "reconnaissance")

        return {
            "owasp":      category,
            "apt_phase":  apt_phase,
            "confidence": confidence,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _classify(self, f: dict) -> tuple[str, float]:
        """
        Priority-ordered classification.
        Returns (category_string, confidence_score).
        Confidence is estimated from signal strength, not a true probability.
        """

        # 1. Command Injection — highest risk, check first
        if f.get("has_cmd_injection"):
            conf = min(1.0, 0.7 + f.get("special_char_count", 0) * 0.03)
            return "A03:2021 - Command Injection", round(conf, 2)

        # 2. Null Byte Injection
        if f.get("has_null_byte"):
            return "A03:2021 - Null Byte Injection", 0.90

        # 3. SQL Injection — strong signal
        if f.get("has_sql_keyword"):
            # More special chars = higher confidence (e.g. ' OR '1'='1)
            conf = min(1.0, 0.65 + f.get("special_char_count", 0) * 0.05)
            return "A03:2021 - SQL Injection", round(conf, 2)

        # 4. XSS
        if f.get("has_xss"):
            conf = min(1.0, 0.70 + f.get("encoded_char_count", 0) * 0.02)
            return "A03:2021 - XSS", round(conf, 2)

        # 5. Path Traversal
        if f.get("has_traversal"):
            return "A01:2021 - Path Traversal", 0.85

        # 6. Double / heavy encoding — likely evasion attempt
        if f.get("has_double_encoding") or f.get("encoded_char_count", 0) > 20:
            conf = min(1.0, 0.5 + f.get("encoded_char_count", 0) * 0.01)
            return "A07:2021 - Encoding Attack", round(conf, 2)

        # 7. Very long parameter value — buffer overflow probe
        if f.get("has_long_param_value") or f.get("body_length", 0) > 8_000:
            return "A05:2021 - Buffer Overflow", 0.75

        # 8. Fallback — anomalous but no specific pattern matched
        return "A09:2021 - Anomalous Request", 0.40
