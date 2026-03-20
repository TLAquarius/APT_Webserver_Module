import re
import math
from urllib.parse import unquote_plus


# ── Fixed column order ────────────────────────────────────────────────────────
# IMPORTANT: this list is the single source of truth for feature column order.
# preprocessing.py and pipeline.py both import this so the matrix never gets
# column-shifted when a key is missing from a feature dict.
FEATURE_COLS = [
    # ── Group 1: Method (2) ───────────────────────────────────────────────────
    "method_get",
    "method_post",

    # ── Group 2: Size & Volume (5) ────────────────────────────────────────────
    "url_length",
    "body_length",
    "num_headers",
    "num_params",
    "body_to_url_ratio",

    # ── Group 3: Injection Patterns — presence (5) ───────────────────────────
    "has_sql_keyword",
    "has_xss",
    "has_cmd_injection",
    "has_traversal",
    "has_null_byte",

    # ── Group 4: Injection Patterns — frequency (3) ──────────────────────────
    "sql_keyword_count",
    "xss_tag_count",
    "special_char_density",

    # ── Group 5: Encoding Signals (3) ────────────────────────────────────────
    "encoded_char_count",
    "has_double_encoding",
    "content_type_form",

    # ── Group 6: Entropy & Randomness (3) ────────────────────────────────────
    "payload_entropy",
    "param_name_entropy",
    "has_repeated_chars",

    # ── Group 7: Parameter-Level (5) ─────────────────────────────────────────
    "max_param_length",
    "avg_param_length",
    "num_numeric_params",
    "has_long_param_value",
    "has_email_in_param",

    # ── Group 8: Path & Structure (5) ────────────────────────────────────────
    "path_depth",
    "has_file_extension",
    "extension_is_exec",
    "has_ip_in_url",
    "is_common_path",

    # ── Group 9: Character Signals (3) ───────────────────────────────────────
    "special_char_count",
    "digit_ratio",
    "is_malformed",
]

# Total: 34 features


# ── Known legitimate CSIC 2010 paths ─────────────────────────────────────────
COMMON_PATHS = {
    "/tienda1/",
    "/tienda1/publico/",
    "/tienda1/publico/anadir.jsp",
    "/tienda1/publico/autenticar.jsp",
    "/tienda1/publico/caracteristicas.jsp",
    "/tienda1/publico/entrar.jsp",
    "/tienda1/publico/formularioaut.jsp",
    "/tienda1/publico/pagar.jsp",
    "/tienda1/publico/vaciar.jsp",
    "/tienda1/publico/ver.jsp",
}

# Executable / dangerous file extensions
EXEC_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".sh", ".bash", ".exe", ".bat", ".cmd",
    ".pl", ".py", ".rb", ".war", ".jar",
}


class FeatureExtractor:
    """
    Extracts a fixed-width numerical feature vector from a parsed HTTP request.

    Input  : dict returned by CSICParser.parse_request()
    Output : dict with keys == FEATURE_COLS (all int or float, 34 total)

    Feature groups:
        1. Method            (2)  - GET / POST flags
        2. Size & Volume     (5)  - lengths, counts, ratios
        3. Injection presence(5)  - binary attack pattern flags
        4. Injection freq    (3)  - how many times patterns appear
        5. Encoding          (3)  - percent-encoding signals
        6. Entropy           (3)  - randomness / obfuscation signals
        7. Parameter-level   (5)  - individual param characteristics
        8. Path & Structure  (5)  - URL path characteristics
        9. Character signals (3)  - character-level statistics
    """

    # ── Compiled patterns ─────────────────────────────────────────────────────

    SQL_PATTERN = re.compile(
        r"(select\b|union\b|drop\b|insert\b|update\b|delete\b"
        r"|from\b|where\b|or\s+1\s*=\s*1|'--|\bexec\b|\bxp_"
        r"|\bcast\b|\bconvert\b|\bchar\b|\bdeclare\b)",
        re.I,
    )

    XSS_PATTERN = re.compile(
        r"(<\s*script|<\s*img|<\s*svg|<\s*body|<\s*iframe"
        r"|javascript\s*:|vbscript\s*:|on\w+\s*="
        r"|%3Cscript|%3Cimg|alert\s*\(|document\.cookie"
        r"|<\s*input|<\s*form|<\s*a\s)",
        re.I,
    )

    CMD_PATTERN = re.compile(
        r"(;|\||`|\$\(|&&|\|\||\bexec\b|\bsystem\b|\bpasswd\b"
        r"|\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b|\bchmod\b|\brm\b)",
        re.I,
    )

    TRAVERSAL_PATTERN = re.compile(
        r"(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|%2e%2e%2f)",
        re.I,
    )

    NULL_BYTE_PATTERN   = re.compile(r"(%00|\x00|\\x00|\\0)", re.I)
    EMAIL_PATTERN       = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    IP_PATTERN          = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    REPEATED_CHARS_PATTERN = re.compile(r"(.)\1{8,}")
    EXTENSION_PATTERN   = re.compile(r"\.([a-zA-Z0-9]{2,5})(?:\?|$|/)")

    # ── Public API ────────────────────────────────────────────────────────────

    def extract(self, parsed: dict) -> dict:
        url     = parsed.get("url", "") or ""
        body    = parsed.get("body_raw", "") or ""
        headers = parsed.get("headers", {}) or {}
        ct      = parsed.get("content_type", "") or ""
        qparams = parsed.get("query_params", {}) or {}
        bparams = parsed.get("body_params", {}) or {}
        path    = parsed.get("path", "") or ""

        payload = url + body

        try:
            decoded_payload = unquote_plus(payload)
        except Exception:
            decoded_payload = payload

        all_param_values = [
            v for vals in list(qparams.values()) + list(bparams.values())
            for v in vals
        ]
        all_param_names = list(qparams.keys()) + list(bparams.keys())

        url_len  = len(url)
        body_len = len(body)

        sql_matches   = self.SQL_PATTERN.findall(decoded_payload)
        xss_matches   = self.XSS_PATTERN.findall(decoded_payload)
        special_chars = re.findall(r"[\'\"<>;(){}\\]", decoded_payload)
        max_param_len = max((len(v) for v in all_param_values), default=0)
        avg_param_len = (
            round(sum(len(v) for v in all_param_values) / len(all_param_values), 2)
            if all_param_values else 0
        )
        ext_match = self.EXTENSION_PATTERN.search(path)
        extension = f".{ext_match.group(1).lower()}" if ext_match else ""

        features = {
            # Group 1: Method
            "method_get":            int(parsed.get("method") == "GET"),
            "method_post":           int(parsed.get("method") == "POST"),

            # Group 2: Size & Volume
            "url_length":            url_len,
            "body_length":           body_len,
            "num_headers":           len(headers),
            "num_params":            len(qparams) + len(bparams),
            "body_to_url_ratio":     round(body_len / max(url_len, 1), 4),

            # Group 3: Injection presence
            "has_sql_keyword":       int(bool(sql_matches)),
            "has_xss":               int(bool(xss_matches)),
            "has_cmd_injection":     int(bool(self.CMD_PATTERN.search(decoded_payload))),
            "has_traversal":         int(bool(self.TRAVERSAL_PATTERN.search(decoded_payload))),
            "has_null_byte":         int(bool(self.NULL_BYTE_PATTERN.search(payload))),

            # Group 4: Injection frequency
            "sql_keyword_count":     len(sql_matches),
            "xss_tag_count":         len(xss_matches),
            "special_char_density":  round(
                len(special_chars) / max(len(decoded_payload), 1) * 100, 4
            ),

            # Group 5: Encoding
            "encoded_char_count":    payload.count("%"),
            "has_double_encoding":   int("%25" in payload),
            "content_type_form":     int("urlencoded" in ct.lower()),

            # Group 6: Entropy & Randomness
            "payload_entropy":       self._entropy(decoded_payload),
            "param_name_entropy":    self._entropy(" ".join(all_param_names)),
            "has_repeated_chars":    int(bool(self.REPEATED_CHARS_PATTERN.search(decoded_payload))),

            # Group 7: Parameter-level
            "max_param_length":      max_param_len,
            "avg_param_length":      avg_param_len,
            "num_numeric_params":    sum(1 for v in all_param_values if v.isdigit()),
            "has_long_param_value":  int(max_param_len > 512),
            "has_email_in_param":    int(any(self.EMAIL_PATTERN.search(v) for v in all_param_values)),

            # Group 8: Path & Structure
            "path_depth":            path.count("/"),
            "has_file_extension":    int(bool(extension)),
            "extension_is_exec":     int(extension in EXEC_EXTENSIONS),
            "has_ip_in_url":         int(bool(self.IP_PATTERN.search(url))),
            "is_common_path":        int(path in COMMON_PATHS),

            # Group 9: Character signals
            "special_char_count":    len(special_chars),
            "digit_ratio":           round(
                sum(c.isdigit() for c in decoded_payload) / max(len(decoded_payload), 1), 4
            ),
            "is_malformed":          int(parsed.get("is_malformed", False)),
        }

        for col in FEATURE_COLS:
            features.setdefault(col, 0)

        return features

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _entropy(self, s: str) -> float:
        """
        Shannon entropy — measures randomness / obfuscation level.

        Range  : 0.0 (all same char) → ~4.7 (perfectly random ASCII)
        Normal : "2" or "Jamon"             → entropy ~0.5 to 2.0
        Attack : "%27OR%271%27%3D%271"      → entropy ~3.5 to 4.5
        """
        if not s:
            return 0.0
        length = len(s)
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return round(
            -sum((count / length) * math.log2(count / length)
                 for count in freq.values()),
            4,
        )