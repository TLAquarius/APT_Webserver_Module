import re
from urllib.parse import urlparse, parse_qs, unquote_plus
from typing import Optional


class CSICParser:
    """
    Robust HTTP request parser designed for the CSIC 2010 dataset.

    FIXED from original:
    - Returns 'body_raw' (not 'body') to match feature_extractor expectations
    - Returns 'path', 'query_string', 'query_params', 'body_params',
      'content_type', 'is_malformed' — all required by feature_extractor
    - Handles CRLF + LF line endings
    - Handles malformed request lines gracefully (no crash)
    - Handles duplicate headers (list values)
    - Decodes URL-encoded and double-encoded payloads
    - Supports multipart/form-data body parsing
    """

    def parse_request(self, raw_request: str) -> dict:
        # Normalise line endings
        raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")

        # Split head and body on first blank line
        if "\n\n" in raw_request:
            head_part, body_raw = raw_request.split("\n\n", 1)
        else:
            head_part = raw_request
            body_raw = ""

        head_lines = head_part.split("\n")

        # Parse request line
        method, url, protocol, is_malformed = self._parse_request_line(head_lines[0])

        # Parse headers
        headers = self._parse_headers(head_lines[1:])

        # Derived fields
        content_type = self._get_header(headers, "content-type", "")
        path, query_string = self._split_url(url)
        query_params = self._decode_query(query_string)
        body_params  = self._parse_body(body_raw, content_type)

        return {
            "method":       method,
            "url":          url,
            "path":         path,
            "protocol":     protocol,
            "query_string": query_string,
            "query_params": query_params,
            "headers":      headers,
            "body_raw":     body_raw,        # ← was "body" in original — fixed
            "body_params":  body_params,
            "content_type": content_type,
            "is_malformed": is_malformed,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _parse_request_line(self, line: str) -> tuple:
        line  = line.strip()
        parts = line.split()
        if len(parts) >= 3:
            return parts[0].upper(), " ".join(parts[1:-1]), parts[-1], False
        if len(parts) == 2:
            return parts[0].upper(), parts[1], "HTTP/1.0", True
        if len(parts) == 1:
            return parts[0].upper(), "", "HTTP/1.0", True
        return "UNKNOWN", line, "HTTP/1.0", True

    def _parse_headers(self, lines: list) -> dict:
        headers: dict = {}
        current_key: Optional[str] = None
        for line in lines:
            if not line:
                break
            if line[0] in (" ", "\t") and current_key:
                headers[current_key][-1] += " " + line.strip()
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                current_key = key.strip().lower()
                headers.setdefault(current_key, []).append(value.strip())
        return headers

    def _get_header(self, headers: dict, key: str, default: str = "") -> str:
        values = headers.get(key.lower(), [])
        return values[0] if values else default

    def _split_url(self, url: str) -> tuple:
        try:
            parsed = urlparse(url)
            return parsed.path or url, parsed.query or ""
        except Exception:
            if "?" in url:
                path, _, qs = url.partition("?")
                return path, qs
            return url, ""

    def _decode_query(self, query_string: str) -> dict:
        if not query_string:
            return {}
        try:
            params = parse_qs(query_string, keep_blank_values=True)
            decoded = {}
            for k, vals in params.items():
                decoded[k] = [unquote_plus(v) for v in vals]
            return decoded
        except Exception:
            return {}

    def _parse_body(self, body_raw: str, content_type: str) -> dict:
        if not body_raw.strip():
            return {}
        ct = content_type.lower()
        if "application/x-www-form-urlencoded" in ct:
            return self._decode_query(body_raw.strip())
        if "multipart/form-data" in ct:
            boundary = self._extract_boundary(content_type)
            return self._parse_multipart(body_raw, boundary)
        return {"_raw": body_raw}

    def _extract_boundary(self, content_type: str) -> str:
        match = re.search(r'boundary=([^\s;]+)', content_type, re.I)
        return match.group(1).strip('"') if match else ""

    def _parse_multipart(self, body: str, boundary: str) -> dict:
        if not boundary:
            return {"_raw": body, "boundary": ""}
        delimiter = "--" + boundary
        parts_raw = body.split(delimiter)
        parts = []
        for part in parts_raw:
            part = part.strip()
            if not part or part == "--":
                continue
            if "\n\n" in part:
                part_head, part_body = part.split("\n\n", 1)
            else:
                part_head, part_body = part, ""
            part_headers = self._parse_headers(part_head.split("\n"))
            parts.append({
                "headers": part_headers,
                "content": part_body.rstrip("-").strip(),
            })
        return {"boundary": boundary, "parts": parts}
