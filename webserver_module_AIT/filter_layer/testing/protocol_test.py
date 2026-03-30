import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os


# ==========================================
# 1. OUR FINAL PROTOCOL DETECTOR
# ==========================================
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


# ==========================================
# 2. COMPETITORS
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(%0d%0a|http://|https://|\$\{)')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


class OwaspCrsWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        self.patterns = [
            re.compile(r'(?i)(?:\r\n|\n|\r|%0d|%0a)'),  # Bắt mọi ký tự ngắt dòng
            re.compile(r'(?i)(?:http://|https://)'),  # Bắt mọi link
            re.compile(r'(?i)(?:\$\{.*\})')  # Bắt eval bracket
        ]

    def inspect_payload(self, payload):
        text = str(payload)
        for p in self.patterns:
            if p.search(text): return True
        return False


# ==========================================
# BENCHMARK RUNNERS
# ==========================================
def download_payloads():
    print("=== Downloading Protocol Manipulation Benchmarks ===")
    urls = [
        # Open Redirect
        "https://raw.githubusercontent.com/payloadbox/open-redirect-payloads/master/open-redirect-payloads.txt",
        # SSTI
        "https://raw.githubusercontent.com/payloadbox/ssti-payloads/master/Intruder/ssti-payloads.txt",
        # CRLF
        "https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/crlf.txt"
    ]

    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            raw_data = urllib.request.urlopen(req, context=ctx, timeout=15).read().decode('utf-8', errors='ignore')
            for line in raw_data.splitlines():
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    combined_payloads.add(clean_line)
        except Exception:
            pass
    return list(combined_payloads)


def run_performance_test(engine, payloads):
    total, detected = len(payloads), 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # Simulate UnifiedEngine decoding
        decoded_p = urllib.parse.unquote(p)
        if engine.inspect_payload(decoded_p): detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {"name": engine.name, "recall": (detected / total) * 100 if total > 0 else 0, "time": end_time - start_time,
            "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    print("\n=== HARD MODE FALSE POSITIVE (FP) TESTING ===")

    # Những request hoàn toàn bình thường nhưng rất dễ bị bắt nhầm
    legitimate_traffic_hard = [
        "comment=Hello \n world \n this is nice",  # Có xuống dòng bình thường
        "text=I paid $100 for this",  # Có dấu $
        "blog=https://trusted-domain.com/article?id=1",  # URL bình thường không nằm trong biến chuyển hướng
        "url=https://trusted-domain.com",  # URL chuyển hướng an toàn (trusted-domain)
        "data={user: 1, type: 'normal'}"  # Có ngoặc nhọn
    ]

    url_benign = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url_benign, headers={'User-Agent': 'Mozilla/5.0'})
        legitimate_traffic_hard += [line.decode('utf-8', errors='ignore').strip() for line in
                                    urllib.request.urlopen(req, context=ctx, timeout=15).readlines()][:5000]
    except Exception as e:
        print(f"[-] Lỗi tải Benign traffic: {e}.")

    print(f"[+] Đã tải {len(legitimate_traffic_hard)} mẫu truy cập hợp lệ.")
    print(f"{'Engine Name':<35} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = sum(1 for lp in legitimate_traffic_hard if engine.inspect_payload(f"q={lp}"))
        print(
            f"{engine.name:<35} | {fps:>2}/{len(legitimate_traffic_hard):<7} | {(fps / len(legitimate_traffic_hard)) * 100:>8.2f}%")


if __name__ == "__main__":
    payloads = download_payloads()
    if not payloads: exit()

    print(f"\n[+] Loaded {len(payloads)} unique Protocol Manipulation payloads. Running analysis...\n")
    engines = [NaiveRegexWAF(), OwaspCrsWAF(), ProtocolManipulationDetector()]

    results = [run_performance_test(engine, payloads) for engine in engines]

    print(f"{'Engine Name':<35} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 80)
    for r in sorted(results, key=lambda x: x['recall'], reverse=True):
        print(f"{r['name']:<35} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)