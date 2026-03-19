import re
import urllib.parse
import urllib.request
import html
import ssl
import time
import tracemalloc
import os


# ==========================================
# 1. OUR FINAL XSS DETECTOR (Hybrid Engine)
# ==========================================
class XSSDetector:
    """
    Tier 1 Deterministic Detector for Cross-Site Scripting (XSS).
    Uses HTML Entity normalization and structural
    regex to identify malicious script injections in URIs.
    """
    __slots__ = ['name', 'patterns']

    def __init__(self):
        self.name = "XSS Detector"

        self.patterns = [
            # TIER 1: Structural Tags (OWASP-style)
            re.compile(r'(?i)<(?:script|iframe|object|embed|applet|meta|link|style|base|form|svg|math|marquee).*?>'),

            # TIER 2: Event Handlers (PortSwigger Bypass Prevention)
            re.compile(r'(?i)\bon[a-z]{3,20}\s*='),

            # TIER 3: Pseudo-Protocols
            re.compile(r'(?i)(?:javascript|vbscript|data|mocha|livescript):'),

            # TIER 4: JS Execution Signatures
            re.compile(r'(?i)(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function|atob)\s*[\(\`\s]'),

            # TIER 5: Fragment Breakout
            re.compile(r'(?i)["\']\s*(?:>\s*<|/?>|onerror|onload)')
        ]

    def _normalize(self, payload):
        if not payload:
            return ""

        curr = str(payload)

        for depth in range(1, 4):
            prev = curr
            curr = html.unescape(curr)
            curr = re.sub(r'[\x00\s]+', '', curr)
            if prev == curr:
                break

        return curr.lower()

    def inspect_payload(self, payload):
        norm_payload = self._normalize(payload)
        for p in self.patterns:
            if p.search(norm_payload):
                return True
        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(<script|alert\(|onerror=)')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


# ==========================================
# 3. COMPETITOR 2: SIMULATED OWASP CRS
# ==========================================
class OwaspCrsWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        self.patterns = [
            re.compile(r'(?i)<script.*?>'),
            re.compile(r'(?i)javascript:'),
            re.compile(r'(?i)\bon[a-z]+\s*='),
            re.compile(r'(?i)<iframe.*?>')
        ]

    def inspect_payload(self, payload):
        text = str(payload)
        for p in self.patterns:
            if p.search(text): return True
        return False


# ==========================================
# THE BENCHMARKING SYSTEM
# ==========================================
def download_payloads():
    print("=== Initiating Mega-Benchmark Download (5000+ Vectors) ===")
    SEC_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/"
    N3_BASE = "https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/"
    PTT_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/"
    OFF_BASE = "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/"

    urls = [
        SEC_BASE + "XSS-Jhaddix.txt", SEC_BASE + "XSS-Bypass-Strings-BruteLogic.txt",
        SEC_BASE + "XSS-Cheat-Sheet-PortSwigger.txt", SEC_BASE + "XSS-BruteLogic.txt",
        SEC_BASE + "XSS-EnDe-evation.txt", SEC_BASE + "XSS-Fuzzing.txt",
        SEC_BASE + "XSS-OFJAAAH.txt", SEC_BASE + "XSS-RSNAKE.txt",
        SEC_BASE + "XSS-Somdev.txt", SEC_BASE + "XSS-Vectors-Mario.txt",
        SEC_BASE + "XSS-payloadbox.txt", SEC_BASE + "xss-without-parentheses-semi-colons-portswigger.txt",
        N3_BASE + "xss_payloads_quick.txt", N3_BASE + "xss_escape_chars.txt",
        N3_BASE + "xss_find_inject.txt", N3_BASE + "xss_funny_stored.txt",
        N3_BASE + "xss_grep.txt", N3_BASE + "xss_remote_payloads-http.txt",
        N3_BASE + "xss_remote_payloads-https.txt", N3_BASE + "xss_swf_fuzz.txt",
        PTT_BASE + "IntrudersXSS.txt", PTT_BASE + "JHADDIX_XSS.txt",
        OFF_BASE + "Cross-Site-Scripting-XSS-Payloads.txt"
    ]

    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, context=ctx, timeout=20)
            raw_data = response.read().decode('utf-8', errors='ignore')
            for line in raw_data.splitlines():
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    combined_payloads.add(clean_line)
        except Exception:
            pass

    print(f"\n[!] TOTAL UNIQUE PAYLOADS LOADED: {len(combined_payloads)}")
    return list(combined_payloads)


def run_performance_test(engine, payloads, output_dir="xss_benchmark_results"):
    if not os.path.exists(output_dir): os.makedirs(output_dir)

    total = len(payloads)
    detected_payloads = []
    missed_payloads = []

    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # Simulate UnifiedEngine decoding
        decoded_p = urllib.parse.unquote(p)
        if engine.inspect_payload(decoded_p):
            detected_payloads.append(p)
        else:
            missed_payloads.append(p)

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (len(detected_payloads) / total) * 100 if total > 0 else 0
    safe_name = engine.name.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    filename = os.path.join(output_dir, f"{safe_name}_results.txt")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(
            f"=== {engine.name} Benchmark Results ===\nTotal Payloads: {total}\nDetected:       {len(detected_payloads)} ({recall:.2f}%)\nMissed:         {len(missed_payloads)}\n")
        f.write("=" * 50 + "\n\n--- MISSED PAYLOADS ---\n")
        for mp in missed_payloads: f.write(f"{mp}\n")

    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    print("\n=== HARD MODE FALSE POSITIVE (FP) TESTING ===")
    url_benign = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url_benign, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            legitimate_traffic = [line.decode('utf-8', errors='ignore').strip() for line in response.readlines()][:5000]
    except Exception as e:
        print(f"[-] Lỗi tải Benign traffic: {e}. Dùng dữ liệu giả lập...")
        legitimate_traffic = ["user=admin", "id=123", "page=about", "search=hello"] * 1000

    print(f"[+] Đã tải {len(legitimate_traffic)} mẫu truy cập hợp lệ từ SecLists.")
    print(f"{'Engine Name':<30} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic:
            if engine.inspect_payload(lp): fps += 1
        fpr = (fps / len(legitimate_traffic)) * 100
        print(f"{engine.name:<30} | {fps:>2}/{len(legitimate_traffic):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = download_payloads()
    if not payloads: exit()

    print(f"[+] Loaded {len(payloads)} unique XSS payloads. Running analysis...\n")

    engines = [NaiveRegexWAF(), OwaspCrsWAF(), XSSDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 77)

    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)