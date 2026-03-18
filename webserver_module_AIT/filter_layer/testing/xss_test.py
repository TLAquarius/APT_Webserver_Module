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
    __slots__ = ['name', 'patterns', 'decode_threshold']

    def __init__(self, decode_threshold=3):
        self.name = "XSS Detector"
        self.decode_threshold = decode_threshold

        self.patterns = [
            # TIER 1: Structural Tags (OWASP-style)
            re.compile(r'(?i)<(?:script|iframe|object|embed|applet|meta|link|style|base|form|svg|math|marquee).*?>'),

            # TIER 2: Event Handlers (PortSwigger Bypass Prevention)
            # Catches standard and rare HTML5 events: onerror, onbeforetoggle, etc.
            re.compile(r'(?i)\bon[a-z]{3,20}\s*='),

            # TIER 3: Pseudo-Protocols
            re.compile(r'(?i)(?:javascript|vbscript|data|mocha|livescript):'),

            # TIER 4: JS Execution Signatures
            re.compile(r'(?i)(?:alert|confirm|prompt|eval|setTimeout|setInterval|Function|atob)\s*[\(\`\s]'),

            # TIER 5: Fragment Breakout (Structural manipulation)
            re.compile(r'(?i)["\']\s*(?:>\s*<|/?>|onerror|onload)')
        ]

    def _normalize(self, payload):
        if not payload: return "", 0
        curr = str(payload)
        max_depth = 0

        for depth in range(1, 6):
            prev = curr
            curr = urllib.parse.unquote(curr)
            curr = html.unescape(curr)

            # Strip null bytes and non-printable noise often used for evasion
            curr = re.sub(r'[\x00\s]+', '', curr)

            if prev == curr:
                max_depth = depth - 1
                break
            max_depth = depth

        return curr.lower(), max_depth

    def inspect_uri(self, uri_path, uri_query):
        norm_path, p_depth = self._normalize(uri_path)
        norm_query, q_depth = self._normalize(uri_query)

        # Heuristic: Detect evasion via excessive encoding
        if p_depth >= self.decode_threshold or q_depth >= self.decode_threshold:
            return True

        combined = f"{norm_path} {norm_query}"
        for p in self.patterns:
            if p.search(combined):
                return True

        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(<script|alert\(|onerror=)')

    def inspect_uri(self, uri_path, uri_query):
        combined = f"{uri_path}?{uri_query}"
        decoded = urllib.parse.unquote(combined)
        return bool(self.pattern.search(decoded))


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

    def inspect_uri(self, uri_path, uri_query):
        combined = f"{uri_path}?{uri_query}"
        decoded = urllib.parse.unquote(combined)
        for p in self.patterns:
            if p.search(decoded): return True
        return False


# ==========================================
# THE BENCHMARKING SYSTEM
# ==========================================
def download_payloads():
    print("=== Initiating Mega-Benchmark Download (5000+ Vectors) ===")

    # BASE RAW URLS
    SEC_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/"
    N3_BASE = "https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/"
    PTT_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/"
    OFF_BASE = "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/"

    urls = [
        # --- SecLists (Robot-Friendly & Master) ---
        SEC_BASE + "XSS-Jhaddix.txt",
        SEC_BASE + "XSS-Bypass-Strings-BruteLogic.txt",
        SEC_BASE + "XSS-Cheat-Sheet-PortSwigger.txt",
        SEC_BASE + "XSS-BruteLogic.txt",
        SEC_BASE + "XSS-EnDe-evation.txt",
        SEC_BASE + "XSS-Fuzzing.txt",
        SEC_BASE + "XSS-OFJAAAH.txt",
        SEC_BASE + "XSS-RSNAKE.txt",
        SEC_BASE + "XSS-Somdev.txt",
        SEC_BASE + "XSS-Vectors-Mario.txt",
        SEC_BASE + "XSS-payloadbox.txt",
        SEC_BASE + "xss-without-parentheses-semi-colons-portswigger.txt",

        # --- 1N3 IntruderPayloads (FuzzLists) ---
        N3_BASE + "xss_payloads_quick.txt",
        N3_BASE + "xss_escape_chars.txt",
        N3_BASE + "xss_find_inject.txt",
        N3_BASE + "xss_funny_stored.txt",
        N3_BASE + "xss_grep.txt",
        N3_BASE + "xss_remote_payloads-http.txt",
        N3_BASE + "xss_remote_payloads-https.txt",
        N3_BASE + "xss_swf_fuzz.txt",
        # --- PayloadsAllTheThings ---
        PTT_BASE + "IntrudersXSS.txt",
        PTT_BASE + "JHADDIX_XSS.txt",

        # --- InfoSecWarrior Offensive Payloads ---
        OFF_BASE + "Cross-Site-Scripting-XSS-Payloads.txt"
    ]

    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            filename = url.split('/')[-1]
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, context=ctx, timeout=20)
            raw_data = response.read().decode('utf-8', errors='ignore')

            lines = raw_data.splitlines()
            count = 0
            for line in lines:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    combined_payloads.add(clean_line)
                    count += 1
            print(f"[+] Successfully loaded {count} payloads from {filename}")
        except Exception as e:
            # Silently log errors for individual files if they fail, but keep going
            print(f"[-] Skipped {url.split('/')[-1]} (Check if file was renamed or 404)")

    print(f"\n[!] TOTAL UNIQUE PAYLOADS LOADED: {len(combined_payloads)}")
    return list(combined_payloads)

def run_performance_test(engine, payloads, output_dir="xss_benchmark_results"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    total = len(payloads)
    detected_payloads = []
    missed_payloads = []

    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # XSS is typically tested in the query (e.g., search=<script>...)
        if engine.inspect_uri("/", f"q={p}"):
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
        f.write(f"=== {engine.name} Benchmark Results ===\n")
        f.write(f"Total Payloads: {total}\n")
        f.write(f"Detected:       {len(detected_payloads)} ({recall:.2f}%)\n")
        f.write(f"Missed:         {len(missed_payloads)}\n")
        f.write("=" * 50 + "\n\n")
        f.write("--- MISSED PAYLOADS ---\n")
        for mp in missed_payloads: f.write(f"{mp}\n")

    return {
        "name": engine.name,
        "recall": recall,
        "time": end_time - start_time,
        "memory_kb": peak_memory / 1024
    }


if __name__ == "__main__":
    payloads = download_payloads()

    if not payloads:
        print("[-] Failed to download payloads. Exiting.")
        exit()

    print(f"[+] Loaded {len(payloads)} unique XSS payloads. Running analysis...\n")

    engines = [NaiveRegexWAF(), OwaspCrsWAF(), XSSDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<40} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 90)

    results.sort(key=lambda x: x['recall'], reverse=True)

    for r in results:
        print(f"{r['name']:<40} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    print("\n[+] Benchmark Complete.")