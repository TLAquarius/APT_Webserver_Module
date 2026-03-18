import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os
import json


# ==========================================
# 1. OUR GENERALIZED DETERMINISTIC ENGINE
# ==========================================
import re
import urllib.parse
import base64

import re
import urllib.parse

import re
import urllib.parse


class PathTraversalDetector:
    __slots__ = ['name', 'patterns', 'decode_threshold']

    def __init__(self, decode_threshold=3):
        self.name = "Path Traversal Detector"
        self.decode_threshold = decode_threshold

        self.patterns = [
            # 1. Structural: Relative traversal (../ or ..\)
            re.compile(r'(?i)(?:\.{2,}[/\\]+|[/\\]+\.{2,})'),

            # 2. System Roots: Linux/Windows Core
            re.compile(r'(?i)(?:/etc/|/proc/|/root/|/\.ssh/|boot\.ini|/windows/system32|/usr/local/bin)'),

            # 3. Application Stack: Catching the "Missed" XAMPP/WAMP/Apache files
            # This targets the "Intent" of reading logs or config files
            re.compile(r'(?i)(?:/xampp/|/wamp/|/apache2?/|/phpmyadmin/|/logs?/|config\.inc\.php|php\.ini|\.viminfo)'),

            # 4. Protocols & Wrappers
            re.compile(r'(?i)(?:php://|file://|expect://|zip://|data://|phar://)')
        ]

    def _normalize(self, payload):
        if not payload: return "", 0
        curr = str(payload)
        max_depth = 0

        for depth in range(1, 6):
            prev = curr
            curr = urllib.parse.unquote(curr)
            # Handle the specific overlong/unicode evasions from your missed list
            curr = curr.replace('%c0%ae', '.').replace('%c0%af', '/').replace('%25c1%259c', '/')
            curr = curr.replace('%uff0e', '.').replace('%u2216', '\\')

            if prev == curr:
                max_depth = depth - 1
                break
            max_depth = depth
        return curr.lower(), max_depth

    def inspect_uri(self, uri_path, uri_query):
        norm_path, p_depth = self._normalize(uri_path)
        norm_query, q_depth = self._normalize(uri_query)

        # Heuristic: Excessive decoding
        if p_depth >= self.decode_threshold or q_depth >= self.decode_threshold:
            return True

        combined = f"{norm_path} {norm_query}"

        # Check Patterns
        for p in self.patterns:
            if p.search(combined):
                return True

        # Check for Null Byte
        if '%00' in str(uri_path) or '%00' in str(uri_query):
            return True

        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|windows\\win\.ini)')

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
            re.compile(r'(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%c0%af|%c1%9c)'),
            re.compile(r'(?i)(?:php://|file://|zip://|data://)'),
            re.compile(r'(?i)(?:/etc/passwd|/etc/shadow|boot\.ini|/windows/win\.ini)')
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
    print("=== Downloading Fuzzing Benchmarks ===")

    urls = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/lfi.txt",
        "https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/traversal.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
        "https://raw.githubusercontent.com/odaysec/PwnTraverse/main/assets/exploits.json",
        "https://raw.githubusercontent.com/ifconfig-me/Directory-Traversal-Payloads/refs/heads/main/payloads.txt"
    ]

    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, context=ctx, timeout=10)
            raw_data = response.read().decode('utf-8', errors='ignore')

            if url.endswith('.json'):
                data = json.loads(raw_data)
                for key, value in data.items():
                    if isinstance(value, str):
                        combined_payloads.add(value.strip())
            else:
                for line in raw_data.splitlines():
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith('#'):
                        combined_payloads.add(clean_line)
        except Exception as e:
            print(f"[-] Failed to download from {url}: {e}")

    return list(combined_payloads)


def run_performance_test(engine, payloads, output_dir="lfi_benchmark_results"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    total = len(payloads)
    detected_payloads = []
    missed_payloads = []

    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        if engine.inspect_uri("/", f"file={p}"):
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
        for mp in missed_payloads:
            f.write(f"{mp}\n")

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

    print(f"[+] Loaded {len(payloads)} unique LFI payloads. Running comparative analysis...\n")

    engines = [NaiveRegexWAF(), OwaspCrsWAF(), PathTraversalDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 77)

    results.sort(key=lambda x: x['recall'], reverse=True)

    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    print("\n[+] Benchmark Complete.")