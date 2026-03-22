import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os
import json


# ==========================================
# 1. OUR FINAL PATH TRAVERSAL DETECTOR (Current System)
# ==========================================
class PathTraversalDetector:
    """
    Tier 1 Deterministic Detector for Path Traversal and LFI.
    Employs structural pattern matching to identify directory escapes
    and unauthorized file access on pre-normalized payloads.
    """
    __slots__ = ['name', 'patterns']

    def __init__(self):
        self.name = "Path Traversal Detector"

        self.patterns = [
            # 1. Structural Traversal: Catch relative climbs (../ or ..\)
            re.compile(r'(?i)(?:\.{2,}[/\\]+|[/\\]+\.{2,})'),

            # 2. System Roots: High-value Linux/Windows core directories
            re.compile(r'(?i)(?:/etc/|/proc/|/root/|/\.ssh/|boot\.ini|/windows/system32|/usr/local/bin)'),

            # 3. Application Stack: Common targets in web environments
            re.compile(r'(?i)(?:/xampp/|/wamp/|/apache2?/|/phpmyadmin/|/logs?/|config\.inc\.php|php\.ini|\.viminfo)'),

            # 4. Protocols & Wrappers: Used in advanced LFI
            re.compile(r'(?i)(?:php://|file://|expect://|zip://|data://|phar://)')
        ]

    def inspect_payload(self, payload):
        """
        Primary entry point. Analyzes the centralized payload for malicious intent.
        Returns: Boolean (True if attack detected).
        """
        if not payload:
            return False

        curr = str(payload).lower()

        # Normalize common obfuscations found during benchmark failure analysis
        curr = curr.replace('%c0%ae', '.').replace('%c0%af', '/')
        curr = curr.replace('%25c1%259c', '/')
        curr = curr.replace('%uff0e', '.').replace('%u2216', '\\')

        # Deterministic Scan
        for p in self.patterns:
            if p.search(curr):
                return True

        # Structural Scan: Detect Null Byte injection (%00 or decoded \x00)
        if '%00' in curr or '\x00' in curr:
            return True

        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|windows\\win\.ini)')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


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

    def inspect_payload(self, payload):
        text = str(payload)
        for p in self.patterns:
            if p.search(text): return True
        return False


# ==========================================
# BENCHMARK RUNNERS
# ==========================================
def download_payloads():
    print("=== Downloading Fuzzing Benchmarks (Path Traversal) ===")
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
            pass

    return list(combined_payloads)

def run_performance_test(engine, payloads, output_dir="lfi_benchmark_results"):
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
        f.write(f"=== {engine.name} Benchmark Results ===\nTotal Payloads: {total}\nDetected:       {len(detected_payloads)} ({recall:.2f}%)\nMissed:         {len(missed_payloads)}\n")
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
            # Lấy 5000 payload lớn nhất
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

    print(f"\n[+] Loaded {len(payloads)} unique LFI payloads. Running comparative analysis...\n")
    engines = [NaiveRegexWAF(), OwaspCrsWAF(), PathTraversalDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 77)

    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)