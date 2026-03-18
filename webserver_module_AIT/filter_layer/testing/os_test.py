import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os


# ==========================================
# 1. OUR FINAL RCE DETECTOR
# ==========================================
class OSCommandInjectionDetector:
    __slots__ = ['name', 'patterns', 'decode_threshold', '_prefilter']

    def __init__(self, decode_threshold=3):
        self.name = "OS Command Injection Detector"
        self.decode_threshold = decode_threshold

        self.patterns = [
            # 1. UNIVERSAL CHAINING (With Negative Lookahead for FP reduction)
            re.compile(
                r'(?i)(?:[;&|\n\r]|`|\$\()[\s\+\$]*\b(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|gcc|hostname|sleep|ping|echo|base64|tail|head|grep|find|dir|ipconfig|powershell|cmd|tasklist|awk|sed|nslookup|dig)\b(?!\s*=)'),

            # 2. PATH & ENV INJECTION
            re.compile(r'(?i)(?:/[a-z0-9_-]+)*/(?:bin|sbin|etc|usr|var|tmp|windows|system32)/[a-z0-9_-]+'),

            # 3. BLIND & SUB-SHELL EXECUTION
            re.compile(r'(?i)(?:`[^`]{2,20}`|\$\([^)]+\))'),

            # 4. IO REDIRECTION & LOGICAL OPERATORS
            re.compile(r'(?i)(?:[0-9]?[><]{1,2}\s*[a-z0-9_\-\./]+|\|\||&&)')
        ]

        self._prefilter = (';', '&', '|', '`', '$', '>', '<', '/', '%', '\n')

    def _normalize(self, payload):
        if not payload:
            return "", 0

        curr = str(payload)
        max_depth = 0

        if not any(x in curr for x in self._prefilter):
            return curr.lower(), 0

        for depth in range(1, 6):
            prev = curr
            curr = urllib.parse.unquote(curr)

            curr_lower = curr.lower()
            if '${ifs}' in curr_lower or '$ifs$9' in curr_lower:
                curr = re.sub(r'(?i)\$\{ifs\}|\$ifs\$9', ' ', curr)

            curr = curr.replace('\x00', '')

            if prev == curr:
                max_depth = depth - 1
                break
            max_depth = depth

        return curr.lower(), max_depth

    def inspect_uri(self, uri_path, uri_query):
        if not any(x in uri_path or x in uri_query for x in self._prefilter):
            return False

        norm_path, p_depth = self._normalize(uri_path)
        norm_query, q_depth = self._normalize(uri_query)

        if p_depth >= self.decode_threshold or q_depth >= self.decode_threshold:
            return True

        combined = f"{norm_path} {norm_query}"
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
        self.pattern = re.compile(r'(?i)(;|&&|\|\||whoami|cat\b|dir\b)')

    def inspect_uri(self, uri_path, uri_query):
        combined = f"{uri_path}?{uri_query}"
        decoded = urllib.parse.unquote(combined)
        return bool(self.pattern.search(decoded))


class OwaspCrsWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        self.patterns = [
            re.compile(r'(?i)[;&|`]'),
            re.compile(r'(?i)\$\('),
            re.compile(r'(?i)\b(?:cat|ls|id|whoami|powershell|cmd)\b')
        ]

    def inspect_uri(self, uri_path, uri_query):
        combined = f"{uri_path}?{uri_query}"
        decoded = urllib.parse.unquote(combined)
        for p in self.patterns:
            if p.search(decoded): return True
        return False


# ==========================================
# BENCHMARK RUNNERS
# ==========================================
def download_payloads():
    print("=== Downloading Verified RCE Benchmarks ===")
    urls = [
        "https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/command_exec.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt"
    ]
    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, context=ctx, timeout=15)
            raw_data = response.read().decode('utf-8', errors='ignore')
            count = 0
            for line in raw_data.splitlines():
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    combined_payloads.add(clean_line)
                    count += 1
            print(f"[+] Loaded {count} payloads from {url.split('/')[-1]}")
        except Exception as e:
            pass
    return list(combined_payloads)


def run_performance_test(engine, payloads):
    total = len(payloads)
    detected = 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        if engine.inspect_uri("/", f"cmd={p}"):
            detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (detected / total) * 100 if total > 0 else 0
    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    legitimate_traffic_hard = [
        "comment=I have a dog; cat is sleeping",
        "code=if (a && b) { return c || d; }",
        "math=5 > 3",
        "xml=<head><title>My Blog</title></head>",
        "path=/var/www/html/uploads/image.png",
        "search=find+and+replace+text",
        "query=SELECT+*+FROM+users;--",
        "email=john.doe@cat.com",
        "url=https://example.com/dir/page?id=1",
        "profile=name:john|age:30|role:admin"
    ]

    print("\n=== HARD MODE FALSE POSITIVE (FP) TESTING ===")
    print(f"{'Engine Name':<35} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic_hard:
            if engine.inspect_uri("/index.php", f"q={lp}"):
                fps += 1
        fpr = (fps / len(legitimate_traffic_hard)) * 100
        print(f"{engine.name:<35} | {fps:>2}/{len(legitimate_traffic_hard):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = download_payloads()
    if not payloads: exit()

    print(f"\n[+] Loaded {len(payloads)} unique RCE payloads. Running analysis...\n")
    engines = [NaiveRegexWAF(), OwaspCrsWAF(), OSCommandInjectionDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<35} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 80)
    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<35} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)