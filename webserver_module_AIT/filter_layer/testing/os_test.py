import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os


# ==========================================
# 1. OUR FINAL RCE DETECTOR (Current System)
# ==========================================
class OSCommandInjectionDetector:
    __slots__ = ['name', 'patterns', 'stderr_patterns', '_prefilter']

    def __init__(self):
        self.name = "OS Command Injection Detector"

        self.patterns = [
            # 1. UNIVERSAL CHAINING (With Negative Lookahead for FP reduction)
            re.compile(
                r'(?i)(?:[;&|\n\r]|`|\$\()[\s\+\$]*\b(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|gcc|hostname|sleep|ping|echo|base64|tail|head|grep|find|dir|ipconfig|powershell|cmd|tasklist|awk|sed|nslookup|dig)\b(?!\s*=)'),

            # 2. PATH & ENV INJECTION
            re.compile(r'(?i)(?:/[a-z0-9_-]+)*/(?:bin|sbin|etc|usr|var|tmp|windows|system32)/[a-z0-9_-]+'),

            # 3. BLIND & SUB-SHELL EXECUTION
            re.compile(r'(?i)(?:`[^`]{2,20}`|\$\([^)]+\))'),

            # 4. IO REDIRECTION & LOGICAL OPERATORS
            re.compile(r'(?i)(?:[0-9]?[><]{1,2}\s*[a-z0-9_\-\./]+|\|\||&&)'),

            # 5. WEBSHELL / STANDALONE COMMANDS
            re.compile(
                r'(?i)\b(?:whoami|uname\s+-[ar]|cat\s+/(?:etc|proc|var)/[a-z0-9_-]+|netstat\s+-[a-z]+|id|ifconfig|ip\s+addr)\b(?!\s*=)'),

            # 6. REVERSE TCP/UDP SHELLS
            re.compile(r'(?i)(?:/dev/tcp/[0-9\.]+|/dev/udp/[0-9\.]+|nc\s+-e|bash\s+-i|bash\s+-c)')
        ]

        self.stderr_patterns = [
            re.compile(r'(?i)(?:TERM environment variable not set|No LSB modules are available)'),
            re.compile(r'(?i)(?:Resolving github\.com|Connecting to.*?\|:443\.\.\. connected)'),
            re.compile(r'(?i)(?:command not found|sh: 1:|bash: line 1:)'),
            re.compile(r'(?i)(?:uid=\d+\(.*\) gid=\d+\(.*\) groups=\d+\(.*\))')
        ]

        self._prefilter = (
            ';', '&', '|', '`', '$', '>', '<', '/', '%', '\n',
            'whoami', 'uname', 'cat ', 'netstat', 'id', 'ifconfig', 'ip ', 'nc ', 'bash'
        )

    def inspect_payload(self, payload):
        if not payload: return False

        payload_lower = payload.lower()
        if not any(x in payload_lower for x in self._prefilter):
            return False

        if '${ifs}' in payload_lower or '$ifs$9' in payload_lower:
            payload_lower = re.sub(r'(?i)\$\{ifs\}|\$ifs\$9', ' ', payload_lower)

        payload_lower = payload_lower.replace('\x00', '')

        for p in self.patterns:
            if p.search(payload_lower):
                return True

        return False

    def inspect_error(self, raw_message):
        if not raw_message: return False
        if "AH00163:" in raw_message or "AH00094:" in raw_message: return False

        for p in self.stderr_patterns:
            if p.search(raw_message): return True
        return False


# ==========================================
# 2. COMPETITORS
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(;|&&|\|\||whoami|cat\b|dir\b)')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


class OwaspCrsWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        self.patterns = [
            re.compile(r'(?i)[;&|`]'),
            re.compile(r'(?i)\$\('),
            re.compile(r'(?i)\b(?:cat|ls|id|whoami|powershell|cmd)\b')
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
            for line in raw_data.splitlines():
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    combined_payloads.add(clean_line)
        except Exception:
            pass
    return list(combined_payloads)


def run_performance_test(engine, payloads):
    total = len(payloads)
    detected = 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # Simulate UnifiedEngine decoding
        decoded_p = urllib.parse.unquote(p)
        if engine.inspect_payload(decoded_p):
            detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (detected / total) * 100 if total > 0 else 0
    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    print("\n=== HARD MODE FALSE POSITIVE (FP) TESTING ===")

    # 1. Base hardcoded URLs that trigger edge cases
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

    # 2. Add SecLists Raft Large Words
    url_benign = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url_benign, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            legitimate_traffic_hard += [line.decode('utf-8', errors='ignore').strip() for line in response.readlines()][
                                       :5000]
    except Exception as e:
        print(f"[-] Lỗi tải Benign traffic: {e}.")

    print(f"[+] Đã tải {len(legitimate_traffic_hard)} mẫu truy cập hợp lệ từ SecLists.")
    print(f"{'Engine Name':<30} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic_hard:
            if engine.inspect_payload(lp):
                fps += 1
        fpr = (fps / len(legitimate_traffic_hard)) * 100
        print(f"{engine.name:<30} | {fps:>2}/{len(legitimate_traffic_hard):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = download_payloads()
    if not payloads: exit()

    print(f"\n[+] Loaded {len(payloads)} unique RCE payloads. Running analysis...\n")
    engines = [NaiveRegexWAF(), OwaspCrsWAF(), OSCommandInjectionDetector()]

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 77)
    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)