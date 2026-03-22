import re
import urllib.parse
import urllib.request
import ssl
import time
import tracemalloc
import os

# ==========================================
# EXTERNAL LIBRARY IMPORTS (COMPETITORS)
# ==========================================
try:
    import sqlparse

    HAS_SQLPARSE = True
except ImportError:
    HAS_SQLPARSE = False
    print("[!] Warning: 'sqlparse' missing. Run 'pip install sqlparse'")

try:
    import libinjection

    HAS_LIBINJECTION = True
except ImportError:
    HAS_LIBINJECTION = False
    print("[!] Warning: 'libinjection-python' missing. Skipping C-library benchmark.")


# ==========================================
# 1. OUR CUSTOM DETERMINISTIC ENGINE (Current System)
# ==========================================
class SQLiDetector:
    """
    Deterministic SQL Injection Detection Engine.
    Engineered for high-throughput web server log analysis.
    Utilizes a Hybrid Architecture: Payload Normalization -> Heuristic Dictionaries -> Structural Regex.
    """
    __slots__ = ['name', 'dangerous_functions', 'command_chains', 'tautology_patterns', 'owasp_patterns']

    def __init__(self):
        self.name = "Our Hybrid Normalized-CRS WAF"

        self.dangerous_functions = [
            'information_schema', '@@version', 'version()',
            'system_user', 'database()', 'user()',
            'pg_sleep', 'waitfor delay', 'benchmark(',
            'load_file(', 'into outfile', 'into dumpfile',
            'sleep(', 'extractvalue(', 'updatexml(', 'group_concat(',
            'xp_cmdshell', 'exec(', 'randomblob(', 'substring('
        ]

        chains = [
            r'union\s+select', r'union\s+all\s+select', r'insert\s+into',
            r'drop\s+table', r'delete\s+from', r'update\s+.+?\s+set',
            r'order\s+by', r'group\s+by', r'having\s+\d+'
        ]
        self.command_chains = [re.compile(c, re.IGNORECASE) for c in chains]

        tautologies = [
            r'(\d+)\s*=\s*\1',
            r'([\'"])(.*?)\1\s*=\s*\1\2\1',
            r'(?i)\bor\s+true\b',
            r'(?i)\bor\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?',
            r'(?i)\bor\s+[\'"]?x[\'"]?\s*=\s*[\'"]?x[\'"]?',
            r'(?i)\bor\s+[\'"]?a[\'"]?\s*=\s*[\'"]?a[\'"]?',
            r'(?i)\blike\s+[\'"]%?[\'"]?',
            r'[\'"]\s*(?:#|--|/\*)',
            r'\)\s*or\s*\('
        ]
        self.tautology_patterns = [re.compile(t) for t in tautologies]

        self.owasp_patterns = [
            re.compile(
                r'(?i)(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*?\b(?:from|into|table|where|set)\b)'),
            re.compile(r'(?i)\b(?:and|or)\b\s+(?:\d+|[\'"]\w+[\'"])\s*[=<>]\s*(?:\d+|[\'"]\w+[\'"])')
        ]

    def _normalize(self, payload):
        if not payload: return ""
        normalized = str(payload).lower()
        normalized = re.sub(r'/\*!\d+(.*?)\*/', r' \1 ', normalized)
        normalized = re.sub(r'/\*.*?\*/', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized.strip()

    def inspect_payload(self, payload):
        if not payload or str(payload) == 'nan': return False
        normalized_payload = self._normalize(payload)

        for func in self.dangerous_functions:
            if func in normalized_payload: return True
        for pattern in self.command_chains:
            if pattern.search(normalized_payload): return True
        for pattern in self.tautology_patterns:
            if pattern.search(normalized_payload): return True
        for pattern in self.owasp_patterns:
            if pattern.search(normalized_payload): return True

        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(union select|insert into|drop table|1=1|or true|sleep\()')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


# ==========================================
# 3. COMPETITOR 2: SQLPARSE (AST Library)
# ==========================================
class SqlParseWAF:
    def __init__(self):
        self.name = "SqlParse (AST Library)"

    def inspect_payload(self, payload):
        if not HAS_SQLPARSE: return False
        try:
            statements = sqlparse.parse(str(payload))
            for stmt in statements:
                if stmt.get_type() in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']: return True
            return False
        except:
            return False


# ==========================================
# 4. COMPETITOR 3: OWASP CRS (Heavy Regex)
# ==========================================
class OwaspCrsWAF:
    def __init__(self):
        self.name = "OWASP CRS (Heavy Regex)"
        self.patterns = [
            re.compile(
                r'(?i)(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*?\b(?:from|into|table|where|set)\b)'),
            re.compile(r'(?i)\b(?:and|or)\b\s+(?:\d+|[\'"]\w+[\'"])\s*[=<>]\s*(?:\d+|[\'"]\w+[\'"])'),
            re.compile(r'(?i)(?:waitfor\s+delay|pg_sleep|sleep\s*\(|benchmark\s*\()'),
            re.compile(r'/\*!?[0-9]*.*?\*/')
        ]

    def inspect_payload(self, payload):
        text = str(payload)
        for p in self.patterns:
            if p.search(text): return True
        return False


# ==========================================
# 5. COMPETITOR 4: LIBINJECTION (C-Library)
# ==========================================
class LibinjectionWAF:
    def __init__(self):
        self.name = "Libinjection (C-Library)"

    def inspect_payload(self, payload):
        if not HAS_LIBINJECTION: return False
        try:
            result = libinjection.is_sql_injection(str(payload))
            return result.get('is_sqli', False)
        except:
            return False


# ==========================================
# THE BENCHMARKING SYSTEM
# ==========================================
def download_payloads():
    print("=== Downloading Stable InfoSecWarrior and PayloadsAllTheThings SQLi Benchmarks ===")
    urls = [
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/SQL-Injection-Payloads.txt",
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/SQL-Injection-Auth-Bypass-Payloads.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_UnionSelect.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQL-Injection"
    ]

    combined_payloads = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, context=ctx, timeout=10)
            lines = response.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#') and not clean_line.startswith(
                        '```') and not clean_line.startswith('<'):
                    combined_payloads.add(clean_line)
        except Exception as e:
            print(f"[-] Failed to download from {url}: {e}")

    return list(combined_payloads)


def run_performance_test(engine, payloads, output_dir="benchmark_results"):
    if not os.path.exists(output_dir): os.makedirs(output_dir)

    total = len(payloads)
    detected_payloads = []
    missed_payloads = []

    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # Simulate UnifiedEngine decoding before passing to engines
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
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            legitimate_traffic = [line.decode('utf-8', errors='ignore').strip() for line in response.readlines()][:5000]
    except Exception as e:
        print(f"[-] Lỗi tải Benign traffic: {e}. Dùng dữ liệu giả lập...")
        legitimate_traffic = ["user=admin", "id=123", "page=about", "search=hello", "profile=name"] * 400

    print(f"[+] Đã tải {len(legitimate_traffic)} mẫu truy cập hợp lệ từ SecLists.")
    print(f"{'Engine Name':<30} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic:
            if engine.inspect_payload(f"q={lp}"): fps += 1
        fpr = (fps / len(legitimate_traffic)) * 100
        print(f"{engine.name:<30} | {fps:>2}/{len(legitimate_traffic):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = download_payloads()
    if not payloads: exit()

    print(f"[+] Loaded {len(payloads)} unique payloads. Running comparative analysis...\n")

    engines = [NaiveRegexWAF(), OwaspCrsWAF(), SQLiDetector()]
    if HAS_SQLPARSE: engines.append(SqlParseWAF())
    if HAS_LIBINJECTION: engines.append(LibinjectionWAF())

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 77)
    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)