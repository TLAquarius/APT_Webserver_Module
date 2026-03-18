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
# 1. OUR CUSTOM DETERMINISTIC ENGINE
# ==========================================
import re
import urllib.parse


class SQLiDetector:
    # __slots__ prevents Python from creating dynamic dictionaries, saving RAM
    __slots__ = ['name', 'dangerous_functions', 'command_chains', 'tautology_patterns', 'owasp_patterns']

    def __init__(self):
        self.name = "Our Hybrid Normalized-CRS WAF"

        # 1. RESTORED FULL DICTIONARY (This brings back the 90%+ Recall)
        self.dangerous_functions = [
            'information_schema', '@@version', 'version()',
            'system_user', 'database()', 'user()',
            'pg_sleep', 'waitfor delay', 'benchmark(',
            'load_file', 'into outfile', 'into dumpfile',
            'sleep(', 'extractvalue(', 'updatexml(', 'group_concat(',
            'xp_cmdshell', 'exec(', 'randomblob(', 'substring('
        ]

        # 2. Pre-compiled list of regexes (Fast, but keeps backreferences intact)
        chains = [
            r'union\s+select', r'union\s+all\s+select', r'insert\s+into',
            r'drop\s+table', r'delete\s+from', r'update\s+.+?\s+set',
            r'order\s+by', r'group\s+by', r'having\s+\d+'
        ]
        self.command_chains = [re.compile(c, re.IGNORECASE) for c in chains]

        # 3. Pre-compiled tautologies
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

        # 4. OWASP
        self.owasp_patterns = [
            re.compile(
                r'(?i)(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*?\b(?:from|into|table|where|set)\b)'),
            re.compile(r'(?i)\b(?:and|or)\b\s+(?:\d+|[\'"]\w+[\'"])\s*[=<>]\s*(?:\d+|[\'"]\w+[\'"])')
        ]

    def _normalize(self, payload):
        if not payload: return ""
        normalized = payload.lower()
        normalized = re.sub(r'/\*!\d+(.*?)\*/', r' \1 ', normalized)
        normalized = re.sub(r'/\*.*?\*/', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized.strip()

    def inspect_uri(self, uri_query):
        if not uri_query or str(uri_query) == 'nan': return False

        # Removed the 'while True' loop. We trust Layer 0!
        # We keep one fast unquote just as a localized safety net.
        payload = self._normalize(urllib.parse.unquote(str(uri_query)))

        # Tiered Inspection Pipeline
        for func in self.dangerous_functions:
            if func in payload: return True

        for pattern in self.command_chains:
            if pattern.search(payload): return True

        for pattern in self.tautology_patterns:
            if pattern.search(payload): return True

        for pattern in self.owasp_patterns:
            if pattern.search(payload): return True

        return False


# ==========================================
# 2. COMPETITOR 1: NAIVE REGEX
# ==========================================
class NaiveRegexWAF:
    def __init__(self):
        self.name = "Naive Regex WAF"
        self.pattern = re.compile(r'(?i)(union select|insert into|drop table|1=1|or true|sleep\()')

    def inspect_uri(self, uri_query):
        decoded = urllib.parse.unquote(uri_query)
        return bool(self.pattern.search(decoded))


# ==========================================
# 3. COMPETITOR 2: SQLPARSE (AST Library)
# ==========================================
class SqlParseWAF:
    def __init__(self):
        self.name = "SqlParse (AST Library)"

    def inspect_uri(self, uri_query):
        if not HAS_SQLPARSE: return False
        decoded = urllib.parse.unquote(uri_query)
        try:
            statements = sqlparse.parse(decoded)
            for stmt in statements:
                if stmt.get_type() in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']:
                    return True
            return False
        except:
            return False


# ==========================================
# 4. COMPETITOR 3: OWASP CRS (Heavy Regex)
# ==========================================
class OwaspCrsWAF:
    """ Simulates Enterprise WAFs that rely on massive, complex regular expressions """

    def __init__(self):
        self.name = "OWASP CRS (Heavy Regex)"
        self.patterns = [
            re.compile(
                r'(?i)(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*?\b(?:from|into|table|where|set)\b)'),
            re.compile(r'(?i)\b(?:and|or)\b\s+(?:\d+|[\'"]\w+[\'"])\s*[=<>]\s*(?:\d+|[\'"]\w+[\'"])'),
            re.compile(r'(?i)(?:waitfor\s+delay|pg_sleep|sleep\s*\(|benchmark\s*\()'),
            re.compile(r'/\*!?[0-9]*.*?\*/')
        ]

    def inspect_uri(self, uri_query):
        decoded = urllib.parse.unquote(uri_query)
        for p in self.patterns:
            if p.search(decoded): return True
        return False


# ==========================================
# 5. COMPETITOR 4: LIBINJECTION (C-Library)
# ==========================================
class LibinjectionWAF:
    """ The Gold Standard Industry Tokenizer """

    def __init__(self):
        self.name = "Libinjection (C-Library)"

    def inspect_uri(self, uri_query):
        if not HAS_LIBINJECTION: return False
        decoded = urllib.parse.unquote(uri_query)
        try:
            # Returns a dict: {'is_sqli': True, 'fingerprint': 's&k'}
            result = libinjection.is_sql_injection(decoded)
            return result.get('is_sqli', False)
        except:
            return False


# ==========================================
# THE BENCHMARKING SYSTEM
# ==========================================
def download_payloads():
    print("=== Downloading Stable InfoSecWarrior and PayloadsAllTheThings SQLi Benchmarks ===")

    urls = [
        # Original InfoSecWarrior Payloads (Stable)
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/SQL-Injection-Payloads.txt",
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/main/SQL-Injection-Auth-Bypass-Payloads.txt",

        # PayloadsAllTheThings (Stable)
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

            # Use errors='ignore' because advanced payloads often contain raw bytes/malformed characters
            lines = response.read().decode('utf-8', errors='ignore').splitlines()

            for line in lines:
                clean_line = line.strip()
                # Filtering to ignore markdown headers/HTML tags present in some raw files
                if clean_line and not clean_line.startswith('#') and not clean_line.startswith(
                        '```') and not clean_line.startswith('<'):
                    combined_payloads.add(clean_line)
        except Exception as e:
            print(f"[-] Failed to download from {url}: {e}")

    return list(combined_payloads)


def run_performance_test(engine, payloads, output_dir="benchmark_results"):
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    total = len(payloads)
    detected_payloads = []
    missed_payloads = []

    # Start tracking time and memory
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        if engine.inspect_uri(p):
            detected_payloads.append(p)
        else:
            missed_payloads.append(p)

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (len(detected_payloads) / total) * 100 if total > 0 else 0

    # --- SAVE TO FILE LOGIC ---
    # Sanitize the engine name for a clean filename
    safe_name = engine.name.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    filename = os.path.join(output_dir, f"{safe_name}_results.txt")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"=== {engine.name} Benchmark Results ===\n")
        f.write(f"Total Payloads: {total}\n")
        f.write(f"Detected:       {len(detected_payloads)} ({recall:.2f}%)\n")
        f.write(f"Missed:         {len(missed_payloads)}\n")
        f.write("=" * 50 + "\n\n")

        f.write("--- MISSED PAYLOADS (Analyze these: Are they Exploits or Harmless Junk?) ---\n")
        for mp in missed_payloads:
            f.write(f"{mp}\n")

        f.write("\n\n--- DETECTED PAYLOADS (True Positives) ---\n")
        for dp in detected_payloads:
            f.write(f"{dp}\n")

    return {
        "name": engine.name,
        "recall": recall,
        "time": end_time - start_time,
        "memory_kb": peak_memory / 1024,
        "log_file": filename
    }


if __name__ == "__main__":
    payloads = download_payloads()

    if not payloads:
        print("[-] Failed to download payloads. Exiting.")
        exit()

    print(f"[+] Loaded {len(payloads)} unique payloads. Running comparative analysis...\n")

    # Initialize Engines
    engines = [NaiveRegexWAF(), OwaspCrsWAF(), SQLiDetector()]
    if HAS_SQLPARSE: engines.append(SqlParseWAF())
    if HAS_LIBINJECTION: engines.append(LibinjectionWAF())

    results = []
    for engine in engines:
        results.append(run_performance_test(engine, payloads))

    # Print Comparative Table
    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)':<15}")
    print("-" * 77)

    results.sort(key=lambda x: x['recall'], reverse=True)

    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    print("\n[+] Benchmark Complete.")
    print("[+] Detailed diagnostic logs have been saved to the 'benchmark_results' folder.")