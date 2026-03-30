import re
import urllib.request
import ssl
import time
import tracemalloc


# ==========================================
# 1. OUR FINAL SCANNER DETECTOR (True Threat Model)
# ==========================================
class ScannerDetector:
    """
    Tier 1 Deterministic Detector for Malicious Bots and Vulnerability Scanners.
    Optimized strictly for Exploit Frameworks and Scripting Libraries,
    intentionally bypassing marketing/SEO scrapers to maintain a near-zero FP rate.
    """
    __slots__ = ['name', 'patterns', '_seo_allowlist']

    def __init__(self):
        self.name = "Scanner & Bot Detector"

        # 1. SEO & SOCIAL MEDIA ALLOWLIST (Fast-Fail)
        # Prevents blocking of legitimate search engine indexers and social link previews
        self._seo_allowlist = re.compile(
            r'(?i)(?:googlebot|bingbot|twitterbot|linkedinbot|duckduckbot|slurp|yandexbot)'
        )

        self.patterns = [
            # 2. KNOWN VULNERABILITY SCANNERS & EXPLOIT TOOLS
            # The loudest tools often found in reconnaissance datasets
            re.compile(r'(?i)(?:sqlmap|nikto|nmap|nuclei|nessus|acunetix|dirbuster|gobuster|wfuzz|masscan|zgrab|projectdiscovery|commix|wpscan|hydra|medusa|burp|ffuf|patator)'),
            # 3. GENERIC HTTP LIBRARIES & SCRIPTING TOOLS
            # Humans use browsers; automated exploit scripts use these raw network libraries.
            re.compile(r'(?i)(?:python-requests|go-http-client|curl/|wget/|urllib|\bruby\b|\bphp\b|httpclient|postman)'),

            # 4. EXPLOIT SIGNATURES IN HEADERS
            # Catching specific malware families or embedded injection attempts
            re.compile(r'(?i)(?:zmeu|morfeus|jndi:|log4j|hello-world|susie)')
        ]

    # UPDATED: Renamed inspect_ua to inspect_payload to conform to the standardized Layer 1 interface.
    def inspect_payload(self, payload):
        """
        Analyzes the User-Agent string (passed as payload).
        Returns: Boolean (True if a malicious scanner/bot is detected).
        """
        # 1. The "Empty UA" Anomaly
        if not payload or payload.strip() in ('', '-'):
            return True

        # 2. Legitimate Bot Allowlist Bypass
        if self._seo_allowlist.search(payload):
            return False

        # 3. Malicious Pattern Match
        for p in self.patterns:
            if p.search(payload):
                return True

        return False


# ==========================================
# 2. COMPETITOR WAF: OWASP SIMULATION
# ==========================================
class OwaspCrsScannerWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        # OWASP tries to catch everything, leading to high FP
        self.pattern = re.compile(
            r'(?i)(sqlmap|nikto|curl|wget|python|java|bot|spider|scan|<b|<script|<a|href=|select|union)')

    def inspect_payload(self, payload):
        if not payload or payload.strip() in ('', '-'): return True
        return bool(self.pattern.search(payload))


# ==========================================
# BENCHMARK RUNNERS
# ==========================================
def download_list(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    payloads = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        raw_data = urllib.request.urlopen(req, context=ctx, timeout=15).read().decode('utf-8', errors='ignore')
        for line in raw_data.splitlines():
            clean_line = line.strip()
            if clean_line and not clean_line.startswith('#') and ' ' not in clean_line[:5]:
                payloads.add(clean_line.split()[0].replace('"', ''))
    except Exception:
        pass
    return list(payloads)


def run_performance_test(engine, payloads):
    total, detected = len(payloads), 0
    tracemalloc.start()
    start_time = time.perf_counter()
    for p in payloads:
        if engine.inspect_payload(p): detected += 1
    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"name": engine.name, "recall": (detected / total) * 100 if total > 0 else 0, "time": end_time - start_time,
            "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines, legit_payloads):
    print("\n=== FALSE POSITIVE (FP) TESTING (Real Browsers) ===")
    print(f"{'Engine Name':<30} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)
    for engine in engines:
        fps = sum(1 for lp in legit_payloads if engine.inspect_payload(lp))
        print(f"{engine.name:<30} | {fps:>2}/{len(legit_payloads):<7} | {(fps / len(legit_payloads)) * 100:>8.2f}%")


if __name__ == "__main__":
    print("=== Downloading Real Datasets ===")
    # Real Bad Bots (Marketing/SEO + Scanners)
    url_bad_bots = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
    malicious_payloads = download_list(url_bad_bots)
    print(f"[+] Loaded {len(malicious_payloads)} Nginx Bad Bots.")

    # Real Browsers
    legit_payloads = download_list(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents-IE.txt") + \
                     download_list(
                         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/user-agents-whatismybrowserdotcom-mid.txt")
    print(f"[+] Loaded {len(legit_payloads)} Legitimate User-Agents.\n")

    engines = [OwaspCrsScannerWAF(), ScannerDetector()]
    results = [run_performance_test(engine, malicious_payloads) for engine in engines]

    print(f"{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 77)
    for r in sorted(results, key=lambda x: x['recall'], reverse=True):
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines, legit_payloads)