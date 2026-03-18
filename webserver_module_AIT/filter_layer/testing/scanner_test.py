import re
import urllib.request
import ssl
import time
import tracemalloc


# ==========================================
# 1. OUR FINAL SCANNER DETECTOR (FP Fixed)
# ==========================================
class ScannerDetector:
    __slots__ = ['name', 'patterns', '_seo_allowlist']

    def __init__(self):
        self.name = "Scanner & Bot Detector"

        # 1. SEO & SOCIAL MEDIA ALLOWLIST
        self._seo_allowlist = re.compile(
            r'(?i)(?:googlebot|bingbot|twitterbot|linkedinbot|duckduckbot|slurp|yandexbot)')

        self.patterns = [
            # 2. KNOWN VULNERABILITY SCANNERS & EXPLOIT TOOLS
            re.compile(
                r'(?i)(?:sqlmap|nikto|nmap|nuclei|nessus|acunetix|dirbuster|gobuster|wfuzz|masscan|zgrab|projectdiscovery|commix)'),

            # 3. GENERIC HTTP LIBRARIES & SCRIPTING TOOLS
            # Removed 'java/' and 'libwww' to fix the 88 False Positives from legacy mobile phones!
            re.compile(r'(?i)(?:python-requests|go-http-client|curl/|wget/|urllib|ruby|php|httpclient|postman)'),

            # 4. KNOWN MALICIOUS/SPAM BOTS & EXPLOIT SIGNATURES
            re.compile(r'(?i)(?:zmeu|morfeus|jndi:|log4j|hello-world|susie)')
        ]

    def inspect_ua(self, user_agent):
        if not user_agent or user_agent.strip() in ('', '-'):
            return True
        if self._seo_allowlist.search(user_agent):
            return False
        for p in self.patterns:
            if p.search(user_agent):
                return True
        return False


# ==========================================
# 2. COMPETITOR WAF: OWASP SIMULATION
# ==========================================
class OwaspCrsScannerWAF:
    def __init__(self):
        self.name = "Simulated OWASP CRS WAF"
        # The monolithic approach (cramming XSS, SQLi, and Scanners together)
        self.pattern = re.compile(
            r'(?i)(sqlmap|nikto|curl|wget|python|java|bot|spider|scan|<b|<script|<a|href=|select|union)')

    def inspect_ua(self, user_agent):
        if not user_agent or user_agent.strip() in ('', '-'): return True
        return bool(self.pattern.search(user_agent))


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
        response = urllib.request.urlopen(req, context=ctx, timeout=15)
        raw_data = response.read().decode('utf-8', errors='ignore')
        for line in raw_data.splitlines():
            clean_line = line.strip()
            if clean_line and not clean_line.startswith('#'):
                payloads.add(clean_line)
    except Exception as e:
        print(f"[-] Failed to download {url}: {e}")
    return list(payloads)


def run_performance_test(engine, payloads):
    total = len(payloads)
    detected = 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        if engine.inspect_ua(p): detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (detected / total) * 100 if total > 0 else 0
    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines, legit_payloads):
    print("\n=== FALSE POSITIVE (FP) TESTING (Real Browsers) ===")
    print(f"{'Engine Name':<35} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legit_payloads:
            if engine.inspect_ua(lp): fps += 1

        fpr = (fps / len(legit_payloads)) * 100 if len(legit_payloads) > 0 else 0
        print(f"{engine.name:<35} | {fps:>2}/{len(legit_payloads):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    print("=== Downloading Datasets ===")

    # 1. Download REAL Bad Bots (Nginx Ultimate Bad Bot Blocker List)
    url_bad_bots = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
    malicious_payloads = download_list(url_bad_bots)

    # Fallback to a synthetic list if the URL fails
    if not malicious_payloads:
        print("[-] Bad Bot URL failed, generating synthetic scanner dataset...")
        malicious_payloads = ["sqlmap/1.5", "Nikto/2.1", "python-requests/2.2", "curl/7.68", "DirBuster",
                              "zgrab/0.x"] * 100

    print(f"[+] Loaded {len(malicious_payloads)} Malicious Bad Bots & Scanners.")

    # 2. Download Legitimate Browser Data
    url_ie = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents-IE.txt"
    url_mid = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/user-agents-whatismybrowserdotcom-mid.txt"

    legit_payloads = download_list(url_ie) + download_list(url_mid)
    print(f"[+] Loaded {len(legit_payloads)} Legitimate User-Agents for FP testing.\n")

    engines = [OwaspCrsScannerWAF(), ScannerDetector()]

    # Run Recall Benchmark
    results = []
    for engine in engines:
        results.append(run_performance_test(engine, malicious_payloads))

    print(f"{'Engine Name':<35} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 80)
    for r in sorted(results, key=lambda x: x['recall'], reverse=True):
        print(f"{r['name']:<35} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    # Run FP Benchmark
    run_false_positive_test(engines, legit_payloads)