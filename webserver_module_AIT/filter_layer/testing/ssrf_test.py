import re
import urllib.parse
import time
import tracemalloc
import itertools
import ssl
import urllib.request


# ==========================================
# 1. OUR FINAL SSRF DETECTOR (Current System)
# ==========================================
class SSRFDetector:
    """
    Tier 1 Deterministic Detector for Server-Side Request Forgery (SSRF).
    Targets high-confidence Indicators of Compromise (IoCs).
    """
    __slots__ = ['name', 'patterns', '_prefilter']

    def __init__(self):
        self.name = "SSRF Detector"

        self.patterns = [
            # 1. CLOUD METADATA THEFT (AWS, GCP, Azure, Alibaba)
            re.compile(
                r'(?i)\b(?:169\.254\.169\.254|169\.254\.169\.253|metadata\.google\.internal|100\.100\.100\.200)\b'),
            # 2. METADATA ENDPOINTS & HEADERS
            re.compile(r'(?i)(?:latest/meta-data|metadata-flavor:\s*google|x-aws-ec2-metadata-token)'),
            # 3. DANGEROUS SCHEMES (Protocol Smuggling)
            re.compile(r'(?i)(?:gopher|dict|file|ldap|sftp|tftp|ws|wss)://'),
            # 4. LOCALHOST & OBFUSCATED LOOPBACKS
            re.compile(
                r'(?i)\b(?:localhost|127\.(?:0\.)*[0-1]|2130706433|0x7f000001|0177\.(?:0\.)*1|\[?::1\]?|0\.0\.0\.0)\b')
        ]

        self._prefilter = (
            ':', '169.', '127.', 'localhost', '0x', '::1', 'file',
            'dict', 'gopher', 'meta', '2130706433', '0.0.0.0', '100.'
        )

    def inspect_payload(self, payload):
        if not payload: return False

        payload_lower = str(payload).lower()

        if not any(x in payload_lower for x in self._prefilter):
            return False

        payload_clean = payload_lower.replace('\x00', '')

        for p in self.patterns:
            if p.search(payload_clean): return True
        return False


# ==========================================
# 2. COMPETITOR WAF (Naive IP Blocker)
# ==========================================
class NaiveSSRF_WAF:
    def __init__(self):
        self.name = "Naive SSRF WAF"
        self.pattern = re.compile(r'(?i)(http://|https://|192\.168|10\.|127\.0\.0\.1)')

    def inspect_payload(self, payload):
        return bool(self.pattern.search(str(payload)))


# ==========================================
# SYNTHETIC BENCHMARK GENERATOR
# ==========================================
def generate_ssrf_payloads():
    print("=== Generating Synthetic SSRF Benchmark Dataset (Combinatorics) ===")
    payloads = set()

    schemes = ["http://", "https://", "//", ""]
    local_ips = [
        "127.0.0.1", "localhost", "127.1", "127.0.1",
        "2130706433", "017700000001", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1",
        "0.0.0.0", "0", "[::]", "[0000::1]", "[::1]", "::1"
    ]
    ports = ["", ":80", ":443", ":22", ":6379", ":8080"]

    for s, ip, p in itertools.product(schemes, local_ips, ports):
        payloads.add(f"{s}{ip}{p}/")

    meta_ips = ["169.254.169.254", "2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "metadata.google.internal",
                "100.100.100.200", "169.254.169.253"]
    meta_paths = ["/latest/meta-data/", "/computeMetadata/v1/", "/latest/user-data/", ""]

    for s, ip, path in itertools.product(["http://", "//", ""], meta_ips, meta_paths):
        payloads.add(f"{s}{ip}{path}")

    protocols = ["file", "gopher", "dict", "ldap", "sftp", "tftp", "ws", "wss"]
    targets = ["127.0.0.1", "localhost", "169.254.169.254", "/etc/passwd", "internal-db:5432"]

    for proto, target in itertools.product(protocols, targets):
        if proto == "file":
            payloads.add(f"file://{target}")
        else:
            payloads.add(f"{proto}://{target}/_INFO")

    decoys = ["google.com", "expected-domain.com"]
    for decoy, ip in itertools.product(decoys, local_ips + meta_ips):
        payloads.add(f"http://{decoy}@{ip}/")
        payloads.add(f"http://{ip}#{decoy}/")

    resolvers = ["127.0.0.1.nip.io", "localtest.me", "169.254.169.254.xip.io", "spoofed.burpcollaborator.net"]
    for r in resolvers: payloads.add(f"http://{r}/")

    print(f"[+] Generated {len(payloads)} Highly Diverse SSRF Payloads.")
    return list(payloads)


def run_performance_test(engine, payloads):
    total = len(payloads)
    detected = 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        # Pass directly to payload inspector (simulating UnifiedEngine)
        decoded_p = urllib.parse.unquote(p)
        if engine.inspect_payload(decoded_p):
            detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (detected / total) * 100 if total > 0 else 0
    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    print("\n=== FALSE POSITIVE (FP) TESTING ===")

    # 1. Base legitimate URLs
    legitimate_traffic = [
        "https://www.google.com](https://www.google.com)",
        "[https://oauth.provider.com/callback](https://oauth.provider.com/callback)",
        "[http://api.slack.com/post_message](http://api.slack.com/post_message)",
        "/dashboard/user/127",
        "[https://github.com/avatar.png](https://github.com/avatar.png)",
        "I am going to meet him at 10.30",
        "version=10.0.1",
        "internal-wiki.mycompany.com"
    ]

    # 2. Add SecLists Raft Small Words
    url_benign = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url_benign, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            legitimate_traffic += [line.decode('utf-8', errors='ignore').strip() for line in response.readlines()][
                                  :3000]
    except Exception as e:
        print(f"[-] Lỗi tải Benign traffic: {e}.")

    print(f"[{'+'}] Đã tải {len(legitimate_traffic)} mẫu truy cập hợp lệ.")
    print(f"{'Engine Name':<30} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic:
            if engine.inspect_payload(lp): fps += 1
        fpr = (fps / len(legitimate_traffic)) * 100
        print(f"{engine.name:<30} | {fps:>2}/{len(legitimate_traffic):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = generate_ssrf_payloads()

    engines = [NaiveSSRF_WAF(), SSRFDetector()]
    results = [run_performance_test(eng, payloads) for eng in engines]

    print(f"\n{'Engine Name':<30} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 80)
    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<30} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)