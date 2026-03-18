import re
import urllib.parse
import time
import tracemalloc


# ==========================================
# 1. OUR FINAL SSRF DETECTOR
# ==========================================
class SSRFDetector:
    __slots__ = ['name', 'patterns', 'decode_threshold', '_prefilter']

    def __init__(self, decode_threshold=3):
        self.name = "SSRF Detector"
        self.decode_threshold = decode_threshold

        self.patterns = [
            # 1. CLOUD METADATA THEFT (AWS, GCP, Azure, Alibaba)
            re.compile(
                r'(?i)\b(?:169\.254\.169\.254|169\.254\.169\.253|metadata\.google\.internal|100\.100\.100\.200)\b'),

            # 2. METADATA ENDPOINTS & HEADERS
            re.compile(r'(?i)(?:latest/meta-data|metadata-flavor:\s*google|x-aws-ec2-metadata-token)'),

            # 3. DANGEROUS SCHEMES (Protocol Smuggling)
            re.compile(r'(?i)(?:gopher|dict|file|ldap|sftp|tftp|ws|wss)://'),

            # 4. LOCALHOST & OBFUSCATED LOOPBACKS
            # Catches: 127.0.0.1, 127.1, 0x7f000001 (Hex), 2130706433 (Dec), 0177.0.0.1 (Oct), [::1]
            re.compile(
                r'(?i)\b(?:localhost|127\.(?:0\.)*[0-1]|2130706433|0x7f000001|0177\.(?:0\.)*1|\[?::1\]?|0\.0\.0\.0)\b')
        ]

        self._prefilter = (
        ':', '169.', '127.', 'localhost', '0x', '::1', 'file', 'dict', 'gopher', 'meta', '2130706433', '0.0.0.0',
        '100.')

    def _normalize(self, payload):
        if not payload: return "", 0
        curr = str(payload)
        max_depth = 0

        if not any(x in curr for x in self._prefilter):
            return curr.lower(), 0

        for depth in range(1, 6):
            prev = curr
            curr = urllib.parse.unquote(curr)
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
            if p.search(combined): return True
        return False


# ==========================================
# 2. COMPETITOR WAF (Naive IP Blocker)
# ==========================================
class NaiveSSRF_WAF:
    def __init__(self):
        self.name = "Naive SSRF WAF"
        self.pattern = re.compile(r'(?i)(http://|https://|192\.168|10\.|127\.0\.0\.1)')

    def inspect_uri(self, uri_path, uri_query):
        combined = f"{uri_path}?{uri_query}"
        decoded = urllib.parse.unquote(combined)
        return bool(self.pattern.search(decoded))


# ==========================================
# SYNTHETIC BENCHMARK GENERATOR
# ==========================================
import itertools
import urllib.parse


def generate_ssrf_payloads():
    """Generates a massive, combinatorial SSRF dataset for rigorous testing."""
    print("=== Generating Synthetic SSRF Benchmark Dataset (Combinatorics) ===")
    payloads = set()

    # --- 1. LOCALHOST & LOOPBACK OBFUSCATIONS ---
    schemes = ["http://", "https://", "//", ""]
    local_ips = [
        "127.0.0.1", "localhost", "127.1", "127.0.1",
        "2130706433", "017700000001", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1",
        "0.0.0.0", "0", "[::]", "[0000::1]", "[::1]", "::1"
    ]
    ports = ["", ":80", ":443", ":22", ":6379", ":8080"]

    for s, ip, p in itertools.product(schemes, local_ips, ports):
        payloads.add(f"{s}{ip}{p}/")

    # --- 2. CLOUD METADATA OBFUSCATIONS ---
    meta_ips = [
        "169.254.169.254", "2852039166", "0xa9fea9fe", "0251.0376.0251.0376",
        "metadata.google.internal", "100.100.100.200", "169.254.169.253"
    ]
    meta_paths = ["/latest/meta-data/", "/computeMetadata/v1/", "/latest/user-data/", ""]

    for s, ip, path in itertools.product(["http://", "//", ""], meta_ips, meta_paths):
        payloads.add(f"{s}{ip}{path}")

    # --- 3. PROTOCOL SMUGGLING ---
    protocols = ["file", "gopher", "dict", "ldap", "sftp", "tftp", "ws", "wss"]
    targets = ["127.0.0.1", "localhost", "169.254.169.254", "/etc/passwd", "internal-db:5432"]

    for proto, target in itertools.product(protocols, targets):
        if proto == "file":
            payloads.add(f"file://{target}")
        else:
            payloads.add(f"{proto}://{target}/_INFO")

    # --- 4. CREDENTIAL & PARSER BYPASSES (@ and # tricks) ---
    decoys = ["google.com", "expected-domain.com"]
    for decoy, ip in itertools.product(decoys, local_ips + meta_ips):
        payloads.add(f"http://{decoy}@{ip}/")
        payloads.add(f"http://{ip}#{decoy}/")

    # --- 5. DNS REBINDING / RESOLVER DOMAINS ---
    # These resolve to 127.0.0.1 or 169.254.169.254 via DNS
    resolvers = [
        "127.0.0.1.nip.io", "localtest.me", "169.254.169.254.xip.io",
        "spoofed.burpcollaborator.net", "localhost.secureserver.net"
    ]
    for r in resolvers:
        payloads.add(f"http://{r}/")

    # --- 6. URL ENCODING STRESS TEST ---
    # Take a sample of 500 payloads and URL-encode them to test the _normalize loop
    encoded_payloads = set()
    for p in list(payloads)[:500]:
        encoded_payloads.add(urllib.parse.quote(p))
        encoded_payloads.add(urllib.parse.quote(urllib.parse.quote(p)))  # Double encode

    payloads.update(encoded_payloads)

    print(f"[+] Generated {len(payloads)} Highly Diverse SSRF Payloads.")
    return list(payloads)


def run_performance_test(engine, payloads):
    total = len(payloads)
    detected = 0
    tracemalloc.start()
    start_time = time.perf_counter()

    for p in payloads:
        if engine.inspect_uri("/", f"url={p}"):
            detected += 1

    end_time = time.perf_counter()
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    recall = (detected / total) * 100 if total > 0 else 0
    return {"name": engine.name, "recall": recall, "time": end_time - start_time, "memory_kb": peak_memory / 1024}


def run_false_positive_test(engines):
    legitimate_traffic = [
        "url=https://www.google.com",
        "redirect_uri=https://oauth.provider.com/callback",
        "webhook=http://api.slack.com/post_message",
        "next=/dashboard/user/127",
        "profile=https://github.com/avatar.png",
        "text=I am going to meet him at 10.30",
        "version=10.0.1",
        "domain=internal-wiki.mycompany.com"
    ]

    print("\n=== FALSE POSITIVE (FP) TESTING ===")
    print(f"{'Engine Name':<35} | {'FP Count':<10} | {'FP Rate (%)':<15}")
    print("-" * 65)

    for engine in engines:
        fps = 0
        for lp in legitimate_traffic:
            if engine.inspect_uri("/api/fetch", f"q={lp}"): fps += 1
        fpr = (fps / len(legitimate_traffic)) * 100
        print(f"{engine.name:<35} | {fps:>2}/{len(legitimate_traffic):<7} | {fpr:>8.2f}%")


if __name__ == "__main__":
    payloads = generate_ssrf_payloads()

    engines = [NaiveSSRF_WAF(), SSRFDetector()]
    results = [run_performance_test(eng, payloads) for eng in engines]

    print(f"\n{'Engine Name':<35} | {'Recall (%)':<12} | {'Time (sec)':<12} | {'Peak Memory (KB)'}")
    print("-" * 80)
    results.sort(key=lambda x: x['recall'], reverse=True)
    for r in results:
        print(f"{r['name']:<35} | {r['recall']:>8.2f}%   | {r['time']:>10.4f}   | {r['memory_kb']:>12.2f}")

    run_false_positive_test(engines)