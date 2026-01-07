import re
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path

class ApacheLogBaseline:
    def __init__(self, log_file):
        self.log_file = log_file
        self.pattern = re.compile(
            r'(?P<ip>[\d.]+) - - \[(?P<datetime>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[\d.]+" '
            r'(?P<status>\d+) (?P<size>\d+|-) "(?P<referer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )
        self.baseline = defaultdict(lambda: defaultdict(int))
        
    def parse_log(self):
        """Parse Apache access log and extract key metrics"""
        entries = []
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.pattern.match(line)
                if match:
                    entries.append(match.groupdict())
        
        return entries
    
    def generate_baseline(self):
        """Generate baseline statistics from log entries"""
        entries = self.parse_log()
        
        if not entries:
            print("No valid log entries found!")
            return None
        
        # IP addresses
        ip_counter = Counter(e['ip'] for e in entries)
        
        # Request methods
        method_counter = Counter(e['method'] for e in entries)
        
        # Status codes
        status_counter = Counter(e['status'] for e in entries)
        
        # Top requested paths
        path_counter = Counter(e['path'] for e in entries)
        
        # User agents
        ua_counter = Counter(e['user_agent'] for e in entries)
        
        # File extensions
        ext_counter = Counter()
        for e in entries:
            ext = Path(e['path']).suffix or 'no_extension'
            ext_counter[ext] += 1
        
        # Response sizes
        sizes = [int(e['size']) for e in entries if e['size'].isdigit()]
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        
        # Hourly distribution
        hour_counter = Counter()
        for e in entries:
            try:
                dt = datetime.strptime(e['datetime'], '%d/%b/%Y:%H:%M:%S %z')
                hour_counter[dt.hour] += 1
            except:
                pass
        
        # Build baseline report
        baseline = {
            'total_requests': len(entries),
            'unique_ips': len(ip_counter),
            'date_generated': datetime.now().isoformat(),
            
            'top_ips': dict(ip_counter.most_common(10)),
            'request_methods': dict(method_counter),
            'status_codes': dict(status_counter),
            'top_paths': dict(path_counter.most_common(20)),
            'top_user_agents': dict(ua_counter.most_common(10)),
            'file_extensions': dict(ext_counter.most_common(15)),
            
            'metrics': {
                'avg_response_size_bytes': round(avg_size, 2),
                'total_data_transferred_mb': round(sum(sizes) / (1024*1024), 2),
                'requests_per_hour': dict(sorted(hour_counter.items()))
            },
            
            'rates': {
                'success_rate': round(status_counter.get('200', 0) / len(entries) * 100, 2),
                'error_rate': round(sum(v for k, v in status_counter.items() if k.startswith(('4', '5'))) / len(entries) * 100, 2),
                'get_rate': round(method_counter.get('GET', 0) / len(entries) * 100, 2),
                'post_rate': round(method_counter.get('POST', 0) / len(entries) * 100, 2)
            }
        }
        
        return baseline
    
    def save_baseline(self, output_file='baseline.json'):
        """Save baseline to JSON file"""
        baseline = self.generate_baseline()
        
        if baseline:
            with open(output_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"Baseline saved to {output_file}")
            return baseline
        return None
    
    def print_summary(self):
        """Print human-readable baseline summary"""
        baseline = self.generate_baseline()
        
        if not baseline:
            return
        
        print("\n" + "="*60)
        print("APACHE WEB SERVER LOG BASELINE REPORT")
        print("="*60)
        print(f"\nGenerated: {baseline['date_generated']}")
        print(f"Total Requests: {baseline['total_requests']:,}")
        print(f"Unique IPs: {baseline['unique_ips']:,}")
        
        print("\n--- REQUEST METHODS ---")
        for method, count in baseline['request_methods'].items():
            pct = count / baseline['total_requests'] * 100
            print(f"  {method}: {count:,} ({pct:.1f}%)")
        
        print("\n--- STATUS CODES ---")
        for status, count in sorted(baseline['status_codes'].items()):
            pct = count / baseline['total_requests'] * 100
            print(f"  {status}: {count:,} ({pct:.1f}%)")
        
        print("\n--- TOP 5 IPs ---")
        for ip, count in list(baseline['top_ips'].items())[:5]:
            print(f"  {ip}: {count:,} requests")
        
        print("\n--- TOP 5 REQUESTED PATHS ---")
        for path, count in list(baseline['top_paths'].items())[:5]:
            print(f"  {path}: {count:,} requests")
        
        print("\n--- METRICS ---")
        print(f"  Success Rate: {baseline['rates']['success_rate']}%")
        print(f"  Error Rate: {baseline['rates']['error_rate']}%")
        print(f"  Avg Response Size: {baseline['metrics']['avg_response_size_bytes']:,.0f} bytes")
        print(f"  Total Data: {baseline['metrics']['total_data_transferred_mb']:,.2f} MB")
        
        print("\n--- HOURLY DISTRIBUTION (Top 5) ---")
        hours = sorted(baseline['metrics']['requests_per_hour'].items(), 
                      key=lambda x: x[1], reverse=True)[:5]
        for hour, count in hours:
            print(f"  {hour:02d}:00 - {count:,} requests")
        
        print("\n" + "="*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Replace with your actual log file path
    log_file = "web_log_baseline.log"
    
    baseline_gen = ApacheLogBaseline(log_file)
    
    # Print summary to console
    baseline_gen.print_summary()
    
    # Save to JSON file
    baseline_gen.save_baseline("baseline.json")
    
    print("Baseline generation complete!")