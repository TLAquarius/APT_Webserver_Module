import pandas as pd
import re
from io import StringIO

# Sample log as a string (from previous example)
log_data = """
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-dashboard3.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
83.149.9.216 - - [17/May/2015:10:05:43 +0000] "GET /presentations/logstash-monitorama-2013/plugin/highlight/jquery.highlight-3.js HTTP/1.1" 200 2618 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
83.149.9.216 - - [17/May/2015:10:05:47 +0000] "GET /presentations/logstash-monitorama-2013/plugin/notes/notes.html HTTP/1.1" 200 11891 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
83.149.9.216 - - [17/May/2015:10:05:12 +0000] "GET /presentations/logstash-monitorama-2013/plugin/zoom-js/images/loading.png HTTP/1.1" 200 1401 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
83.149.9.216 - - [17/May/2015:10:05:07 +0000] "GET /presentations/logstash-monitorama-2013/plugin/zoom-js/zoom.js HTTP/1.1" 200 7696 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
66.249.66.19 - - [17/May/2015:10:05:27 +0000] "GET /blog/geekery/ssl-latency.html HTTP/1.1" 200 17147 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.66.19 - - [17/May/2015:10:05:20 +0000] "GET /blog/geekery/xvfb-firefox.html HTTP/1.1" 200 10975 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.66.19 - - [17/May/2015:10:05:24 +0000] "GET /blog/geekery/debugging-java-jvm-core.html HTTP/1.1" 200 11492 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
"""

# Regex pattern for Combined Log Format
log_pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'

# Parse logs into list of dicts
parsed_logs = []
for line in StringIO(log_data):
    match = re.match(log_pattern, line.strip())
    if match:
        parsed_logs.append({
            'ip': match.group(1),
            'timestamp': pd.to_datetime(match.group(2), format='%d/%b/%Y:%H:%M:%S %z'),
            'method': match.group(3),
            'endpoint': match.group(4),
            'status': int(match.group(5)),
            'bytes_sent': int(match.group(6)),
            'referrer': match.group(7),
            'user_agent': match.group(8)
        })

# Create DataFrame
df = pd.DataFrame(parsed_logs)
print(df.head())  # For verification

import numpy as np

# Group by IP and calculate stats
ip_stats = df.groupby('ip').agg(
    request_count=('ip', 'size'),
    avg_bytes=('bytes_sent', 'mean'),
    std_bytes=('bytes_sent', 'std')
).fillna(0)  # Fill NaN std for single requests

# Overall baselines
mean_requests = ip_stats['request_count'].mean()
std_requests = ip_stats['request_count'].std()
mean_bytes = df['bytes_sent'].mean()
status_dist = df['status'].value_counts(normalize=True)  # Proportion of each status

# Define baseline thresholds (e.g., for anomaly flagging later)
request_threshold = mean_requests + 3 * std_requests
print(f"Baseline mean requests per IP: {mean_requests}")
print(f"Baseline status distribution: {status_dist}")
# Example: Flag IPs exceeding threshold
anomalous_ips = ip_stats[ip_stats['request_count'] > request_threshold].index.tolist()
print(f"Anomalous IPs: {anomalous_ips}")

#===============================================================================
#===============================================================================
#===============================================================================
# Define rules
allowed_methods = ['GET', 'POST']
allowed_status = [200, 304]  # Success codes
malicious_patterns = ['sqlmap', 'nikto']  # Example suspicious user agents

# Apply rules to flag deviations
df['is_anomalous'] = False
df.loc[~df['method'].isin(allowed_methods), 'is_anomalous'] = True
df.loc[~df['status'].isin(allowed_status), 'is_anomalous'] = True
for pattern in malicious_patterns:
    df.loc[df['user_agent'].str.contains(pattern, case=False, na=False), 'is_anomalous'] = True

# Baseline: Proportion of normal logs
normal_proportion = 1 - (df['is_anomalous'].sum() / len(df))
print(f"Baseline normal proportion: {normal_proportion}")
print(df[df['is_anomalous']])  # View flagged logs

#============================================================
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

# Prepare features (exclude timestamp for simplicity)
features = ['method', 'status', 'bytes_sent']
preprocessor = ColumnTransformer([('onehot', OneHotEncoder(), ['method', 'status'])], remainder='passthrough')
X = preprocessor.fit_transform(df[features])

# Train Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)  # Assume 10% anomalies
model.fit(X)
df['anomaly_score'] = model.decision_function(X)  # Lower = more anomalous
df['is_anomalous'] = model.predict(X) == -1

print(df[['timestamp', 'ip', 'anomaly_score', 'is_anomalous']])

#============================================================
from statsmodels.tsa.arima.model import ARIMA

# Resample to time-series (requests per second for this small sample)
df.set_index('timestamp', inplace=True)
ts = df.resample('s').size().fillna(0)  # Requests per second

# Fit ARIMA (order p=1,d=1,q=1 for simplicity; tune with ACF/PACF in practice)
model = ARIMA(ts, order=(1,1,1))
model_fit = model.fit()
forecast = model_fit.forecast(steps=10)  # Baseline forecast for next 10 seconds

# Residuals as anomaly measure (high residuals = anomalous)
residuals = model_fit.resid
threshold = residuals.std() * 3
anomalies = ts[abs(residuals) > threshold]
print(f"Baseline forecast: {forecast}")
print(f"Anomalies: {anomalies}")

#===================================================
# Statistical baseline first (from method 1)
ip_stats = df.groupby('ip').agg(request_count=('ip', 'size'))
high_request_ips = ip_stats[ip_stats['request_count'] > request_threshold].index

# Filter DataFrame for those IPs and apply Isolation Forest
df_high = df[df['ip'].isin(high_request_ips)]
if not df_high.empty:
    X_high = preprocessor.fit_transform(df_high[features])  # Reuse preprocessor
    model.fit(X_high)
    df_high['is_anomalous'] = model.predict(X_high) == -1
    print(df_high[df_high['is_anomalous']])
else:
    print("No high-request IPs for ML refinement.")