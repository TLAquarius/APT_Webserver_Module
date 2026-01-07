import re
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import warnings
warnings.filterwarnings('ignore')

class IsolationForestLogDetector:
    def __init__(self, log_file):
        self.log_file = log_file
        self.pattern = re.compile(
            r'(?P<ip>[\d.]+) - - \[(?P<datetime>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[\d.]+" '
            r'(?P<status>\d+) (?P<size>\d+|-) "(?P<referer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = []
        
    def parse_logs(self):
        """Parse Apache logs into structured DataFrame"""
        print("Parsing log file...")
        entries = []
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                match = self.pattern.match(line)
                if match:
                    entries.append(match.groupdict())
                    
        df = pd.DataFrame(entries)
        print(f"✓ Parsed {len(df)} log entries successfully")
        return df
    
    def extract_features(self, df):
        """Engineer comprehensive features for Isolation Forest"""
        print("\nExtracting features...")
        features = pd.DataFrame()
        
        # === IP-based features ===
        ip_counts = df['ip'].value_counts()
        features['ip_request_count'] = df['ip'].map(ip_counts)
        features['ip_frequency_rank'] = df['ip'].map(ip_counts.rank(method='dense'))
        
        # === Time-based features ===
        df['dt'] = pd.to_datetime(df['datetime'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        features['hour'] = df['dt'].dt.hour
        features['day_of_week'] = df['dt'].dt.dayofweek
        features['is_weekend'] = (df['dt'].dt.dayofweek >= 5).astype(int)
        features['is_night'] = ((df['dt'].dt.hour >= 22) | (df['dt'].dt.hour <= 6)).astype(int)
        features['is_business_hours'] = ((df['dt'].dt.hour >= 9) & (df['dt'].dt.hour <= 17)).astype(int)
        
        # === Request method features ===
        features['method_get'] = (df['method'] == 'GET').astype(int)
        features['method_post'] = (df['method'] == 'POST').astype(int)
        features['method_head'] = (df['method'] == 'HEAD').astype(int)
        features['method_rare'] = (~df['method'].isin(['GET', 'POST', 'HEAD'])).astype(int)
        
        # === Status code features ===
        features['status'] = df['status'].astype(int)
        features['is_success'] = (features['status'] == 200).astype(int)
        features['is_redirect'] = ((features['status'] >= 300) & (features['status'] < 400)).astype(int)
        features['is_client_error'] = ((features['status'] >= 400) & (features['status'] < 500)).astype(int)
        features['is_server_error'] = (features['status'] >= 500).astype(int)
        features['is_not_found'] = (features['status'] == 404).astype(int)
        features['is_forbidden'] = (features['status'] == 403).astype(int)
        
        # === Response size features ===
        df['size_clean'] = pd.to_numeric(df['size'], errors='coerce').fillna(0)
        features['response_size'] = df['size_clean']
        features['response_size_log'] = np.log1p(df['size_clean'])
        features['response_size_kb'] = df['size_clean'] / 1024
        features['is_empty_response'] = (df['size_clean'] == 0).astype(int)
        features['is_large_response'] = (df['size_clean'] > 1000000).astype(int)  # > 1MB
        
        # === Path analysis features ===
        features['path_length'] = df['path'].str.len()
        features['path_depth'] = df['path'].str.count('/')
        features['has_query_params'] = df['path'].str.contains(r'\?', na=False).astype(int)
        features['query_param_count'] = df['path'].str.count('&')
        features['has_extension'] = df['path'].str.contains(r'\.[a-z]{2,4}$', case=False, na=False).astype(int)
        
        # === Suspicious pattern features ===
        features['suspicious_chars'] = df['path'].str.count(r'[<>"\';{}()\[\]]')
        features['has_sql_keywords'] = df['path'].str.contains(
            r'(union|select|insert|update|delete|drop|create|alter)', 
            case=False, na=False
        ).astype(int)
        features['has_script_tags'] = df['path'].str.contains(
            r'<script|javascript:|onerror=', 
            case=False, na=False
        ).astype(int)
        features['has_path_traversal'] = df['path'].str.contains(r'\.\.|%2e%2e', case=False, na=False).astype(int)
        features['has_null_byte'] = df['path'].str.contains(r'%00', na=False).astype(int)
        features['excessive_slashes'] = df['path'].str.count('//+')
        
        # === User agent features ===
        features['ua_length'] = df['user_agent'].str.len()
        features['is_empty_ua'] = (df['user_agent'] == '-').astype(int)
        features['is_bot'] = df['user_agent'].str.contains(
            r'bot|crawler|spider|scraper', 
            case=False, na=False
        ).astype(int)
        features['is_curl'] = df['user_agent'].str.contains(r'^curl', case=False, na=False).astype(int)
        features['is_python'] = df['user_agent'].str.contains(r'python', case=False, na=False).astype(int)
        
        # === Rate-based features (sliding window) ===
        if 'dt' in df.columns and df['dt'].notna().any():
            df_sorted = df.sort_values('dt').copy()
            
            # Group by IP and calculate time-based metrics
            df_sorted['time_diff'] = df_sorted.groupby('ip')['dt'].diff().dt.total_seconds()
            features['avg_request_interval'] = df_sorted.groupby('ip')['time_diff'].transform('mean').fillna(60)
            features['min_request_interval'] = df_sorted.groupby('ip')['time_diff'].transform('min').fillna(60)
            features['rapid_requests'] = (features['min_request_interval'] < 1).astype(int)
        
        # === Referer features ===
        features['has_referer'] = (df['referer'] != '-').astype(int)
        features['external_referer'] = df['referer'].str.contains(r'^https?://', na=False).astype(int)
        
        # Fill any remaining NaN values
        features = features.fillna(0)
        
        self.feature_names = features.columns.tolist()
        print(f"✓ Extracted {len(self.feature_names)} features")
        
        return features
    
    def train(self, contamination=0.05, n_estimators=200, max_samples='auto', random_state=42):
        """Train Isolation Forest model"""
        print("\n" + "="*60)
        print("TRAINING ISOLATION FOREST MODEL")
        print("="*60)
        
        # Parse and prepare data
        df = self.parse_logs()
        X = self.extract_features(df)
        
        # Scale features
        print("\nScaling features...")
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        print(f"\nTraining Isolation Forest...")
        print(f"  - Contamination: {contamination}")
        print(f"  - Estimators: {n_estimators}")
        print(f"  - Max samples: {max_samples}")
        
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
            verbose=0
        )
        
        self.model.fit(X_scaled)
        print("✓ Model trained successfully!")
        
        return df, X, X_scaled
    
    def detect_anomalies(self, df, X, X_scaled):
        """Detect anomalies and score all requests"""
        print("\nDetecting anomalies...")
        
        # Predict anomalies (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Create results DataFrame
        results = pd.DataFrame()
        results['ip'] = df['ip'].values
        results['datetime'] = df['datetime'].values
        results['method'] = df['method'].values
        results['path'] = df['path'].values
        results['status'] = df['status'].values
        results['size'] = df['size'].values
        results['user_agent'] = df['user_agent'].values
        
        results['is_anomaly'] = (predictions == -1).astype(int)
        results['anomaly_score'] = anomaly_scores
        results['anomaly_score_normalized'] = -anomaly_scores  # Flip sign for easier interpretation
        
        # Rank anomalies by score
        results['anomaly_rank'] = results['anomaly_score'].rank()
        
        print(f"✓ Detection complete!")
        
        return results
    
    def analyze_feature_importance(self, X, X_scaled, results, top_n=10):
        """Analyze which features contribute most to anomalies"""
        print("\nAnalyzing feature importance...")
        
        anomalies = results[results['is_anomaly'] == 1].index
        normal = results[results['is_anomaly'] == 0].index
        
        if len(anomalies) == 0:
            print("No anomalies detected for feature analysis")
            return None
        
        # Calculate mean absolute difference for each feature
        importance = {}
        for i, feature in enumerate(self.feature_names):
            anomaly_mean = X_scaled[anomalies, i].mean()
            normal_mean = X_scaled[normal, i].mean()
            importance[feature] = abs(anomaly_mean - normal_mean)
        
        # Sort by importance
        sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)
        
        print(f"\nTop {top_n} Most Important Features for Anomaly Detection:")
        print("-" * 60)
        for feature, score in sorted_features[:top_n]:
            print(f"  {feature:.<45} {score:.4f}")
        
        return sorted_features
    
    def print_report(self, results, top_n=20):
        """Print comprehensive anomaly detection report"""
        print("\n" + "="*80)
        print("ISOLATION FOREST ANOMALY DETECTION REPORT")
        print("="*80)
        
        total = len(results)
        anomalies = results[results['is_anomaly'] == 1].copy()
        n_anomalies = len(anomalies)
        
        print(f"\nTotal Requests: {total:,}")
        print(f"Anomalies Detected: {n_anomalies:,} ({n_anomalies/total*100:.2f}%)")
        print(f"Normal Requests: {total-n_anomalies:,} ({(total-n_anomalies)/total*100:.2f}%)")
        
        if n_anomalies == 0:
            print("\n✓ No anomalies detected - all traffic appears normal!")
            return anomalies
        
        # Sort by anomaly score
        anomalies = anomalies.sort_values('anomaly_score')
        
        print(f"\n{'='*80}")
        print(f"TOP {min(top_n, n_anomalies)} ANOMALOUS REQUESTS (Most Suspicious First)")
        print("="*80)
        
        for idx, (i, row) in enumerate(anomalies.head(top_n).iterrows(), 1):
            print(f"\n[{idx}] Anomaly Score: {row['anomaly_score']:.4f} (normalized: {row['anomaly_score_normalized']:.4f})")
            print(f"    IP: {row['ip']}")
            print(f"    Time: {row['datetime']}")
            print(f"    Request: {row['method']} {row['path'][:80]}")
            if len(row['path']) > 80:
                print(f"             ...{row['path'][-30:]}")
            print(f"    Status: {row['status']} | Size: {row['size']} bytes")
            print(f"    User-Agent: {row['user_agent'][:70]}")
        
        print("\n" + "="*80)
        print("ANOMALY PATTERNS")
        print("="*80)
        
        print("\nTop Anomalous IPs:")
        for ip, count in anomalies['ip'].value_counts().head(10).items():
            pct = count / n_anomalies * 100
            print(f"  {ip:.<30} {count:>4} anomalies ({pct:>5.1f}%)")
        
        print("\nAnomaly Distribution by Status Code:")
        for status, count in anomalies['status'].value_counts().head(10).items():
            pct = count / n_anomalies * 100
            print(f"  {status:.<30} {count:>4} anomalies ({pct:>5.1f}%)")
        
        print("\nAnomaly Distribution by HTTP Method:")
        for method, count in anomalies['method'].value_counts().items():
            pct = count / n_anomalies * 100
            print(f"  {method:.<30} {count:>4} anomalies ({pct:>5.1f}%)")
        
        print("\nMost Anomalous Paths:")
        for path, count in anomalies['path'].value_counts().head(10).items():
            print(f"  {path[:70]}")
            if len(path) > 70:
                print(f"  ...{path[-30:]}")
            print(f"    → {count} occurrences\n")
        
        print("="*80 + "\n")
        
        return anomalies
    
    def save_results(self, results, filename='isolation_forest_results.csv'):
        """Save detection results to CSV"""
        results.to_csv(filename, index=False)
        print(f"✓ Results saved to '{filename}'")
    
    def save_model_config(self, filename='model_config.json'):
        """Save model configuration and statistics"""
        config = {
            'model_type': 'IsolationForest',
            'features': self.feature_names,
            'n_features': len(self.feature_names),
            'contamination': self.model.contamination,
            'n_estimators': self.model.n_estimators,
            'max_samples': self.model.max_samples,
            'trained_at': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Model configuration saved to '{filename}'")


# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = IsolationForestLogDetector("web_log_baseline.log")
    
    # Train model (adjust contamination based on expected anomaly rate)
    # contamination=0.05 means expecting ~5% of requests to be anomalous
    df, X, X_scaled = detector.train(
        contamination=0.05,
        n_estimators=200,
        random_state=42
    )
    
    # Detect anomalies
    results = detector.detect_anomalies(df, X, X_scaled)
    
    # Analyze feature importance
    feature_importance = detector.analyze_feature_importance(X, X_scaled, results, top_n=15)
    
    # Print comprehensive report
    anomalies = detector.print_report(results, top_n=20)
    
    # Save results
    detector.save_results(results, 'anomaly_results.csv')
    detector.save_model_config('model_config.json')
    
    print("\n✓ Anomaly detection complete!")