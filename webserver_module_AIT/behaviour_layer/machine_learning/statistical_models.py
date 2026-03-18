import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json


class Layer2AnomalyEnsemble:
    def __init__(self):
        # We set contamination to auto, but we will calculate our own strict percentile threshold later
        self.iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        # nu=0.02 means we expect about 2% outliers in normal traffic
        self.ocsvm = OneClassSVM(kernel='rbf', gamma='scale', nu=0.02)
        self.scaler = StandardScaler()

        self.feature_cols = [
            'is_external_ip', 'is_off_hours', 'session_duration_sec', 'total_requests',
            'req_per_min', 'min_interarrival_sec', 'avg_uri_depth',
            'error_404_rate', 'error_403_rate', 'error_50x_rate', 'post_rate', 'rare_method_rate',
            'unique_path_ratio', 'static_asset_ratio', 'suspicious_ext_rate',
            'status_diversity', 'unique_uas', 'avg_payload_bytes', 'max_resp_bytes',
            'geo_country_freq'
        ]

    def _format_output(self, df, output_csv_path):
        output_cols = ['session_id', 'statistical_threat_score', 'statistical_threat_level']
        if 'parent_tracking_id' in df.columns:
            output_cols.insert(1, 'parent_tracking_id')

        output_df = df[output_cols]
        output_df = output_df.sort_values(by='statistical_threat_score', ascending=False)
        output_df.to_csv(output_csv_path, index=False)
        return output_df

    def train_baseline(self, csv_path, output_csv_path, model_dir="models"):
        print(f"[*] [TRAIN MODE] Loading dataset from {csv_path}...")
        df = pd.read_csv(csv_path)

        if df.empty:
            print("[-] Dataset is empty. Cannot train models.")
            return

        os.makedirs(model_dir, exist_ok=True)

        geo_map = {}
        if 'geo_country' in df.columns:
            print("[*] Calculating Geographic Frequency Map...")
            geo_map = df['geo_country'].value_counts(normalize=True).to_dict()
            df['geo_country_freq'] = df['geo_country'].map(geo_map)
            with open(os.path.join(model_dir, 'geo_map.json'), 'w') as f:
                json.dump(geo_map, f)
        else:
            df['geo_country_freq'] = 1.0

        for col in self.feature_cols:
            if col not in df.columns:
                df[col] = 0.0

        X = df[self.feature_cols].fillna(0)

        print("[*] Scaling features and fitting models...")
        X_scaled = self.scaler.fit_transform(X)

        self.iso_forest.fit(X_scaled)
        self.ocsvm.fit(X_scaled)

        # --- THE FIX: STATIC PERCENTILE THRESHOLDS ---
        # Since the training data is "clean", we strictly define anomalies as the bottom 2% of scores.
        # This prevents the model from hallucinating anomalies in a perfectly flat dataset.
        iso_scores = self.iso_forest.score_samples(X_scaled)
        ocsvm_scores = self.ocsvm.score_samples(X_scaled)

        iso_threshold = np.percentile(iso_scores, 2)
        ocsvm_threshold = np.percentile(ocsvm_scores, 2)

        thresholds = {
            "iso_threshold": iso_threshold,
            "ocsvm_threshold": ocsvm_threshold
        }
        with open(os.path.join(model_dir, 'thresholds.json'), 'w') as f:
            json.dump(thresholds, f)

        print(f"  -> Locked iForest Threshold (2nd Percentile): {iso_threshold:.4f}")
        print(f"  -> Locked OCSVM Threshold   (2nd Percentile): {ocsvm_threshold:.4f}")

        df['iso_prediction'] = (iso_scores < iso_threshold).astype(int)
        df['ocsvm_prediction'] = (ocsvm_scores < ocsvm_threshold).astype(int)

        def calculate_threat(row):
            score = 0
            if row['iso_prediction'] == 1: score += 50
            if row['ocsvm_prediction'] == 1: score += 50
            if row.get('l1_alert_count', 0) > 0: score = 100
            return score

        df['statistical_threat_score'] = df.apply(calculate_threat, axis=1)
        df['statistical_threat_level'] = df['statistical_threat_score'].apply(
            lambda s: "CRITICAL" if s == 100 else ("SUSPICIOUS" if s == 50 else "NORMAL")
        )

        print(f"[*] Saving trained models to {model_dir}/...")
        joblib.dump(self.iso_forest, os.path.join(model_dir, 'isolation_forest.joblib'))
        joblib.dump(self.ocsvm, os.path.join(model_dir, 'one_class_svm.joblib'))
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.joblib'))

        output_df = self._format_output(df, output_csv_path)
        print(f"[+] Successfully saved Training Baseline Scores to {output_csv_path}")

    def score_live(self, csv_path, output_csv_path, model_dir="models"):
        print(f"[*] [LIVE SCORING MODE] Loading dataset from {csv_path}...")
        df = pd.read_csv(csv_path)

        if df.empty: return

        print(f"[*] Loading frozen models and thresholds from {model_dir}/...")
        try:
            iso_forest = joblib.load(os.path.join(model_dir, 'isolation_forest.joblib'))
            ocsvm = joblib.load(os.path.join(model_dir, 'one_class_svm.joblib'))
            scaler = joblib.load(os.path.join(model_dir, 'scaler.joblib'))

            with open(os.path.join(model_dir, 'thresholds.json'), 'r') as f:
                thresholds = json.load(f)
            iso_threshold = thresholds['iso_threshold']
            ocsvm_threshold = thresholds['ocsvm_threshold']

            with open(os.path.join(model_dir, 'geo_map.json'), 'r') as f:
                geo_map = json.load(f)
        except FileNotFoundError as e:
            print(f"[-] Error: Missing model files. Have you run train_baseline() yet? ({e})")
            return

        if 'geo_country' in df.columns:
            df['geo_country_freq'] = df['geo_country'].map(geo_map).fillna(0.0001)
        else:
            df['geo_country_freq'] = 1.0

        for col in self.feature_cols:
            if col not in df.columns:
                df[col] = 0.0

        X = df[self.feature_cols].fillna(0)
        X_scaled = scaler.transform(X)

        iso_scores = iso_forest.score_samples(X_scaled)
        ocsvm_scores = ocsvm.score_samples(X_scaled)

        df['iso_prediction'] = (iso_scores < iso_threshold).astype(int)
        df['ocsvm_prediction'] = (ocsvm_scores < ocsvm_threshold).astype(int)

        def calculate_threat(row):
            score = 0
            if row['iso_prediction'] == 1: score += 50
            if row['ocsvm_prediction'] == 1: score += 50
            if row.get('l1_alert_count', 0) > 0: score = 100
            return score

        df['statistical_threat_score'] = df.apply(calculate_threat, axis=1)
        df['statistical_threat_level'] = df['statistical_threat_score'].apply(
            lambda s: "CRITICAL" if s == 100 else ("SUSPICIOUS" if s == 50 else "NORMAL")
        )

        output_df = self._format_output(df, output_csv_path)
        print(f"[+] Successfully saved Live Scores to {output_csv_path}")
        print("\n=== LIVE STATISTICAL SCORING RESULTS ===")
        print(output_df['statistical_threat_level'].value_counts())
        print("========================================\n")


if __name__ == '__main__':
    import pandas as pd
    import json
    import os

    FULL_DATA_CSV = "../ml_features.csv"
    FULL_TIMELINES_JSON = "../session_timelines.json"
    CLEAN_TRAIN_CSV = "clean_train_features.csv"

    TRAIN_OUTPUT_CSV = "./scores/statistical_scores_baseline.csv"
    LIVE_OUTPUT_CSV = "./scores/statistical_scores_live.csv"

    print("\n[!] Preparing Data Split: Identifying dirty sessions by source file...")
    dirty_session_ids = set()

    with open(FULL_TIMELINES_JSON, 'r', encoding='utf-8') as f:
        for line in f:
            session = json.loads(line.strip())
            for event in session.get('timeline', []):
                event_id = event.get('event_id', '')
                if 'access.log.2' in event_id or 'error.log.2' in event_id:
                    dirty_session_ids.add(session['session_id'])
                    break

    print(f"[+] Found {len(dirty_session_ids)} dirty sessions to exclude.")

    df_full = pd.read_csv(FULL_DATA_CSV)
    df_clean = df_full[~df_full['session_id'].isin(dirty_session_ids)]
    df_clean.to_csv(CLEAN_TRAIN_CSV, index=False)
    print(f"[+] Clean training set saved ({len(df_clean)} normal sessions).")

    ensemble = Layer2AnomalyEnsemble()

    print("\n=== PHASE 1: TRAINING ON CLEAN BASELINE ===")
    ensemble.train_baseline(CLEAN_TRAIN_CSV, TRAIN_OUTPUT_CSV)

    print("\n=== PHASE 2: LIVE SCORING ON FULL DATASET ===")
    ensemble.score_live(FULL_DATA_CSV, LIVE_OUTPUT_CSV)

    if os.path.exists(CLEAN_TRAIN_CSV):
        os.remove(CLEAN_TRAIN_CSV)