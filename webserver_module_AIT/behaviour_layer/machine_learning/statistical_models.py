import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json
from typing import Callable

class Layer2AnomalyEnsemble:
    def __init__(self):
        self.iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
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

    def train_baseline(self, csv_path: str, output_csv_path: str, model_dir: str, status_callback: Callable = None):
        if status_callback: status_callback("iForest & SVM: Fitting new baseline models...", 60)
        df = pd.read_csv(csv_path)
        if df.empty: return

        os.makedirs(model_dir, exist_ok=True)

        geo_map = {}
        if 'geo_country' in df.columns:
            geo_map = df['geo_country'].value_counts(normalize=True).to_dict()
            df['geo_country_freq'] = df['geo_country'].map(geo_map)
            with open(os.path.join(model_dir, 'geo_map.json'), 'w') as f:
                json.dump(geo_map, f)
        else:
            df['geo_country_freq'] = 1.0

        for col in self.feature_cols:
            if col not in df.columns: df[col] = 0.0

        X = df[self.feature_cols].fillna(0)
        X_scaled = self.scaler.fit_transform(X)

        self.iso_forest.fit(X_scaled)
        self.ocsvm.fit(X_scaled)

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

        joblib.dump(self.iso_forest, os.path.join(model_dir, 'isolation_forest.joblib'))
        joblib.dump(self.ocsvm, os.path.join(model_dir, 'one_class_svm.joblib'))
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.joblib'))

        self._format_output(df, output_csv_path)

    def score_live(self, csv_path: str, output_csv_path: str, model_dir: str, status_callback: Callable = None):
        if status_callback: status_callback("iForest & SVM: Scoring session anomalies...", 65)
        df = pd.read_csv(csv_path)
        if df.empty: return

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
            raise FileNotFoundError(f"Missing models for scoring. Did you train a baseline first? Details: {e}")

        if 'geo_country' in df.columns:
            df['geo_country_freq'] = df['geo_country'].map(geo_map).fillna(0.0001)
        else:
            df['geo_country_freq'] = 1.0

        for col in self.feature_cols:
            if col not in df.columns: df[col] = 0.0

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

        self._format_output(df, output_csv_path)