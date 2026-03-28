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
        """
        Initializes the statistical anomaly detection ensemble.
        """
        self.iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        self.ocsvm = OneClassSVM(kernel='rbf', gamma='scale', nu=0.02)
        self.scaler = StandardScaler()

        self.feature_cols = [
            'is_external_ip', 'session_duration_sec', 'total_requests',
            'req_per_min', 'min_interarrival_sec', 'avg_uri_depth',
            'error_404_rate', 'error_403_rate', 'error_50x_rate', 'post_rate', 'rare_method_rate',
            'unique_path_ratio', 'static_asset_ratio', 'suspicious_ext_rate',
            'status_diversity', 'unique_uas', 'avg_payload_bytes', 'max_resp_bytes',
            'geo_country_freq', 'auth_attempt_rate', 'bytes_std_dev'
        ]

    def _normalize_anomaly_scores(self, scores, min_val, p99_val):
        """
        Maps raw anomaly scores to a 0-100 scale using the 99th percentile as the 50 midpoint.
        """
        denominator = (p99_val - min_val) if (p99_val - min_val) > 1e-6 else 1e-6
        norm = np.where(
            scores <= p99_val,
            ((scores - min_val) / denominator) * 50,
            50 + ((scores - p99_val) / denominator) * 50
        )
        return np.clip(norm, 0, 100)

    def _extract_anomaly_reasons(self, X_scaled):
        """
        Extracts the top deviating features based on their Z-scores to provide explainability.
        """
        top_reasons = []
        for i in range(len(X_scaled)):
            z_scores = X_scaled[i]
            abs_z_scores = np.abs(z_scores)

            top_3_indices = np.argsort(abs_z_scores)[-3:][::-1]

            reasons = []
            for idx in top_3_indices:
                val = z_scores[idx]
                if abs(val) > 2.0:
                    feat_name = self.feature_cols[idx]
                    reasons.append(f"{feat_name} ({val:+.1f}σ)")

            if reasons:
                top_reasons.append(" | ".join(reasons))
            else:
                top_reasons.append("Complex multi-dimensional anomaly")

        return top_reasons

    def _format_output(self, df, output_csv_path):
        """
        Filters and sorts the dataframe to output IDs, threat scores, and anomaly reasons.
        """
        output_cols = ['session_id', 'statistical_threat_score']
        if 'parent_tracking_id' in df.columns:
            output_cols.insert(1, 'parent_tracking_id')
        if 'anomaly_reasons' in df.columns:
            output_cols.append('anomaly_reasons')

        output_df = df[output_cols]
        output_df = output_df.sort_values(by='statistical_threat_score', ascending=False)
        output_df.to_csv(output_csv_path, index=False)
        return output_df

    def train_baseline(self, csv_path: str, output_csv_path: str, model_dir: str, status_callback: Callable = None):
        """
        Trains the models on benign data and records the 99th percentile thresholds.
        """
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

        iso_raw_scores = self.iso_forest.score_samples(X_scaled)
        ocsvm_raw_scores = self.ocsvm.score_samples(X_scaled)

        iso_anomaly_scores = -iso_raw_scores.reshape(-1, 1).flatten()
        ocsvm_anomaly_scores = -ocsvm_raw_scores.reshape(-1, 1).flatten()

        iso_min = np.min(iso_anomaly_scores)
        iso_99th = np.percentile(iso_anomaly_scores, 99)
        ocsvm_min = np.min(ocsvm_anomaly_scores)
        ocsvm_99th = np.percentile(ocsvm_anomaly_scores, 99)

        normalized_iso = self._normalize_anomaly_scores(iso_anomaly_scores, iso_min, iso_99th)
        normalized_ocsvm = self._normalize_anomaly_scores(ocsvm_anomaly_scores, ocsvm_min, ocsvm_99th)

        df['statistical_threat_score'] = (normalized_iso + normalized_ocsvm) / 2
        df['statistical_threat_score'] = df['statistical_threat_score'].round(2)
        df['anomaly_reasons'] = self._extract_anomaly_reasons(X_scaled)

        joblib.dump(self.iso_forest, os.path.join(model_dir, 'isolation_forest.joblib'))
        joblib.dump(self.ocsvm, os.path.join(model_dir, 'one_class_svm.joblib'))
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.joblib'))

        thresholds = {
            'iso_min': float(iso_min), 'iso_99th': float(iso_99th),
            'ocsvm_min': float(ocsvm_min), 'ocsvm_99th': float(ocsvm_99th)
        }
        with open(os.path.join(model_dir, 'stat_thresholds.json'), 'w') as f:
            json.dump(thresholds, f)

        self._format_output(df, output_csv_path)

    def score_live(self, csv_path: str, output_csv_path: str, model_dir: str, status_callback: Callable = None):
        """
        Scores new sessions against the previously established baseline thresholds.
        """
        if status_callback: status_callback("iForest & SVM: Scoring session anomalies...", 65)
        df = pd.read_csv(csv_path)
        if df.empty: return

        try:
            iso_forest = joblib.load(os.path.join(model_dir, 'isolation_forest.joblib'))
            ocsvm = joblib.load(os.path.join(model_dir, 'one_class_svm.joblib'))
            scaler = joblib.load(os.path.join(model_dir, 'scaler.joblib'))

            with open(os.path.join(model_dir, 'stat_thresholds.json'), 'r') as f:
                thresh = json.load(f)

            with open(os.path.join(model_dir, 'geo_map.json'), 'r') as f:
                geo_map = json.load(f)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Missing models. Did you train a baseline first? Details: {e}")

        if 'geo_country' in df.columns:
            df['geo_country_freq'] = df['geo_country'].map(geo_map).fillna(0.0001)
        else:
            df['geo_country_freq'] = 1.0

        for col in self.feature_cols:
            if col not in df.columns: df[col] = 0.0

        X = df[self.feature_cols].fillna(0)
        X_scaled = scaler.transform(X)

        iso_raw_scores = iso_forest.score_samples(X_scaled)
        ocsvm_raw_scores = ocsvm.score_samples(X_scaled)

        iso_anomaly_scores = -iso_raw_scores.reshape(-1, 1).flatten()
        ocsvm_anomaly_scores = -ocsvm_raw_scores.reshape(-1, 1).flatten()

        normalized_iso = self._normalize_anomaly_scores(iso_anomaly_scores, thresh['iso_min'], thresh['iso_99th'])
        normalized_ocsvm = self._normalize_anomaly_scores(ocsvm_anomaly_scores, thresh['ocsvm_min'],
                                                          thresh['ocsvm_99th'])

        df['statistical_threat_score'] = (normalized_iso + normalized_ocsvm) / 2
        df['statistical_threat_score'] = df['statistical_threat_score'].round(2)
        df['anomaly_reasons'] = self._extract_anomaly_reasons(X_scaled)

        self._format_output(df, output_csv_path)