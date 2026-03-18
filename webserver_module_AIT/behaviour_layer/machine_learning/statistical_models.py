import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import joblib
import os
import json
from typing import Callable


class Layer2AnomalyEnsemble:
    def __init__(self):
        self.iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        self.ocsvm = OneClassSVM(kernel='rbf', gamma='scale', nu=0.02)

        self.scaler = StandardScaler()
        # Thêm 2 bộ Scaler để chuẩn hóa điểm số của Model về thang 0-100
        self.iso_score_scaler = MinMaxScaler(feature_range=(0, 100))
        self.ocsvm_score_scaler = MinMaxScaler(feature_range=(0, 100))

        self.feature_cols = [
            'is_external_ip', 'is_off_hours', 'session_duration_sec', 'total_requests',
            'req_per_min', 'min_interarrival_sec', 'avg_uri_depth',
            'error_404_rate', 'error_403_rate', 'error_50x_rate', 'post_rate', 'rare_method_rate',
            'unique_path_ratio', 'static_asset_ratio', 'suspicious_ext_rate',
            'status_diversity', 'unique_uas', 'avg_payload_bytes', 'max_resp_bytes',
            'geo_country_freq'
        ]

    def _format_output(self, df, output_csv_path):
        # Tầng này giờ CHỈ trả về điểm (score), KHÔNG gán nhãn (level) nữa. Nhãn để Correlator lo.
        output_cols = ['session_id', 'statistical_threat_score']
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

        # 1. Huấn luyện Model
        self.iso_forest.fit(X_scaled)
        self.ocsvm.fit(X_scaled)

        # 2. Lấy điểm nguyên bản từ Model (score_samples trả về số âm, càng nhỏ càng bất thường)
        iso_raw_scores = self.iso_forest.score_samples(X_scaled)
        ocsvm_raw_scores = self.ocsvm.score_samples(X_scaled)

        # 3. Đảo ngược dấu để: Điểm Càng Cao = Càng Bất Thường
        iso_anomaly_scores = -iso_raw_scores.reshape(-1, 1)
        ocsvm_anomaly_scores = -ocsvm_raw_scores.reshape(-1, 1)

        # 4. Chuẩn hóa (Min-Max) cái điểm đó về đúng thang 0 -> 100
        normalized_iso = self.iso_score_scaler.fit_transform(iso_anomaly_scores).flatten()
        normalized_ocsvm = self.ocsvm_score_scaler.fit_transform(ocsvm_anomaly_scores).flatten()

        # 5. Điểm ML cuối cùng là trung bình cộng độ dị thường của 2 thuật toán
        df['statistical_threat_score'] = (normalized_iso + normalized_ocsvm) / 2
        df['statistical_threat_score'] = df['statistical_threat_score'].round(2)

        # 6. Lưu lại tất cả mô hình và các bộ Scaler để dùng cho pha Detect
        joblib.dump(self.iso_forest, os.path.join(model_dir, 'isolation_forest.joblib'))
        joblib.dump(self.ocsvm, os.path.join(model_dir, 'one_class_svm.joblib'))
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.joblib'))
        joblib.dump(self.iso_score_scaler, os.path.join(model_dir, 'iso_score_scaler.joblib'))
        joblib.dump(self.ocsvm_score_scaler, os.path.join(model_dir, 'ocsvm_score_scaler.joblib'))

        self._format_output(df, output_csv_path)

    def score_live(self, csv_path: str, output_csv_path: str, model_dir: str, status_callback: Callable = None):
        if status_callback: status_callback("iForest & SVM: Scoring session anomalies...", 65)
        df = pd.read_csv(csv_path)
        if df.empty: return

        try:
            iso_forest = joblib.load(os.path.join(model_dir, 'isolation_forest.joblib'))
            ocsvm = joblib.load(os.path.join(model_dir, 'one_class_svm.joblib'))
            scaler = joblib.load(os.path.join(model_dir, 'scaler.joblib'))
            iso_score_scaler = joblib.load(os.path.join(model_dir, 'iso_score_scaler.joblib'))
            ocsvm_score_scaler = joblib.load(os.path.join(model_dir, 'ocsvm_score_scaler.joblib'))

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

        # 1. Chấm điểm raw
        iso_raw_scores = iso_forest.score_samples(X_scaled)
        ocsvm_raw_scores = ocsvm.score_samples(X_scaled)

        # 2. Đảo dấu
        iso_anomaly_scores = -iso_raw_scores.reshape(-1, 1)
        ocsvm_anomaly_scores = -ocsvm_raw_scores.reshape(-1, 1)

        # 3. Chuẩn hóa về thang 0-100 dựa trên ranh giới đã học lúc Train
        normalized_iso = iso_score_scaler.transform(iso_anomaly_scores).flatten()
        normalized_ocsvm = ocsvm_score_scaler.transform(ocsvm_anomaly_scores).flatten()

        # 4. Ép giới hạn (phòng trường hợp live data dị thường hơn cả lúc train thì điểm vượt 100)
        normalized_iso = np.clip(normalized_iso, 0, 100)
        normalized_ocsvm = np.clip(normalized_ocsvm, 0, 100)

        # 5. Điểm cuối cùng (0 - 100)
        df['statistical_threat_score'] = (normalized_iso + normalized_ocsvm) / 2
        df['statistical_threat_score'] = df['statistical_threat_score'].round(2)

        self._format_output(df, output_csv_path)