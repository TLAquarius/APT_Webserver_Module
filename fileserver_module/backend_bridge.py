"""
=============================================================================
FileServerBridge — Backend Orchestrator for Streamlit Integration
=============================================================================

Mirrors the pattern of webserver_module_AIT/backend_bridge.py but adapted
for the File Server UEBA pipeline (FileServerLogParser → UEBAFeatureExtractor
→ IndividualBaselineModel).
"""

import os
import sys
import json
import hashlib
import pickle
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Ensure fileserver_module is on sys.path so sibling imports work
# ---------------------------------------------------------------------------
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from file_server_log_parser import FileServerLogParser
from ueba_feature_extractor import UEBAFeatureExtractor, FEATURE_COLUMNS
from individual_baseline_model import IndividualBaselineModel, ML_FEATURE_COLUMNS

logger = logging.getLogger("FileServerBridge")

# ---------- Window auto-selection (ported from main.py) ----------

_WINDOW_FALLBACK_CHAIN: list[tuple[str, float]] = [
    ("1h",   60.0),
    ("30min", 30.0),
    ("15min", 15.0),
    ("5min",  5.0),
    ("2min",  2.0),
    ("1min",  1.0),
    ("30s",   0.5),
]
MIN_WINDOWS_SPLIT_MODE = 6
MIN_WINDOWS_SINGLE_MODE = 5


def _select_optimal_window(span_minutes: float, requested_window: str) -> str:
    for window_str, window_min in _WINDOW_FALLBACK_CHAIN:
        if window_str == requested_window:
            expected = span_minutes / window_min if window_min > 0 else 999
            if expected >= MIN_WINDOWS_SPLIT_MODE:
                return requested_window
            break
    for window_str, window_min in _WINDOW_FALLBACK_CHAIN:
        if window_min <= 0:
            continue
        if span_minutes / window_min >= MIN_WINDOWS_SPLIT_MODE:
            return window_str
    return _WINDOW_FALLBACK_CHAIN[-1][0]


# ===================================================================
# FileServerBridge
# ===================================================================

class FileServerBridge:
    """Orchestrates the File Server UEBA pipeline for the Streamlit UI."""

    BASE_DATA_DIR = "./fileserver_module/module_data"

    def __init__(self, profile_name: str):
        self.profile_name = profile_name
        self.profile_dir = os.path.join(self.BASE_DATA_DIR, profile_name)
        self.raw_logs_dir = os.path.join(self.profile_dir, "raw_logs")
        self.models_dir = os.path.join(self.profile_dir, "models")
        self.results_dir = os.path.join(self.profile_dir, "results")

        for d in [self.raw_logs_dir, self.models_dir, self.results_dir]:
            os.makedirs(d, exist_ok=True)

        self.metadata_path = os.path.join(self.profile_dir, "metadata.json")
        if not os.path.exists(self.metadata_path):
            self._save_metadata([])

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @classmethod
    def get_all_profiles(cls) -> List[str]:
        if not os.path.isdir(cls.BASE_DATA_DIR):
            return []
        return [
            d for d in os.listdir(cls.BASE_DATA_DIR)
            if os.path.isdir(os.path.join(cls.BASE_DATA_DIR, d))
        ]

    @classmethod
    def create_profile(cls, name: str) -> bool:
        safe = "".join(c for c in name if c.isalnum() or c in ("_", "-")).strip()
        if not safe:
            return False
        path = os.path.join(cls.BASE_DATA_DIR, safe)
        if os.path.exists(path):
            return False
        os.makedirs(os.path.join(path, "raw_logs"), exist_ok=True)
        os.makedirs(os.path.join(path, "models"), exist_ok=True)
        os.makedirs(os.path.join(path, "results"), exist_ok=True)
        with open(os.path.join(path, "metadata.json"), "w") as f:
            json.dump([], f)
        return True

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def _load_metadata(self) -> List[Dict]:
        if not os.path.exists(self.metadata_path):
            return []
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def _save_metadata(self, metadata: List[Dict]):
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4, default=str)

    # ------------------------------------------------------------------
    # File ingestion
    # ------------------------------------------------------------------

    def ingest_file(self, uploaded_file) -> Dict:
        """Save an uploaded log file, compute MD5, record metadata."""
        file_bytes = uploaded_file.read()
        file_hash = hashlib.md5(file_bytes).hexdigest()

        metadata = self._load_metadata()
        for rec in metadata:
            if rec.get("file_hash") == file_hash:
                raise ValueError(
                    f"File '{uploaded_file.name}' đã tồn tại (trùng MD5)."
                )

        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{ts_str}_{uploaded_file.name}"
        physical_path = os.path.join(self.raw_logs_dir, safe_name)

        uploaded_file.seek(0)
        with open(physical_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        record = {
            "file_id": f"fs_{file_hash[:8]}_{ts_str}",
            "original_name": uploaded_file.name,
            "physical_path": physical_path,
            "file_hash": file_hash,
            "size_bytes": len(file_bytes),
            "upload_time": datetime.now().isoformat(),
            "status": "pending",
        }
        metadata.append(record)
        self._save_metadata(metadata)
        return record

    # ------------------------------------------------------------------
    # Delete helpers
    # ------------------------------------------------------------------

    def delete_profile(self):
        import shutil
        shutil.rmtree(self.profile_dir, ignore_errors=True)

    def delete_files(self, file_ids: List[str]):
        metadata = self._load_metadata()
        new_meta = []
        for rec in metadata:
            if rec["file_id"] in file_ids:
                p = rec.get("physical_path")
                if p and os.path.exists(p):
                    os.remove(p)
            else:
                new_meta.append(rec)
        self._save_metadata(new_meta)
        # Clear results since underlying data changed
        for fname in os.listdir(self.results_dir):
            os.remove(os.path.join(self.results_dir, fname))

    # ------------------------------------------------------------------
    # Pipeline execution
    # ------------------------------------------------------------------

    def run_pipeline(
        self,
        time_window: str = "1h",
        contamination: float = 0.05,
        train_ratio: float = 0.8,
        status_callback: Optional[Callable[[str, int], None]] = None,
    ) -> bool:
        """Run the full UEBA pipeline on all ingested files."""

        def _ui(msg: str, pct: int):
            if status_callback:
                status_callback(msg, pct)

        try:
            metadata = self._load_metadata()
            files = [
                f for f in metadata
                if os.path.exists(f.get("physical_path", ""))
            ]
            if not files:
                _ui("Không có file nào để phân tích.", 100)
                return False

            # Step 1: Parse all files
            _ui("1/4: Đang phân tích Log (Parsing)...", 10)
            all_dfs: list[pd.DataFrame] = []
            for rec in files:
                try:
                    parser = FileServerLogParser(rec["physical_path"])
                    df = parser.parse()
                    if not df.empty:
                        all_dfs.append(df)
                except Exception as e:
                    logger.warning("Skip file %s: %s", rec["original_name"], e)

            if not all_dfs:
                _ui("❌ Không tìm thấy Event hợp lệ trong các file đã nạp.", 100)
                return False

            parsed_df = pd.concat(all_dfs, ignore_index=True)
            parsed_df.sort_values("TimeCreated", inplace=True)
            parsed_df.reset_index(drop=True, inplace=True)

            total_events = len(parsed_df)
            n_users = parsed_df["SubjectUserName"].nunique()
            _ui(f"1/4: Đã phân tích {total_events:,} events từ {n_users} người dùng.", 20)

            # Step 2: Auto-adjust window & extract features
            ts = pd.to_datetime(parsed_df["TimeCreated"], errors="coerce").dropna()
            span_min = (ts.max() - ts.min()).total_seconds() / 60.0 if not ts.empty else 0
            optimal_window = _select_optimal_window(span_min, time_window)

            _ui(f"2/4: Trích xuất Đặc trưng (window={optimal_window})...", 30)
            extractor = UEBAFeatureExtractor(time_window=optimal_window)
            features_df = extractor.extract_features(parsed_df)

            if features_df.empty:
                _ui("❌ Không thể tạo Feature Vector. Dữ liệu quá ít.", 100)
                return False

            # Save features
            features_path = os.path.join(self.results_dir, "features.csv")
            features_df.to_csv(features_path, index=False)

            # Step 3: Train & predict per user
            _ui("3/4: Huấn luyện & Chấm điểm Anomaly (Isolation Forest)...", 50)
            users = features_df["SubjectUserName"].unique()
            all_results: list[dict] = []

            for i, user in enumerate(users):
                pct = 50 + int(40 * (i + 1) / len(users))
                _ui(f"3/4: Phân tích user {i+1}/{len(users)}: {user}", pct)

                user_data = (
                    features_df[features_df["SubjectUserName"] == user]
                    .sort_values("TimeWindow")
                    .reset_index(drop=True)
                )
                n_total = len(user_data)

                if n_total < MIN_WINDOWS_SINGLE_MODE:
                    all_results.append({
                        "user": user,
                        "total_windows": n_total,
                        "status": "skipped",
                        "reason": f"Chỉ có {n_total} cửa sổ (cần ≥ {MIN_WINDOWS_SINGLE_MODE})",
                        "anomaly_count": 0,
                        "max_score": 0.0,
                        "avg_score": 0.0,
                        "scores": [],
                        "top_features": [],
                    })
                    continue

                # Decide split vs single-batch
                if n_total >= MIN_WINDOWS_SPLIT_MODE:
                    split_idx = max(int(n_total * train_ratio), MIN_WINDOWS_SINGLE_MODE)
                    train_data = user_data.iloc[:split_idx]
                    test_data = user_data.iloc[split_idx:]
                    if test_data.empty:
                        train_data = user_data.iloc[: n_total - 1]
                        test_data = user_data.iloc[n_total - 1:]
                    mode_label = "split"
                else:
                    train_data = user_data
                    test_data = user_data
                    mode_label = "single-batch"

                model = IndividualBaselineModel(contamination=contamination)
                model.fit(train_data)
                results = model.predict(test_data)

                anomaly_count = int(results["is_anomaly"].sum())
                max_score = float(results["anomaly_score"].max())
                avg_score = float(results["anomaly_score"].mean())

                # Feature importance
                importance = model.get_feature_importances(test_data)
                top_feats = []
                for _, feat in importance.head(5).iterrows():
                    top_feats.append({
                        "feature": feat["feature"],
                        "z_deviation": round(float(feat.get("z_deviation", 0)), 2),
                        "training_mean": round(float(feat["training_mean"]), 2),
                        "training_std": round(float(feat["training_std"]), 2),
                        "current_value": round(float(feat.get("current_value", 0)), 2),
                    })

                # Per-window scores
                window_scores = []
                for _, row in results.iterrows():
                    window_scores.append({
                        "time_window": str(row["TimeWindow"]),
                        "anomaly_score": round(float(row["anomaly_score"]), 2),
                        "is_anomaly": bool(row["is_anomaly"]),
                    })

                # Save model
                model_path = os.path.join(self.models_dir, f"{user}.pkl")
                model.save_model(model_path)

                # Aggregate all 25 feature values (max across windows) for LLM context
                feature_values = {}
                for col in ML_FEATURE_COLUMNS:
                    if col in user_data.columns:
                        feature_values[col] = round(float(user_data[col].max()), 4)
                    else:
                        feature_values[col] = 0.0

                all_results.append({
                    "user": user,
                    "total_windows": n_total,
                    "status": "analyzed",
                    "mode": mode_label,
                    "anomaly_count": anomaly_count,
                    "max_score": round(max_score, 1),
                    "avg_score": round(avg_score, 1),
                    "scores": window_scores,
                    "top_features": top_feats,
                    "feature_values": feature_values,
                })

            # Step 4: Save results
            _ui("4/4: Lưu kết quả phân tích...", 95)
            results_path = os.path.join(self.results_dir, "analysis_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump({
                    "analysis_time": datetime.now().isoformat(),
                    "total_events": total_events,
                    "total_users": n_users,
                    "time_window": optimal_window,
                    "contamination": contamination,
                    "data_span_minutes": round(span_min, 1),
                    "user_results": all_results,
                }, f, indent=2, ensure_ascii=False, default=str)

            # Mark files as processed
            for rec in metadata:
                if rec.get("status") == "pending":
                    rec["status"] = "processed"
            self._save_metadata(metadata)

            _ui("Hoàn tất phân tích!", 100)
            return True

        except Exception as e:
            import traceback
            logger.error("Pipeline error: %s", traceback.format_exc())
            _ui(f"❌ Lỗi: {e}", 100)
            return False

    # ------------------------------------------------------------------
    # Dashboard data
    # ------------------------------------------------------------------

    def has_results(self) -> bool:
        return os.path.exists(
            os.path.join(self.results_dir, "analysis_results.json")
        )

    def compile_dashboard_data(self) -> Dict[str, Any]:
        """Load saved analysis results for the dashboard."""
        results_path = os.path.join(self.results_dir, "analysis_results.json")
        if not os.path.exists(results_path):
            return {}
        with open(results_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_features_df(self) -> Optional[pd.DataFrame]:
        """Load the saved feature matrix."""
        features_path = os.path.join(self.results_dir, "features.csv")
        if not os.path.exists(features_path):
            return None
        return pd.read_csv(features_path)
