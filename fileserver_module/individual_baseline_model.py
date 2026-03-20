"""
=============================================================================
Module: IndividualBaselineModel — Isolation Forest Anomaly Detection
=============================================================================

Purpose:
    Implements the "Individual User Baseline" — a per-user anomaly detection
    model using ``scikit-learn``'s ``IsolationForest`` algorithm.

    The baseline learns what **normal** looks like for a specific user by
    training on their historical behavioral feature vectors.  At inference
    time, new feature vectors that deviate significantly from this learned
    normal produce high anomaly scores, indicating potential account
    compromise or insider threat activity.

Why Isolation Forest (not Z-score):
    Traditional Z-score anomaly detection assumes data follows a Gaussian
    (normal) distribution and operates poorly in high-dimensional spaces.
    Windows Event Log data is inherently non-Gaussian: it is noisy,
    heavy-tailed, and contains correlated features.  Isolation Forest is a
    **non-parametric** ensemble method that:

      • Works directly on the data's actual distribution without assumptions.
      • Scales linearly with data size — O(n·t·ψ) where t = trees, ψ = sample.
      • Handles high-dimensional feature spaces gracefully.
      • Isolates anomalies by *path length*, not distance metrics.

    Core Insight: Anomalies are "few and different" — they get isolated
    (partitioned into their own tree leaf) in fewer random splits than
    normal points.  A short average path length across the forest = anomaly.

Normalization Strategy:
    The raw ``decision_function`` output from Isolation Forest can range
    from negative (more anomalous) to positive (more normal).  We apply
    min-max normalization to map this to a **0–100 Anomaly Risk Score**:

      • 0 = completely normal (long path length, deep in trees)
      • 100 = extremely anomalous (short path length, quickly isolated)

    This score is designed for direct integration into a SOC dashboard
    where analysts need intuitive, comparable risk metrics.

Author:  UEBA Pipeline — Phase 1
Python:  3.9+
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Optional, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# Feature columns expected from UEBAFeatureExtractor
ML_FEATURE_COLUMNS: list[str] = [
    # Volume / Velocity
    "total_read_operations",
    "total_write_operations",
    "total_delete_operations",
    "total_events",
    "read_write_ratio",
    # Variety / Context
    "distinct_files_accessed",
    "distinct_processes_used",
    "admin_share_access_count",
    "lolbin_event_count",
    # Spatio-Temporal
    "off_hour_activity_ratio",
    "hour_sin",
    "hour_cos",
    # Authentication
    "successful_logon_count",
    "failed_logon_count",
    "failed_logon_ratio",
    "distinct_logon_source_ips",
    "explicit_credential_count",
    # Process Execution
    "new_process_count",
    "suspicious_process_count",
    "distinct_parent_processes",
    # Persistence
    "scheduled_task_created_count",
    "service_installed_count",
    # Anti-Forensics
    "audit_log_cleared_count",
    "object_deleted_count",
    # Network / Share
    "share_session_count",
    "distinct_shares_accessed",
]


class IndividualBaselineModel:
    """
    Per-user anomaly detection baseline using Isolation Forest.

    The model operates in two phases:

      1. **Fit (training)**: Learns the user's normal behavioral patterns
         from historical feature vectors (typically 14–30 days of data).
         Applies ``StandardScaler`` normalization before fitting.

      2. **Predict (inference)**: Evaluates new feature vectors against
         the learned baseline.  Returns a normalized Anomaly Risk Score
         (0–100) and a boolean anomaly flag.

    Parameters:
        contamination: Expected proportion of anomalies in training data.
            Lower values make the model more conservative (fewer false
            positives but may miss subtle attacks).  Default ``0.05``
            assumes ~5% of historical data may be mildly anomalous.
        n_estimators: Number of isolation trees in the ensemble.
            More trees → more stable scores, but slower.  Default: 200.
        random_state: Random seed for reproducibility.

    Example::

        model = IndividualBaselineModel(contamination=0.05)
        model.fit(user_a_historical_features)
        results = model.predict(user_a_new_features)
        print(results[["anomaly_score", "is_anomaly"]])
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        # Components initialized during fit()
        self._scaler: Optional[StandardScaler] = None
        self._model: Optional[IsolationForest] = None
        self._is_fitted: bool = False

        # Store training stats for explainability
        self._training_means: Optional[pd.Series] = None
        self._training_stds: Optional[pd.Series] = None
        self._feature_names: list[str] = ML_FEATURE_COLUMNS.copy()

        # Score normalization bounds (learned from training data)
        self._score_min: float = 0.0
        self._score_max: float = 1.0

        logger.info(
            "IndividualBaselineModel initialized — contamination=%.3f, "
            "n_estimators=%d, random_state=%d",
            contamination, n_estimators, random_state,
        )

    def fit(self, user_features: pd.DataFrame) -> "IndividualBaselineModel":
        """
        Train the baseline model on a user's historical feature matrix.

        The training pipeline:
          1. Extract and validate ML feature columns.
          2. Fit a ``StandardScaler`` to normalize volumetric features.
             This is critical because features like ``total_read_operations``
             (range: 0–10,000+) and ``off_hour_activity_ratio`` (range: 0–1)
             operate on vastly different scales.  Without scaling, the
             Isolation Forest's random splits would be dominated by
             high-magnitude features.
          3. Fit the Isolation Forest on scaled features.
          4. Compute score normalization bounds from training data.

        Args:
            user_features: DataFrame from ``UEBAFeatureExtractor.extract_features()``.
                Must contain all columns in ``ML_FEATURE_COLUMNS``.

        Returns:
            Self (for method chaining).

        Raises:
            ValueError: If the DataFrame is empty or missing required columns.
        """
        X = self._prepare_features(user_features)

        if len(X) < 5:
            raise ValueError(
                f"Insufficient training data: {len(X)} samples. "
                "Need at least 5 time-window vectors to establish a baseline. "
                "Consider using a longer training period or smaller time windows."
            )

        # Store training statistics for explainability
        self._training_means = X.mean()
        self._training_stds = X.std().replace(0, 1)  # Avoid div-by-zero

        # Step 1: Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Step 2: Train Isolation Forest
        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self._model.fit(X_scaled)

        # Step 3: Compute score normalization bounds
        # decision_function returns: negative = anomalous, positive = normal
        train_scores = self._model.decision_function(X_scaled)
        self._score_min = float(train_scores.min())
        self._score_max = float(train_scores.max())

        self._is_fitted = True

        logger.info(
            "Model fitted on %d samples. Score range: [%.4f, %.4f]",
            len(X), self._score_min, self._score_max,
        )

        return self

    def predict(self, new_features: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluate new feature vectors against the learned baseline.

        For each input row, computes:
          • ``anomaly_score``: Normalized 0–100 risk score.
            - 0 = perfectly normal (matches baseline patterns)
            - 100 = extreme anomaly (completely outside baseline)
          • ``is_anomaly``: Boolean flag from Isolation Forest thresholding.

        The score normalization uses the training data's score distribution
        to map the raw ``decision_function`` output to the 0–100 range.
        Scores beyond the training range are clipped to 0 or 100.

        Args:
            new_features: DataFrame with the same feature columns as training.

        Returns:
            Copy of the input DataFrame augmented with ``anomaly_score``
            and ``is_anomaly`` columns.

        Raises:
            RuntimeError: If the model has not been fitted yet.
        """
        if not self._is_fitted:
            raise RuntimeError(
                "Model has not been fitted yet. Call fit() first."
            )

        X = self._prepare_features(new_features)
        X_scaled = self._scaler.transform(X)

        # Raw decision function: negative = more anomalous
        raw_scores = self._model.decision_function(X_scaled)

        # Binary prediction: -1 = anomaly, 1 = normal
        predictions = self._model.predict(X_scaled)

        # Normalize to 0–100 Anomaly Risk Score
        # Invert: decision_function gives higher = more normal,
        # but we want higher = more anomalous for the dashboard
        anomaly_scores = self._normalize_scores(raw_scores)

        # Build result DataFrame
        result = new_features.copy()
        result["anomaly_score"] = np.round(anomaly_scores, 2)
        result["is_anomaly"] = predictions == -1
        result["raw_decision_score"] = np.round(raw_scores, 6)

        n_anomalies = (predictions == -1).sum()
        if n_anomalies > 0:
            logger.warning(
                "Detected %d anomalous time windows out of %d evaluated.",
                n_anomalies, len(X),
            )

        return result

    def _normalize_scores(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Convert raw Isolation Forest decision_function scores to a 0–100
        Anomaly Risk Score.

        The decision_function returns values where:
          • Positive = normal (long average path → hard to isolate)
          • Negative = anomalous (short average path → easy to isolate)

        We invert and scale to 0–100:
          • score_max (most normal training point) → 0 (no risk)
          • score_min (most anomalous training point) → ~95 (high risk)
          • Values beyond training range → clipped to 0 or 100

        Args:
            raw_scores: Array of decision_function outputs.

        Returns:
            Array of scores in [0, 100] range.
        """
        score_range = self._score_max - self._score_min
        if score_range == 0:
            # All training data had the same score (degenerate case)
            return np.full_like(raw_scores, 50.0)

        # Invert: lower raw score = higher anomaly risk
        normalized = (self._score_max - raw_scores) / score_range * 100.0
        return np.clip(normalized, 0.0, 100.0)

    def get_feature_importances(
        self, new_features: Optional[pd.DataFrame] = None
    ) -> pd.DataFrame:
        """
        Compute feature-level deviation analysis for explainability.

        For each feature, shows how the new data compares to the training
        baseline using Z-score-style deviations.  This helps SOC analysts
        understand *why* a particular time window was flagged.

        Args:
            new_features: DataFrame to analyze (if None, returns training stats).

        Returns:
            DataFrame with columns: feature, training_mean, training_std,
            current_value (if new_features provided), z_deviation.
        """
        if not self._is_fitted:
            raise RuntimeError("Model has not been fitted yet.")

        result = pd.DataFrame({
            "feature": self._feature_names,
            "training_mean": [self._training_means[f] for f in self._feature_names],
            "training_std": [self._training_stds[f] for f in self._feature_names],
        })

        if new_features is not None and not new_features.empty:
            X = self._prepare_features(new_features)
            latest = X.iloc[-1]  # Analyze the most recent window
            result["current_value"] = [latest[f] for f in self._feature_names]
            result["z_deviation"] = [
                abs(latest[f] - self._training_means[f]) / self._training_stds[f]
                for f in self._feature_names
            ]
            result.sort_values("z_deviation", ascending=False, inplace=True)

        return result

    def _prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract and validate ML feature columns from input DataFrame.

        Args:
            df: DataFrame that should contain all ``ML_FEATURE_COLUMNS``.

        Returns:
            DataFrame with only the ML feature columns, NaN filled with 0.

        Raises:
            ValueError: If required feature columns are missing.
        """
        missing = set(self._feature_names) - set(df.columns)
        if missing:
            raise ValueError(
                f"Missing feature columns: {sorted(missing)}. "
                f"Expected: {self._feature_names}"
            )

        X = df[self._feature_names].copy()
        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        return X

    def save_model(self, file_path: str) -> None:
        """
        Serialize the fitted model to disk for later reuse.

        Saves the complete state: scaler, model, normalization bounds,
        and training statistics.

        Args:
            file_path: Path for the output pickle file.
        """
        if not self._is_fitted:
            raise RuntimeError("Cannot save an unfitted model.")

        state = {
            "scaler": self._scaler,
            "model": self._model,
            "score_min": self._score_min,
            "score_max": self._score_max,
            "training_means": self._training_means,
            "training_stds": self._training_stds,
            "feature_names": self._feature_names,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
        }
        with open(file_path, "wb") as f:
            pickle.dump(state, f)
        logger.info("Model saved to %s", file_path)

    @classmethod
    def load_model(cls, file_path: str) -> "IndividualBaselineModel":
        """
        Load a previously saved model from disk.

        Args:
            file_path: Path to the pickle file.

        Returns:
            A fitted ``IndividualBaselineModel`` instance.
        """
        with open(file_path, "rb") as f:
            state = pickle.load(f)

        model = cls(
            contamination=state["contamination"],
            n_estimators=state["n_estimators"],
        )
        model._scaler = state["scaler"]
        model._model = state["model"]
        model._score_min = state["score_min"]
        model._score_max = state["score_max"]
        model._training_means = state["training_means"]
        model._training_stds = state["training_stds"]
        model._feature_names = state["feature_names"]
        model._is_fitted = True

        logger.info("Model loaded from %s", file_path)
        return model
