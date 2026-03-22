import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from src.feature_extractor import FEATURE_COLS


class Preprocessor:
    """
    Converts feature dicts into a scaled numpy array.

    FIXED from uploaded version:
    - Import changed from 'src.feature_extractor' to 'feature_extractor'
      to work both as a standalone module and inside src/ package.
    - normalize_scores: detector already returns [0,1] scores in two-stage mode.
      Preprocessing now checks the score range before inverting to avoid
      double-normalization that would flip high scores to low and break severity.
    """

    def __init__(self):
        self.scaler       = StandardScaler()
        self.score_scaler = MinMaxScaler()
        self._fitted      = False

    def fit_transform(self, feature_dicts: list) -> np.ndarray:
        X = self._to_matrix(feature_dicts)
        X_scaled = self.scaler.fit_transform(X)
        self._fitted = True
        return X_scaled

    def transform(self, feature_dicts: list) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("Preprocessor has not been fitted yet. Call fit_transform() first.")
        X = self._to_matrix(feature_dicts)
        return self.scaler.transform(X)

    def normalize_scores(self, scores: np.ndarray, fit: bool = False) -> np.ndarray:
        """
        Normalize anomaly scores to [0, 1] where higher = more anomalous.

        IMPORTANT: In two-stage mode, baseline_trainer already returns scores
        in [0, 1] (blend of IF + RF probabilities). In single-stage mode it
        returns raw IF decision_function values (negative = anomalous).

        This method detects which case it is and handles both correctly:
        - Raw IF scores:    range is roughly [-0.5, 0.5], negative = anomalous
                            → invert and scale to [0, 1]
        - Blended scores:  already in [0, 1], higher = anomalous
                            → pass through as-is (no inversion needed)
        """
        scores = np.array(scores)

        # Detect if scores are already normalized [0, 1]
        already_normalized = (scores.min() >= 0.0 and scores.max() <= 1.0)

        if already_normalized:
            # Two-stage mode: scores are already [0,1], just return them
            return np.clip(scores, 0.0, 1.0)

        # Single-stage IF mode: invert (more negative = more anomalous → higher score)
        s = scores.reshape(-1, 1) * -1
        if fit:
            return self.score_scaler.fit_transform(s).flatten()
        try:
            return self.score_scaler.transform(s).flatten()
        except Exception:
            # Scaler not fitted yet — fit and transform
            return self.score_scaler.fit_transform(s).flatten()

    def save(self, path: str):
        joblib.dump({
            "scaler": self.scaler,
            "score_scaler": self.score_scaler,
            "fitted": self._fitted
        }, path)

    def load(self, path: str):
        obj = joblib.load(path)
        self.scaler       = obj["scaler"]
        self.score_scaler = obj["score_scaler"]
        self._fitted      = obj.get("fitted", True)

    def _to_matrix(self, feature_dicts: list) -> np.ndarray:
        return np.array(
            [[f.get(col, 0) for col in FEATURE_COLS] for f in feature_dicts],
            dtype=np.float64,
        )

    @property
    def feature_names(self) -> list:
        return FEATURE_COLS
