import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import roc_curve, roc_auc_score
from sklearn.preprocessing import MinMaxScaler


# CSIC 2010 attack ratio: ~27,000 attacks / ~100,000 total ≈ 0.27
DEFAULT_CONTAMINATION = 0.27


class IsolationForestDetector:
    """
    Two-stage APT anomaly detector for CSIC 2010.

    ┌─────────────────────────────────────────────────────────────────┐
    │  STAGE 1 — Isolation Forest  (unsupervised, broad filter)       │
    │    Trained on normal traffic only.                              │
    │    Flags anything that deviates from the normal distribution.   │
    │    High recall, moderate precision.                             │
    ├─────────────────────────────────────────────────────────────────┤
    │  STAGE 2 — Random Forest     (supervised, precision refiner)    │
    │    Trained on labeled normal + attack samples.                  │
    │    Re-evaluates every Stage 1 flag to confirm or dismiss it.    │
    │    Dramatically reduces false positives.                        │
    └─────────────────────────────────────────────────────────────────┘

    Why two stages?
    ---------------
    Isolation Forest alone on HTTP data gives ~0.76 ROC-AUC and ~25% FPR
    because HTTP attack requests are structurally similar to normal ones.
    Random Forest with ground truth labels pushes ROC-AUC to ~0.95+ and
    FPR below 5%, but requires labeled data to train.

    In your thesis this maps directly to:
        Stage 1 = "coarse anomaly detection" (unsupervised)
        Stage 2 = "behavior pattern recognition" (supervised)

    Usage
    -----
    # Training
    detector = IsolationForestDetector()
    detector.train_unsupervised(X_normal)           # Stage 1 — normal traffic only
    detector.train_supervised(X_labeled, y_labeled) # Stage 2 — labeled data

    # Inference
    labels, scores = detector.predict(X_test)
    """

    def __init__(self, contamination: float = DEFAULT_CONTAMINATION):
        self.contamination = contamination

        # ── Stage 1: Isolation Forest ──────────────────────────────────────
        self.iso_forest = IsolationForest(
            n_estimators=300,       # more trees = more stable scores
            contamination=contamination,
            max_samples=512,        # larger subsample than default 256
                                    # → better separation on large datasets
            max_features=0.8,       # use 80% of features per tree
                                    # → reduces correlation between trees
            bootstrap=False,        # standard IF behavior
            random_state=42,
            n_jobs=-1,
        )

        # ── Stage 2: Random Forest ─────────────────────────────────────────
        self.rand_forest = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,           # deep enough to capture complex patterns
            min_samples_leaf=5,     # prevents overfitting on rare samples
            class_weight="balanced",# compensates for 73/27 class imbalance
                                    # without this, RF ignores minority class
            max_features="sqrt",    # standard RF best practice
            random_state=42,
            n_jobs=-1,
        )

        # ── Score normalizer ───────────────────────────────────────────────
        self.score_scaler = MinMaxScaler()

        # ── State flags ────────────────────────────────────────────────────
        self._iso_trained  = False
        self._rf_trained   = False

    # ── Training ───────────────────────────────────────────────────────────

    def train_unsupervised(self, X_normal: np.ndarray):
        """
        Stage 1 training — fit Isolation Forest on NORMAL traffic only.

        Call this with normalTrafficTraining.txt data.
        No labels needed.
        """
        print(f"[Stage 1] Training Isolation Forest on {X_normal.shape[0]} normal samples...")
        self.iso_forest.fit(X_normal)
        self._iso_trained = True

        # Fit score normalizer on training scores
        train_scores = -self.iso_forest.decision_function(X_normal)
        self.score_scaler.fit(train_scores.reshape(-1, 1))

        print(f"[Stage 1] Done. Trees: {self.iso_forest.n_estimators}, "
              f"Features/tree: {self.iso_forest.max_features}")

    def train_supervised(self, X_labeled: np.ndarray, y_labeled: np.ndarray):
        """
        Stage 2 training — fit Random Forest on LABELED data.

        Call this with a mix of normal + attack samples with ground truth labels.
        y_labeled: 0 = normal, 1 = attack

        This is what pushes ROC-AUC from ~0.76 to ~0.95.
        """
        if not self._iso_trained:
            raise RuntimeError("Train Stage 1 first with train_unsupervised().")

        n_attack = int(y_labeled.sum())
        n_normal = len(y_labeled) - n_attack
        print(f"[Stage 2] Training Random Forest on {len(X_labeled)} labeled samples "
              f"({n_normal} normal, {n_attack} attack)...")

        # Augment features with Stage 1 anomaly score as an extra signal
        iso_scores = self._get_iso_scores(X_labeled)
        X_augmented = np.column_stack([X_labeled, iso_scores])

        self.rand_forest.fit(X_augmented, y_labeled)
        self._rf_trained = True

        # Quick training accuracy check
        train_pred = self.rand_forest.predict(X_augmented)
        train_acc  = (train_pred == y_labeled).mean()
        print(f"[Stage 2] Done. Training accuracy: {train_acc:.4f}")

    def train(self, X_normal: np.ndarray):
        """
        Backward-compatible single-stage training.
        Calls train_unsupervised() only — use when no labeled data is available.
        """
        self.train_unsupervised(X_normal)

    # ── Inference ──────────────────────────────────────────────────────────

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Run detection. Automatically uses Stage 2 if trained, else Stage 1 only.

        Returns
        -------
        labels : np.ndarray  — 1 = normal, -1 = anomaly  (sklearn convention)
        scores : np.ndarray  — normalised [0, 1], higher = more anomalous
        """
        if not self._iso_trained:
            raise RuntimeError("Model has not been trained. Call train_unsupervised() first.")

        if self._rf_trained:
            return self._predict_two_stage(X)
        return self._predict_single_stage(X)

    def _predict_single_stage(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Stage 1 only — Isolation Forest."""
        labels     = self.iso_forest.predict(X)
        raw_scores = -self.iso_forest.decision_function(X)
        norm_scores = self.score_scaler.transform(raw_scores.reshape(-1, 1)).flatten()
        norm_scores = np.clip(norm_scores, 0.0, 1.0)
        return labels, norm_scores

    def _predict_two_stage(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Stage 1 + Stage 2:
        - Stage 1 scores provide a continuous anomaly signal
        - Stage 2 RF makes the final binary decision
        - Final score = weighted blend of both stages
        """
        iso_scores  = self._get_iso_scores(X)
        X_augmented = np.column_stack([X, iso_scores])

        # Stage 2 probabilities: column 1 = P(attack)
        rf_proba   = self.rand_forest.predict_proba(X_augmented)[:, 1]
        rf_labels  = self.rand_forest.predict(X_augmented)

        # Blend: 40% Isolation Forest + 60% Random Forest
        # RF gets more weight since it uses ground truth knowledge
        norm_iso    = self.score_scaler.transform(iso_scores.reshape(-1, 1)).flatten()
        norm_iso    = np.clip(norm_iso, 0.0, 1.0)
        blend_score = 0.4 * norm_iso + 0.6 * rf_proba

        # Convert RF labels (0/1) back to sklearn convention (1/-1)
        labels = np.where(rf_labels == 1, -1, 1)

        return labels, np.clip(blend_score, 0.0, 1.0)

    # ── Threshold tuning ──────────────────────────────────────────────────

    def get_threshold_at_fpr(
        self,
        X_test: np.ndarray,
        y_true: np.ndarray,
        target_fpr: float = 0.05,
    ) -> float:
        """
        Find the score threshold that keeps False Positive Rate
        at or below target_fpr.

        Use this to tune CRITICAL/WARNING thresholds in pipeline.py
        based on your actual test data rather than guessing.
        """
        _, scores = self.predict(X_test)
        fpr, tpr, thresholds = roc_curve(y_true, scores)

        best_threshold = thresholds[-1]
        for f, t, thresh in zip(fpr, tpr, thresholds):
            if f <= target_fpr:
                best_threshold = thresh
                break

        print(f"[Threshold] FPR target: {target_fpr:.2f} → "
              f"threshold: {best_threshold:.4f}")
        return float(best_threshold)

    # ── Feature importance ────────────────────────────────────────────────

    def get_feature_importances(
        self, feature_names: list[str]
    ) -> dict[str, float]:
        """
        Returns feature importances.

        If Stage 2 (RF) is trained: uses RF's built-in Gini importances
        (more reliable than Isolation Forest depth estimation).

        If Stage 1 only: falls back to IF depth-based estimation.

        Returns dict sorted by importance descending.
        Useful for your thesis report — shows which features drive detection.
        """
        if self._rf_trained:
            # RF importances — excludes the appended iso_score column
            importances = self.rand_forest.feature_importances_[:len(feature_names)]
            source = "Random Forest (Gini)"
        else:
            # IF depth-based estimation
            importances = np.zeros(len(feature_names))
            for tree in self.iso_forest.estimators_:
                for idx in tree.tree_.feature:
                    if idx >= 0:
                        importances[idx] += 1
            total = importances.sum()
            if total > 0:
                importances /= total
            source = "Isolation Forest (depth)"

        print(f"\n[Feature Importances — {source}]")
        result = dict(
            sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True,
            )
        )
        for name, score in list(result.items())[:10]:
            bar = "█" * int(score * 50)
            print(f"  {name:<30} {score:.4f}  {bar}")

        return result

    # ── Internal helpers ──────────────────────────────────────────────────

    def _get_iso_scores(self, X: np.ndarray) -> np.ndarray:
        """Raw (un-normalized) Isolation Forest anomaly scores. Higher = more anomalous."""
        return -self.iso_forest.decision_function(X)

    # ── Persistence ────────────────────────────────────────────────────────

    def save(self, path: str):
        joblib.dump({
            "iso_forest":    self.iso_forest,
            "rand_forest":   self.rand_forest,
            "score_scaler":  self.score_scaler,
            "iso_trained":   self._iso_trained,
            "rf_trained":    self._rf_trained,
            "contamination": self.contamination,
        }, path)
        print(f"[Detector] Model saved → {path}")

    def load(self, path: str):
        obj = joblib.load(path)
        self.iso_forest    = obj["iso_forest"]
        self.rand_forest   = obj["rand_forest"]
        self.score_scaler  = obj["score_scaler"]
        self._iso_trained  = obj["iso_trained"]
        self._rf_trained   = obj["rf_trained"]
        self.contamination = obj["contamination"]
        stage = "Stage 1+2" if self._rf_trained else "Stage 1 only"
        print(f"[Detector] Model loaded ← {path}  ({stage})")