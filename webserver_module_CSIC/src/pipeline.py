from src.csic_parser import CSICParser
from src.feature_extractor import FeatureExtractor
from src.preprocessing import Preprocessor
from src.baseline_trainer import IsolationForestDetector
from src.owasp_mapper import OWASPMapper
from src.timeline_analyzer import TimelineAnalyzer
from src.evaluator import Evaluator
import numpy as np


# Normalised score thresholds
THRESHOLD_CRITICAL = 0.70
THRESHOLD_WARNING  = 0.40


class CSICPipeline:
    """
    End-to-end APT detection pipeline.

    FIXED from uploaded version:
    - _parse_and_extract fallback no longer calls self.extractor.extract(parsed)
      recursively when an error occurs — now uses a static zero-dict instead,
      preventing infinite recursion on malformed requests.
    - train() no longer calls preprocessor.normalize_scores() with already-
      normalized scores from two-stage detector, avoiding double-normalization.
    - All imports use 'src.' prefix consistently.
    """

    def __init__(self, contamination: float = 0.27, session_gap_minutes: int = 10):
        self.parser       = CSICParser()
        self.extractor    = FeatureExtractor()
        self.preprocessor = Preprocessor()
        self.detector     = IsolationForestDetector(contamination=contamination)
        self.mapper       = OWASPMapper()
        self.timeline     = TimelineAnalyzer(session_gap_minutes=session_gap_minutes)
        self.evaluator    = Evaluator()

    # ── Training ───────────────────────────────────────────────────────────

    def train(self, records: list):
        """Stage 1 — unsupervised, normal traffic only."""
        print(f"[Pipeline] Stage 1 training on {len(records)} normal records...")
        features, _ = self._parse_and_extract(records)
        X_scaled = self.preprocessor.fit_transform(features)
        self.detector.train_unsupervised(X_scaled)

        # Fit score normalizer using raw IF scores from training data
        # NOTE: we call detector.iso_forest directly here to get raw scores
        # before two-stage blending, so the normalizer is fitted correctly
        raw_train_scores = -self.detector.iso_forest.decision_function(X_scaled)
        self.preprocessor.score_scaler.fit(raw_train_scores.reshape(-1, 1))

        print(f"[Pipeline] Stage 1 complete. Features: {len(features[0])} dims.")

    def train_supervised(self, labeled_records: list):
        """Stage 2 — supervised, requires labeled records (label=0 or label=1)."""
        print(f"[Pipeline] Stage 2 training on {len(labeled_records)} labeled records...")
        features, _ = self._parse_and_extract(labeled_records)
        X_scaled = self.preprocessor.transform(features)
        y = np.array([r.get("label", 0) for r in labeled_records])
        self.detector.train_supervised(X_scaled, y)
        print("[Pipeline] Stage 2 complete. Two-stage detection active.")

    # ── Inference ──────────────────────────────────────────────────────────

    def run(self, records: list) -> list:
        """Run detection. Returns one result dict per request."""
        print(f"[Pipeline] Running inference on {len(records)} records...")
        features, parsed_list = self._parse_and_extract(records)

        X_scaled            = self.preprocessor.transform(features)
        labels, norm_scores = self.detector.predict(X_scaled)

        # normalize_scores handles both raw IF and blended [0,1] scores correctly
        norm_scores = self.preprocessor.normalize_scores(norm_scores)

        results = []
        for record, parsed, feat, label, norm_score in zip(
            records, parsed_list, features, labels, norm_scores
        ):
            severity  = self._severity(label, norm_score)
            owasp_map = self.mapper.map(feat)

            results.append({
                "timestamp":   record.get("timestamp"),
                "url":         parsed.get("url", ""),
                "method":      parsed.get("method", ""),
                "body_raw":    parsed.get("body_raw", "")[:200],
                "label":       int(label),
                "is_attack":   label == -1,
                "score":       round(float(norm_score), 4),
                "severity":    severity,
                "owasp":       owasp_map["owasp"],
                "apt_phase":   owasp_map["apt_phase"],
                "confidence":  owasp_map["confidence"],
                "true_label":  record.get("label", -1),
                "parse_error": parsed.get("is_malformed", False),
            })

        return results

    # ── Evaluation ─────────────────────────────────────────────────────────

    def evaluate(self, results: list, output_dir: str = ".") -> dict:
        y_true   = [r["true_label"] for r in results if r["true_label"] != -1]
        y_pred   = [int(r["is_attack"]) for r in results if r["true_label"] != -1]
        y_scores = [r["score"] for r in results if r["true_label"] != -1]

        if not y_true:
            print("[Pipeline] No ground truth labels found. Skipping evaluation.")
            return {}

        metrics = self.evaluator.evaluate(y_true, y_pred, y_scores)
        self.evaluator.save_metrics(metrics,          f"{output_dir}/metrics.json")
        self.evaluator.plot_roc_curve(y_true, y_scores, f"{output_dir}/roc_curve.png")
        self.evaluator.plot_pr_curve(y_true, y_scores,  f"{output_dir}/pr_curve.png")
        self.evaluator.plot_confusion_matrix(y_true, y_pred, f"{output_dir}/confusion_matrix.png")
        return metrics

    # ── Timeline Analysis ──────────────────────────────────────────────────

    def analyze_timeline(self, results: list):
        timeline_df   = self.timeline.build_timeline(results)
        apt_chains_df = self.timeline.detect_apt_chains(timeline_df)
        self.timeline.summarize(timeline_df, apt_chains_df)
        return timeline_df, apt_chains_df

    # ── Persistence ────────────────────────────────────────────────────────

    def save(self, model_path: str = "model.pkl", scaler_path: str = "scaler.pkl"):
        self.detector.save(model_path)
        self.preprocessor.save(scaler_path)

    def load(self, model_path: str = "model.pkl", scaler_path: str = "scaler.pkl"):
        self.detector.load(model_path)
        self.preprocessor.load(scaler_path)

    # ── Internal ───────────────────────────────────────────────────────────

    def _parse_and_extract(self, records: list) -> tuple:
        from src.feature_extractor import FEATURE_COLS
        features    = []
        parsed_list = []

        for record in records:
            raw = record.get("raw", "")
            try:
                parsed = self.parser.parse_request(raw)
                feat   = self.extractor.extract(parsed)
            except Exception:
                # FIXED: use static zero-dict — not recursive extract() call
                parsed = {
                    "url": "", "method": "UNKNOWN", "body_raw": "",
                    "headers": {}, "is_malformed": True,
                    "query_params": {}, "body_params": {},
                    "content_type": "", "path": "",
                }
                feat = {col: 0 for col in FEATURE_COLS}
                feat["is_malformed"] = 1

            features.append(feat)
            parsed_list.append(parsed)

        return features, parsed_list

    def _severity(self, label: int, norm_score: float) -> str:
        if label == -1:
            return "CRITICAL" if norm_score >= THRESHOLD_CRITICAL else "WARNING"
        return "NORMAL"
