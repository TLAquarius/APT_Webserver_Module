import json
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score,
)


class Evaluator:
    """
    Full evaluation suite for the APT detection pipeline.

    Improvements over the original one-liner:
    - Returns a structured metrics dict (not just prints).
    - Computes False Positive Rate explicitly (required by thesis).
    - Computes ROC-AUC and PR-AUC for model comparison.
    - Generates and saves ROC curve, PR curve, and Confusion Matrix plots.
    - Saves all metrics to JSON for your thesis report.
    """

    def evaluate(
        self,
        y_true: list | np.ndarray,
        y_pred: list | np.ndarray,
        y_scores: list | np.ndarray = None,
    ) -> dict:
        """
        Parameters
        ----------
        y_true   : ground truth labels  (0=normal, 1=attack)
        y_pred   : predicted labels     (0=normal, 1=attack)
                   Note: convert sklearn's  1/-1 convention to 1/0 before passing.
        y_scores : continuous anomaly scores [0,1], higher = more anomalous.
                   Required for ROC-AUC. Pass normalized scores from Preprocessor.

        Returns
        -------
        dict with all metrics.
        """
        y_true  = np.array(y_true)
        y_pred  = np.array(y_pred)

        # ── Classification report ──────────────────────────────────────────
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

        # ── Confusion matrix ───────────────────────────────────────────────
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

        fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0.0   # False Positive Rate
        fnr_val = fn / (fn + tp) if (fn + tp) > 0 else 0.0   # False Negative Rate

        metrics = {
            # Per-class metrics
            "precision_attack":  round(report.get("1", {}).get("precision", 0), 4),
            "recall_attack":     round(report.get("1", {}).get("recall", 0), 4),
            "f1_attack":         round(report.get("1", {}).get("f1-score", 0), 4),
            "precision_normal":  round(report.get("0", {}).get("precision", 0), 4),
            "recall_normal":     round(report.get("0", {}).get("recall", 0), 4),
            "f1_normal":         round(report.get("0", {}).get("f1-score", 0), 4),
            # Overall
            "accuracy":          round(report.get("accuracy", 0), 4),
            # Thesis-required metrics
            "false_positive_rate": round(fpr_val, 4),
            "false_negative_rate": round(fnr_val, 4),
            # Raw counts
            "true_positives":    int(tp),
            "true_negatives":    int(tn),
            "false_positives":   int(fp),
            "false_negatives":   int(fn),
        }

        # ── AUC metrics (only if scores provided) ─────────────────────────
        if y_scores is not None:
            y_scores = np.array(y_scores)
            metrics["roc_auc"]  = round(roc_auc_score(y_true, y_scores), 4)
            metrics["pr_auc"]   = round(average_precision_score(y_true, y_scores), 4)

        # ── Print summary ─────────────────────────────────────────────────
        self._print_summary(metrics)

        return metrics

    # ── Plotting ───────────────────────────────────────────────────────────

    def plot_roc_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        save_path: str = "roc_curve.png",
    ):
        """Generate and save ROC curve plot."""
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        auc = roc_auc_score(y_true, y_scores)

        plt.figure(figsize=(7, 5))
        plt.plot(fpr, tpr, color="steelblue", lw=2, label=f"ROC (AUC = {auc:.3f})")
        plt.plot([0, 1], [0, 1], "k--", lw=1)
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate (Detection Rate)")
        plt.title("ROC Curve — APT Anomaly Detection")
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.close()
        print(f"[Evaluator] ROC curve saved → {save_path}")

    def plot_pr_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        save_path: str = "pr_curve.png",
    ):
        """Generate and save Precision-Recall curve plot."""
        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        ap = average_precision_score(y_true, y_scores)

        plt.figure(figsize=(7, 5))
        plt.plot(recall, precision, color="darkorange", lw=2, label=f"PR (AP = {ap:.3f})")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall Curve — APT Anomaly Detection")
        plt.legend(loc="upper right")
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.close()
        print(f"[Evaluator] PR curve saved → {save_path}")

    def plot_confusion_matrix(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        save_path: str = "confusion_matrix.png",
    ):
        """Generate and save a labelled confusion matrix plot."""
        cm = confusion_matrix(y_true, y_pred)
        labels = ["Normal", "Attack"]

        fig, ax = plt.subplots(figsize=(5, 4))
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        plt.colorbar(im, ax=ax)
        ax.set(
            xticks=[0, 1], yticks=[0, 1],
            xticklabels=labels, yticklabels=labels,
            xlabel="Predicted Label",
            ylabel="True Label",
            title="Confusion Matrix — APT Detection",
        )
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]),
                        ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black",
                        fontsize=14)
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.close()
        print(f"[Evaluator] Confusion matrix saved → {save_path}")

    # ── Persistence ────────────────────────────────────────────────────────

    def save_metrics(self, metrics: dict, path: str = "metrics.json"):
        """Save metrics dict to JSON for your thesis report."""
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"[Evaluator] Metrics saved → {path}")

    # ── Internal ───────────────────────────────────────────────────────────

    def _print_summary(self, m: dict):
        print("\n" + "=" * 50)
        print("  APT DETECTION EVALUATION RESULTS")
        print("=" * 50)
        print(f"  Accuracy              : {m['accuracy']:.4f}")
        print(f"  Precision (Attack)    : {m['precision_attack']:.4f}")
        print(f"  Recall    (Attack)    : {m['recall_attack']:.4f}")
        print(f"  F1-Score  (Attack)    : {m['f1_attack']:.4f}")
        print(f"  False Positive Rate   : {m['false_positive_rate']:.4f}")
        print(f"  False Negative Rate   : {m['false_negative_rate']:.4f}")
        if "roc_auc" in m:
            print(f"  ROC-AUC               : {m['roc_auc']:.4f}")
        if "pr_auc" in m:
            print(f"  PR-AUC                : {m['pr_auc']:.4f}")
        print(f"  TP={m['true_positives']}  TN={m['true_negatives']}"
              f"  FP={m['false_positives']}  FN={m['false_negatives']}")
        print("=" * 50 + "\n")
