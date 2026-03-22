MODEL_PARAMS = {
    "n_estimators": 300,
    "max_samples": "auto",
    "contamination": 0.08,
    "random_state": 42,
    "n_jobs": -1
}

MODEL_PATH = "output/trained_model.pkl"
THRESHOLD_PATH = "output/threshold.npy"

ANOMALY_OUTPUT = "output/anomaly_logs.csv"
BEHAVIOR_OUTPUT = "output/anomaly_report.json"

TAIL_PERCENTILE = 2