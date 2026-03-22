import argparse
import os
import pandas as pd
import numpy as np
import joblib

from config import *
from preprocessing.csv_preprocessor import CSVPreprocessor
from preprocessing.feature_engineering import FeatureEngineer
from models.isolation_forest_model import IsolationForestModel
from utils.export_json import export_anomaly_to_json

PREPROCESSOR_PATH = "output/preprocessor.pkl"

def train_pipeline(train_path):

    df = pd.read_csv(train_path)
    df.columns = df.columns.str.strip()

    df = FeatureEngineer.add_ratio_features(df)

    preprocessor = CSVPreprocessor()
    X_train = preprocessor.fit_transform(df)

    model = IsolationForestModel(**MODEL_PARAMS)
    model.train(X_train)

    scores = model.decision_function(X_train)
    threshold = np.percentile(scores, TAIL_PERCENTILE)

    os.makedirs("output", exist_ok=True)

    model.save_model(MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)
    np.save(THRESHOLD_PATH, threshold)

    print("[✓] Training completed.")


def build_behavior_summary(df):

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")

    grouped = df.groupby("Source IP").agg(
        total_flows=("y_pred", "count"),
        anomaly_flows=("y_pred", lambda x: (x == -1).sum()),
        mean_score=("anomaly_score", "mean"),
        min_score=("anomaly_score", "min"),
        unique_dest=("Destination IP", "nunique"),
        bytes_sent=("Bytes Sent", "sum"),
        bytes_received=("Bytes Received", "sum"),
        first_seen=("Timestamp", "min"),
        last_seen=("Timestamp", "max")
    ).reset_index()

    grouped["anomaly_ratio"] = (
        grouped["anomaly_flows"] / grouped["total_flows"]
    )

    grouped["active_duration"] = (
        grouped["last_seen"] - grouped["first_seen"]
    ).dt.total_seconds()

    eps = 1e-6

    grouped["ratio_norm"] = (
        (grouped["anomaly_ratio"] - grouped["anomaly_ratio"].min()) /
        (grouped["anomaly_ratio"].max() - grouped["anomaly_ratio"].min() + eps)
    )

    grouped["flow_norm"] = (
        grouped["anomaly_flows"] /
        (grouped["anomaly_flows"].max() + eps)
    )

    grouped["risk_score"] = (
        0.7 * grouped["ratio_norm"] +
        0.3 * grouped["flow_norm"]
    )

    risk_threshold = np.percentile(grouped["risk_score"], 90)

    grouped["apt_flag"] = (
        grouped["risk_score"] >= risk_threshold
    ).astype(int)

    return grouped, risk_threshold

def test_pipeline(test_path):

    df = pd.read_csv(test_path)
    df.columns = df.columns.str.strip()

    df = FeatureEngineer.add_ratio_features(df)

    model = IsolationForestModel(**MODEL_PARAMS)
    model.load_model(MODEL_PATH)

    preprocessor = joblib.load(PREPROCESSOR_PATH)
    threshold = np.load(THRESHOLD_PATH)

    X_test = preprocessor.transform(df)
    scores = model.decision_function(X_test)

    df["anomaly_score"] = scores
    df["y_pred"] = np.where(scores < threshold, -1, 1)

    host_table, risk_th = build_behavior_summary(df)

    os.makedirs("output", exist_ok=True)
    host_table.to_csv("output/host_behavior_table.csv", index=False)

    print("Host risk threshold:", risk_th)

    if "Label" in df.columns:
        df["Label"] = df["Label"].str.strip().str.upper()
        df["y_true"] = (df["Label"] != "NORMAL").astype(int)
    else:
        df["y_true"] = None

    export_anomaly_to_json(df, host_table, output_path=BEHAVIOR_OUTPUT)

    print("[✓] anomaly_report.json and host_behavior_table.csv exported for LLM.")


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["train", "test"], required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    if args.mode == "train":
        train_pipeline(args.input)

    elif args.mode == "test":
        test_pipeline(args.input)


if __name__ == "__main__":
    main()