"""
=============================================================================
Main Execution — APT File Server UEBA Pipeline (Phase 1)
=============================================================================

Purpose:
    End-to-end execution script that orchestrates the complete Phase 1
    pipeline:

      1. Accept a real log file path (CLI argument or interactive prompt).
      2. Parse the log file using ``FileServerLogParser``.
      3. Extract behavioral features using ``UEBAFeatureExtractor``.
      4. Chronologically split data (80% train / 20% test).
      5. Train an ``IndividualBaselineModel`` (Isolation Forest) per user.
      6. Evaluate and print anomaly risk scores.

Usage:
    Interactive mode:
        ``python main.py``

    CLI mode:
        ``python main.py --file C:/Logs/Security.evtx``
        ``python main.py --file C:/Logs/exported_events.json --window 4h``

Author:  UEBA Pipeline — Phase 1
Python:  3.9+
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd

from file_server_log_parser import FileServerLogParser
from ueba_feature_extractor import UEBAFeatureExtractor
from individual_baseline_model import IndividualBaselineModel, ML_FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("UEBA.Main")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "APT File Server UEBA Pipeline — Phase 1\n"
            "Ingests real Windows Event Logs, extracts behavioral features, "
            "and detects anomalies using Isolation Forest."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        default=None,
        help="Path to log file (.evtx, .json, or .csv). If omitted, prompts interactively.",
    )
    parser.add_argument(
        "--window", "-w",
        type=str,
        default="1h",
        help="Time window for feature aggregation (e.g., '1h', '4h', '15min'). Default: 1h",
    )
    parser.add_argument(
        "--contamination", "-c",
        type=float,
        default=0.05,
        help="Expected anomaly ratio for Isolation Forest (0.01–0.5). Default: 0.05",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Fraction of data used for training (chronological split). Default: 0.8",
    )
    return parser.parse_args()


def get_log_file_path(cli_path: str | None) -> str:
    """
    Resolve the log file path from CLI argument or interactive prompt.

    Args:
        cli_path: Path from --file argument, or None for interactive mode.

    Returns:
        Validated file path string.
    """
    if cli_path:
        path = Path(cli_path)
        if not path.exists():
            print(f"\n❌ Error: File not found: {path.resolve()}")
            sys.exit(1)
        return str(path)

    print("\n" + "=" * 70)
    print("  APT File Server UEBA Pipeline — Phase 1")
    print("  Real Log Data Ingestion & Individual Baseline Analysis")
    print("=" * 70)
    print("\nSupported formats:")
    print("  • .evtx  — Raw Windows Event Log binary")
    print("  • .json  — JSON export (PowerShell ConvertTo-Json)")
    print("  • .csv   — CSV export (Event Viewer / Export-Csv)")
    print()

    while True:
        file_path = input("📂 Enter the path to your log file: ").strip()
        if not file_path:
            print("  ⚠ Please enter a valid file path.")
            continue
        # Remove surrounding quotes if present
        file_path = file_path.strip('"').strip("'")
        path = Path(file_path)
        if not path.exists():
            print(f"  ❌ File not found: {path.resolve()}")
            continue
        if path.suffix.lower() not in (".evtx", ".json", ".csv"):
            print(f"  ❌ Unsupported format: {path.suffix}")
            continue
        return str(path)


def print_separator(title: str = "") -> None:
    """Print a visual separator for console output."""
    print("\n" + "─" * 70)
    if title:
        print(f"  {title}")
        print("─" * 70)


def _compute_data_span_minutes(parsed_df: pd.DataFrame) -> float:
    """Compute the total time span of the data in minutes."""
    ts = pd.to_datetime(parsed_df["TimeCreated"], errors="coerce").dropna()
    if ts.empty:
        return 0.0
    return (ts.max() - ts.min()).total_seconds() / 60.0


# Ordered list of fallback windows from largest to smallest
_WINDOW_FALLBACK_CHAIN: list[tuple[str, float]] = [
    ("1h",   60.0),
    ("30min", 30.0),
    ("15min", 15.0),
    ("5min",  5.0),
    ("2min",  2.0),
    ("1min",  1.0),
    ("30s",   0.5),
]

# Minimum windows needed per user for meaningful analysis
MIN_WINDOWS_SPLIT_MODE = 6    # Enough for train/test split
MIN_WINDOWS_SINGLE_MODE = 5   # Minimum for Isolation Forest fit


def _select_optimal_window(
    span_minutes: float,
    requested_window: str,
    n_users: int,
) -> str:
    """
    Auto-select the best time window for the data span.

    The goal is to produce at least MIN_WINDOWS_SPLIT_MODE windows per user.
    If the requested window is too large, automatically fallback to smaller
    windows.

    Args:
        span_minutes: Total data span in minutes.
        requested_window: User-requested window (e.g., "1h").
        n_users: Number of unique users in the data.

    Returns:
        The optimal window string.
    """
    # If user explicitly set a small window, respect it
    for window_str, window_min in _WINDOW_FALLBACK_CHAIN:
        if window_str == requested_window:
            expected = span_minutes / window_min if window_min > 0 else 999
            if expected >= MIN_WINDOWS_SPLIT_MODE:
                return requested_window
            break

    # Auto-select: find the largest window that gives ≥ MIN_WINDOWS_SPLIT_MODE
    for window_str, window_min in _WINDOW_FALLBACK_CHAIN:
        if window_min <= 0:
            continue
        expected_windows = span_minutes / window_min
        if expected_windows >= MIN_WINDOWS_SPLIT_MODE:
            return window_str

    # Last resort: smallest available
    return _WINDOW_FALLBACK_CHAIN[-1][0]


def run_pipeline(
    file_path: str,
    time_window: str = "1h",
    contamination: float = 0.05,
    train_ratio: float = 0.8,
) -> None:
    """
    Execute the complete Phase 1 UEBA pipeline.

    Steps:
      1. Parse raw log file → standardized DataFrame.
      2. Auto-detect optimal time window if data span is short.
      3. Extract behavioral features → feature matrix.
      4. Train Individual Baseline (Isolation Forest) per user.
      5. Predict and display anomaly risk scores.

    When data is limited (< MIN_WINDOWS_SPLIT_MODE per user), the pipeline
    automatically switches to "single-batch" mode: trains on ALL data and
    scores the same data.  This is less rigorous than a proper train/test
    split but still useful for detecting outlier windows in short captures.

    Args:
        file_path: Path to the log file.
        time_window: Aggregation window for features.
        contamination: Isolation Forest contamination parameter.
        train_ratio: Fraction of chronological data for training.
    """
    # =================================================================
    # Step 1: Parse Log File
    # =================================================================
    print_separator("STEP 1: Parsing Log File")
    print(f"  File: {file_path}")
    print(f"  Detecting format and extracting all APT-relevant Event IDs...")

    parser = FileServerLogParser(file_path)
    parsed_df = parser.parse()

    if parsed_df.empty:
        print("\n  ⚠ No relevant events found in the log file.")
        print("  Possible causes:")
        print("    • Audit policy not configured")
        print("    • Log file does not contain supported events")
        print("    • File format parsing issue — check column names")
        return

    print(f"\n  ✅ Parsed {len(parsed_df):,} events successfully.")
    print(f"     • Unique users: {parsed_df['SubjectUserName'].nunique()}")
    print(f"     • Time range: {parsed_df['TimeCreated'].min()} → {parsed_df['TimeCreated'].max()}")

    # Compute data span and auto-adjust window
    span_min = _compute_data_span_minutes(parsed_df)
    print(f"     • Data span:  {span_min:.1f} minutes ({span_min/60:.1f} hours)")

    # Show event breakdown by category
    category_labels = {
        "file_access": "📁 File Access (4656/4658/4660/4663/5140/5145)",
        "authentication": "🔑 Authentication (4624/4625/4648)",
        "process": "⚙ Process Execution (4688)",
        "persistence": "📌 Persistence (4698/7045)",
        "anti_forensics": "🚨 Anti-Forensics (1102)",
    }
    print("\n  📊 Event Breakdown by Category:")
    if "EventCategory" in parsed_df.columns:
        for cat, label in category_labels.items():
            count = (parsed_df["EventCategory"] == cat).sum()
            if count > 0:
                pct = count / len(parsed_df) * 100
                print(f"     • {label}: {count:>8,} ({pct:5.1f}%)")

    # Show Event ID breakdown
    print("\n  📋 Event ID Detail:")
    eid_counts = parsed_df["EventID"].value_counts().sort_index()
    for eid, cnt in eid_counts.items():
        print(f"     • Event {eid}: {cnt:>8,}")

    # Show AccessMask distribution for file-access events only
    file_df = parsed_df[parsed_df["EventCategory"] == "file_access"] if "EventCategory" in parsed_df.columns else parsed_df
    if not file_df.empty and "is_read" in file_df.columns:
        print("\n  🔒 Access Type Distribution (file events):")
        for flag in ["is_read", "is_write", "is_append", "is_delete", "is_write_dac"]:
            if flag in file_df.columns:
                count = file_df[flag].sum()
                pct = count / len(file_df) * 100 if len(file_df) > 0 else 0
                print(f"     • {flag:15s}: {count:>8,} ({pct:5.1f}%)")

    # Show LOLBin detection
    if "is_lolbin" in parsed_df.columns:
        lolbin_count = parsed_df["is_lolbin"].sum()
        if lolbin_count > 0:
            print(f"\n  ⚠ LOLBin (Living off the Land) events detected: {lolbin_count:,}")

    # =================================================================
    # Step 2: Auto-detect & Extract Behavioral Features
    # =================================================================
    optimal_window = _select_optimal_window(
        span_min, time_window, parsed_df["SubjectUserName"].nunique()
    )

    if optimal_window != time_window:
        print_separator("STEP 2: Auto-adjusting Time Window")
        print(f"  ⚠ Requested window '{time_window}' is too large for {span_min:.0f}-minute data span.")
        print(f"  ✅ Auto-adjusted to: '{optimal_window}'")
        time_window = optimal_window
    else:
        print_separator("STEP 2: Extracting Behavioral Features")

    print(f"  Time window: {time_window}")

    extractor = UEBAFeatureExtractor(time_window=time_window)
    features_df = extractor.extract_features(parsed_df)

    if features_df.empty:
        print("\n  ⚠ No feature vectors could be computed.")
        print("  This may happen if all events have invalid timestamps.")
        return

    print(f"\n  ✅ Generated {len(features_df):,} feature vectors.")
    print(f"     • Unique users: {features_df['SubjectUserName'].nunique()}")
    print(f"     • Time windows: {features_df['TimeWindow'].nunique()}")

    # Display sample of the feature matrix
    print("\n  📋 Feature Matrix (first 5 rows):")
    display_cols = ["SubjectUserName", "TimeWindow",
                    "total_events", "total_read_operations",
                    "failed_logon_count", "new_process_count",
                    "lolbin_event_count"]
    available_cols = [c for c in display_cols if c in features_df.columns]
    print(features_df[available_cols].head().to_string(index=False))

    # =================================================================
    # Step 3 & 4: Train & Evaluate Per-User Baselines
    # =================================================================
    print_separator("STEP 3: Individual User Baseline Analysis (Isolation Forest)")
    print(f"  Contamination: {contamination}")

    users = features_df["SubjectUserName"].unique()
    all_results: list[pd.DataFrame] = []

    for user in users:
        user_data = features_df[
            features_df["SubjectUserName"] == user
        ].sort_values("TimeWindow").reset_index(drop=True)

        n_total = len(user_data)

        # Decide mode: split vs. single-batch
        if n_total >= MIN_WINDOWS_SPLIT_MODE:
            # Normal mode: chronological train/test split
            split_idx = int(n_total * train_ratio)
            split_idx = max(split_idx, MIN_WINDOWS_SINGLE_MODE)  # Ensure enough train data
            train_data = user_data.iloc[:split_idx]
            test_data = user_data.iloc[split_idx:]

            if len(test_data) < 1:
                # Edge case: give at least 1 row to test
                train_data = user_data.iloc[:n_total - 1]
                test_data = user_data.iloc[n_total - 1:]

            mode_label = f"Split mode — Train: {len(train_data)} | Test: {len(test_data)}"

        elif n_total >= MIN_WINDOWS_SINGLE_MODE:
            # Single-batch mode: train on all, score all
            train_data = user_data
            test_data = user_data
            mode_label = f"Single-batch mode — {n_total} windows (train & score all)"

        else:
            print(f"\n  ⏭ Skipping user '{user}': only {n_total} windows (need >= {MIN_WINDOWS_SINGLE_MODE})")
            continue

        print(f"\n  👤 User: {user}")
        print(f"     {mode_label}")

        # Train the model
        model = IndividualBaselineModel(contamination=contamination)
        model.fit(train_data)

        # Predict on test data
        results = model.predict(test_data)
        all_results.append(results)

        # Display results
        anomaly_count = results["is_anomaly"].sum()
        max_score = results["anomaly_score"].max()
        avg_score = results["anomaly_score"].mean()

        risk_indicator = "🔴" if anomaly_count > 0 else "🟢"
        print(f"     {risk_indicator} Anomalies detected: {anomaly_count}/{len(test_data)}")
        print(f"     📊 Risk Score — Avg: {avg_score:.1f}/100 | Max: {max_score:.1f}/100")

        # Show the most anomalous windows
        if anomaly_count > 0:
            top_anomalies = results.nlargest(min(3, anomaly_count), "anomaly_score")
            print("\n     🚨 Top Anomalous Windows:")
            for _, row in top_anomalies.iterrows():
                print(
                    f"        [{row['TimeWindow']}] "
                    f"Score: {row['anomaly_score']:.1f} | "
                    f"Reads: {row.get('total_read_operations', 'N/A')} | "
                    f"Writes: {row.get('total_write_operations', 'N/A')} | "
                    f"Files: {row.get('distinct_files_accessed', 'N/A')}"
                )

            # Feature importance for the latest test window
            print("\n     🔍 Feature Deviation Analysis (most recent window):")
            importance = model.get_feature_importances(test_data)
            top_features = importance.head(5)
            for _, feat in top_features.iterrows():
                z = feat.get("z_deviation", 0)
                arrow = "⬆" if feat.get("current_value", 0) > feat["training_mean"] else "⬇"
                print(
                    f"        {arrow} {feat['feature']:30s} "
                    f"z={z:6.2f}  "
                    f"(baseline: {feat['training_mean']:.1f} ± {feat['training_std']:.1f}, "
                    f"current: {feat.get('current_value', 'N/A'):.1f})"
                )
        else:
            # Show quick feature summary even for normal results
            print("     📋 Feature Summary (avg per window):")
            for col in ["total_read_operations", "total_write_operations",
                        "total_delete_operations", "distinct_files_accessed",
                        "off_hour_activity_ratio"]:
                if col in test_data.columns:
                    val = test_data[col].mean()
                    print(f"        {col:35s}: {val:.1f}")

    # =================================================================
    # Summary
    # =================================================================
    if all_results:
        combined = pd.concat(all_results, ignore_index=True)
        print_separator("PIPELINE SUMMARY")
        total_anomalies = combined["is_anomaly"].sum()
        total_windows = len(combined)
        print(f"  Total users analyzed: {len(all_results)}")
        print(f"  Total test windows:   {total_windows}")
        print(f"  Total anomalies:      {total_anomalies}")
        print(f"  Anomaly rate:         {total_anomalies/total_windows*100:.1f}%")
        print(f"  Mean risk score:      {combined['anomaly_score'].mean():.1f}/100")
        print(f"  Max risk score:       {combined['anomaly_score'].max():.1f}/100")

        if total_anomalies > 0:
            print("\n  ⚠  Anomalous activity detected — recommend SOC investigation.")
        else:
            print("\n  ✅ No anomalies detected in the evaluation period.")
    else:
        print_separator("NO RESULTS")
        print("  No users had sufficient data for baseline analysis.")
        print(f"  Data span: {span_min:.0f} minutes | Window: {time_window}")
        print(f"  Need at least {MIN_WINDOWS_SINGLE_MODE} windows per user.")
        print("  Recommendations:")
        print("    • Collect logs for a longer period (use: python collect_logs.py --days 1)")
        print("    • Try an even smaller window (e.g., --window 30s)")


# =======================================================================
# Entry Point
# =======================================================================
if __name__ == "__main__":
    args = parse_arguments()

    file_path = get_log_file_path(args.file)

    try:
        run_pipeline(
            file_path=file_path,
            time_window=args.window,
            contamination=args.contamination,
            train_ratio=args.train_ratio,
        )
    except KeyboardInterrupt:
        print("\n\n⛔ Pipeline interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.error("Pipeline failed: %s", exc, exc_info=True)
        print(f"\n❌ Pipeline error: {exc}")
        sys.exit(1)
