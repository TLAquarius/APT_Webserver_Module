import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Create a folder to save the charts
OUTPUT_DIR = "analysis_plots"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def validate_zaker_features(filepath):
    print(f"\n{'=' * 60}")
    print(f"  FEATURE SANITY VALIDATION: Zaker Dataset")
    print(f"{'=' * 60}")

    # 1. LOAD DATA (Scope: Zaker Only)
    try:
        df = pd.read_csv(filepath)
        print(f"[LOAD] Loaded {len(df)} sessions from {filepath}")
    except FileNotFoundError:
        print(f"[ERROR] Could not find {filepath}. Run the pipeline first.")
        return

    # Drop non-feature columns for analysis
    meta_cols = ['ip', 'label']
    feature_cols = [c for c in df.columns if c not in meta_cols]
    df_feats = df[feature_cols]

    # =========================================================
    # STEP 1: BASIC NUMERIC SANITY (Distribution Check)
    # =========================================================
    print(f"\n[STEP 1] Checking Basic Statistics...")

    stats = df_feats.describe().transpose()
    # Calculate % of Zeros (Crucial for sparsity check)
    stats['pct_zeros'] = df_feats.apply(lambda x: (x == 0).mean() * 100)

    # Print the table cleanly
    print(f"{'Feature':<25} {'Min':<10} {'Max':<10} {'Mean':<10} {'Std':<10} {'% Zeros':<10}")
    print("-" * 80)
    for index, row in stats.iterrows():
        print(
            f"{index:<25} {row['min']:<10.2f} {row['max']:<10.2f} {row['mean']:<10.2f} {row['std']:<10.2f} {row['pct_zeros']:<10.1f}%")

    # RED FLAG CHECK
    print("\n[!] Running Automated Red Flag Checks...")
    issues_found = False

    # Check 1: Constant Features (Variance = 0)
    dead_feats = stats[stats['std'] == 0].index.tolist()
    if dead_feats:
        print(f"  [WARN] DEAD FEATURES (Always Constant): {dead_feats}")
        issues_found = True

    # Check 2: Infinite/NaN values (Division bugs)
    if df_feats.isnull().values.any() or np.isinf(df_feats.values).any():
        print(f"  [FAIL] Dataset contains NaN or Infinite values! Check Feature Extractor math.")
        issues_found = True

    # Check 3: Suspiciously High Max Values (e.g. Duration > 1 year)
    if df['duration'].max() > 86400:  # 24 hours
        print(f"  [WARN] Extreme duration detected ({df['duration'].max()}s). Verify timeout logic.")
        issues_found = True

    if not issues_found:
        print("  [PASS] No obvious numeric corruptions found.")

    # =========================================================
    # STEP 2: VISUAL INSPECTION (Histograms)
    # =========================================================
    print(f"\n[STEP 2] Generating Distribution Plots (Saved to {OUTPUT_DIR}/)...")

    # We plot key features mentioned in your advice
    key_features = [
        'duration', 'total_requests', 'requests_per_sec',
        'avg_uri_entropy', 'unique_path_ratio', 'avg_resp_bytes'
    ]

    for col in key_features:
        if col not in df.columns: continue

        plt.figure(figsize=(10, 5))
        sns.histplot(df[col], bins=50, kde=True, log_scale=(False, True))  # Log scale Y to see tails
        plt.title(f"Distribution of {col} (Zaker)")
        plt.xlabel(col)
        plt.ylabel("Frequency (Log Scale)")
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{OUTPUT_DIR}/hist_{col}.png")
        plt.close()

    print("  [DONE] Plots generated. Please verify 'Long Tails' manually.")

    # =========================================================
    # STEP 3: CORRELATION CHECK
    # =========================================================
    print(f"\n[STEP 3] Checking Feature Correlations...")

    corr_matrix = df_feats.corr()

    # Find highly correlated pairs (> 0.95)
    high_corr = []
    for i in range(len(corr_matrix.columns)):
        for j in range(i):
            if abs(corr_matrix.iloc[i, j]) > 0.95:
                high_corr.append((corr_matrix.columns[i], corr_matrix.columns[j], corr_matrix.iloc[i, j]))

    if high_corr:
        print("  [INFO] Highly Correlated Pairs (> 0.95):")
        for f1, f2, val in high_corr:
            print(f"    * {f1} <-> {f2}: {val:.3f}")
        print("    (This is usually OK, but good to know for later dimensionality reduction)")
    else:
        print("  [PASS] No extreme redundancy found.")

    # =========================================================
    # STEP 4: SEMANTIC SANITY CHECK (Human Logic)
    # =========================================================
    print(f"\n[STEP 4] Semantic Sanity Check (Inspect 3 Random Sessions)")

    sample = df.sample(3)
    for idx, row in sample.iterrows():
        print(f"\n  --- Session Sample (IP: {row.get('ip', 'N/A')}) ---")
        print(f"    Duration: {row['duration']:.2f}s | Requests: {row['total_requests']}")
        print(f"    Speed: {row['requests_per_sec']:.2f} rps | Error Rate: {row['rate_4xx']:.2f}")
        print(f"    Unique Paths: {row['unique_path_count']} | Ratio: {row['unique_path_ratio']:.2f}")
        print(f"    Entropy: {row['avg_uri_entropy']:.2f} | Rules Triggered: {row['rule_match_count']}")
        print(f"    Logic Check: Does this make sense? (e.g., Short duration = Few requests?)")


if __name__ == "__main__":
    validate_zaker_features("data/zaker_features.csv")