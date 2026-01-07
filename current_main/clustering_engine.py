import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import warnings

warnings.filterwarnings('ignore')

INPUT_CSV = "user_behavior_features.csv"
OUTPUT_CLUSTERS = "user_groups.csv"


def perform_clustering(file_path, n_clusters=3):
    print(f"[-] Loading features from {file_path}...")
    df = pd.read_csv(file_path)

    # 1. PREPARE DATA FOR AI
    # We only use the numerical columns for clustering (drop user_id)
    feature_cols = [
        "avg_rpm", "total_bytes_sent", "total_bytes_received",
        "error_rate_pct", "write_read_ratio"
    ]

    X = df[feature_cols]

    # 2. SCALING (CRITICAL STEP)
    # K-Means fails if one column is 1,000,000 and another is 0.5.
    # Scaler forces all columns to be on the same "scale" (Mean=0, StdDev=1).
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 3. RUN K-MEANS
    print(f"[-] Running K-Means with {n_clusters} clusters...")
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    clusters = kmeans.fit_predict(X_scaled)

    # Add the cluster label back to the original data
    df['cluster_group'] = clusters

    return df


def analyze_groups(df):
    print("\n[+] CLUSTER PROFILING (Who are these groups?)")
    print("=" * 60)

    # Group by the new 'cluster_group' and calculate the mean of each feature
    # This tells us the "Personality" of each group.
    profile = df.groupby('cluster_group')[
        ["avg_rpm", "total_bytes_sent", "error_rate_pct", "write_read_ratio"]
    ].mean()

    print(profile.round(2).to_string())
    print("=" * 60)

    # Logic to Auto-Label the groups based on the data
    # We look at the 'avg_rpm' and 'bytes' to guess the role.
    labels = {}
    for cluster_id, row in profile.iterrows():
        label = "Standard User"  # Default

        if row['avg_rpm'] > profile['avg_rpm'].mean() * 1.5:
            label = "High Velocity (Bot/Script)"
        elif row['total_bytes_sent'] > profile['total_bytes_sent'].mean() * 2.0:
            label = "High Volume (Admin/Server)"
        elif row['error_rate_pct'] > 10.0:
            label = "High Error (Suspicious/Scanner)"

        labels[cluster_id] = label
        print(f"Group {cluster_id} appears to be: {label}")

    return labels


if __name__ == "__main__":
    # 1. Cluster
    result_df = perform_clustering(INPUT_CSV)

    # 2. Profile
    group_labels = analyze_groups(result_df)

    # 3. Save
    result_df.to_csv(OUTPUT_CLUSTERS, index=False)
    print(f"\n[+] Saved labeled groups to {OUTPUT_CLUSTERS}")