import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.preprocessing import LabelEncoder
import networkx as nx
import torch
import torch.nn as nn
import pickle
import random
from datetime import datetime, timedelta


# Step 1: Generate Clean/Semi-Cleaned/Injected-APT Logs
def generate_logs(num_logs=100, apt_inject_prob=0.1):
    """Generate simulated mixed security logs: clean normal, semi-cleaned, and APT-injected."""
    base_time = datetime(2025, 10, 19, 10, 0, 0)
    entities = ['user:admin', 'user:guest', 'IP:192.168.1.100', 'IP:192.168.1.101']
    log_types = ['system', 'network', 'firewall']
    normal_events = {
        'system': ['login_success', 'file_access normal', 'process_start benign'],
        'network': ['connection_attempt internal', 'data_transfer low'],
        'firewall': ['allow_inbound', 'block_malware false_positive']
    }
    apt_events = ['port_scan', 'login_attempt failed', 'file_access sensitive_data', 'exfil_attempt',
                  'lateral_movement']

    logs = []
    for i in range(num_logs):
        ts = base_time + timedelta(minutes=i)
        entity = random.choice(entities)
        log_type = random.choice(log_types)
        if random.random() < apt_inject_prob:  # Inject APT chain subtly
            event = random.choice(apt_events)
            is_anomalous = True
        else:
            event = random.choice(normal_events[log_type]) + f" {entity}"
            is_anomalous = False
        logs.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M'),
            'log_type': log_type,
            'event': event,
            'entity': entity,
            'is_anomalous': is_anomalous  # Ground truth for simulation/evaluation
        })

    df = pd.DataFrame(logs)

    # Clean/Semi-Clean: Remove duplicates, sort by time, add features
    df.drop_duplicates(subset=['timestamp', 'event'], inplace=True)
    df.sort_values('timestamp', inplace=True)
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour  # Derived feature
    df['event_length'] = df['event'].apply(len)  # Simple numeric feature

    # Save raw logs
    df.to_csv('simulated_logs.csv', index=False)
    return df


# Step 2: Filter Necessary Features and Group by User/Event
def process_logs(df):
    """Filter features (select top K via correlation), group by entity/event."""
    # Encode categoricals for feature selection
    le = LabelEncoder()
    df['log_type_code'] = le.fit_transform(df['log_type'])
    df['entity_code'] = le.fit_transform(df['entity'])
    df['event_code'] = le.fit_transform(df['event'])

    # Feature selection: Select top 4 features correlated with 'is_anomalous' (for demo)
    X = df[['hour', 'event_length', 'log_type_code', 'entity_code', 'event_code']]
    y = df['is_anomalous'].astype(int)
    selector = SelectKBest(f_classif, k=4)
    X_selected = selector.fit_transform(X, y)
    selected_cols = X.columns[selector.get_support()].tolist()
    print(f"Selected features: {selected_cols}")

    # Filtered DF with necessary features
    filtered_df = df[['timestamp', 'log_type', 'event', 'entity', 'is_anomalous'] + selected_cols]

    # Group by entity (user/IP) and event for baselines
    grouped_entity = filtered_df.groupby('entity')
    grouped_event = filtered_df.groupby('event')

    return filtered_df, grouped_entity, grouped_event


# Step 3: Get and Save Baselines
def compute_and_save_baselines(grouped_entity, grouped_event):
    """Compute baselines (e.g., mean/std per group) and save via pickle."""
    # Entity baselines: e.g., avg hour, event count per entity
    entity_baselines = grouped_entity.agg({
        'hour': ['mean', 'std'],
        'event_length': ['mean', 'std'],
        'event': 'count'
    }).reset_index()

    # Event baselines: e.g., freq per event type
    event_baselines = grouped_event.agg({
        'entity': 'nunique',  # Unique entities per event
        'hour': 'mean'
    }).reset_index()

    # Save baselines
    with open('../entity_baseline.pkl', 'wb') as f:
        pickle.dump(entity_baselines, f)
    with open('../event_baseline.pkl', 'wb') as f:
        pickle.dump(event_baselines, f)

    print("Baselines saved to PKL files.")
    return entity_baselines, event_baselines


# Step 4: Detection Methods with Baselines
# 4.1 UEBA: Use baselines for clustering per entity
def ueba_detection(filtered_df, entity_baselines):
    """UEBA: Group by entity, use baselines for clustering, detect deviations."""
    anomalies = []
    for entity, group in filtered_df.groupby('entity'):
        baseline = entity_baselines[entity_baselines['entity'] == entity]
        if baseline.empty:
            continue
        features = group[['hour', 'event_length']].values  # Use selected features
        dbscan = DBSCAN(eps=1.5, min_samples=2)
        labels = dbscan.fit_predict(features)
        anomalous_indices = group[labels == -1].index
        anomalies.extend(anomalous_indices)

    anomalous_df = filtered_df.loc[anomalies]
    if not anomalous_df.empty:
        seq = anomalous_df['event'].tolist()
        llm_prompt = f"Reconstruct APT from UEBA sequence: {seq}"
        print(llm_prompt)
    return anomalous_df


# 4.2 Graph-Based: Build graph per group, detect anomalous paths using baselines
def graph_detection(filtered_df):
    """Graph: Build per-entity graphs, detect long/deviant paths."""
    G = nx.DiGraph()
    for entity, group in filtered_df.groupby('entity'):
        events = group['event'].tolist()
        for i in range(len(events) - 1):
            G.add_edge(events[i], events[i + 1])

    # Use baseline event count to threshold (e.g., paths longer than avg)
    with open('../event_baseline.pkl', 'rb') as f:
        event_baselines = pickle.load(f)
    avg_path_len = event_baselines['entity'].mean()  # Proxy for baseline

    anomalous_paths = []
    for path in nx.all_simple_paths(G, source=filtered_df['event'].iloc[0], target=filtered_df['event'].iloc[-1]):
        if len(path) > avg_path_len:
            anomalous_paths.append(path)

    if anomalous_paths:
        llm_prompt = f"Reconstruct APT from graph path: {anomalous_paths}"
        print(llm_prompt)
    return anomalous_paths


# 4.3 Sequence-Based: LSTM with intent, using baselines for prediction thresholds
class LSTMAnomaly(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        _, (h, _) = self.lstm(x)
        return self.fc(h.squeeze(0))


def sequence_detection(filtered_df):
    """Sequence: Model sequences per group, detect mismatches using baselines."""
    le = LabelEncoder()
    filtered_df['event_code'] = le.fit_transform(filtered_df['event'])
    seq = torch.tensor(filtered_df['event_code'].values).unsqueeze(0).unsqueeze(2).float()

    model = LSTMAnomaly(1, 10, len(le.classes_))
    output = model(seq[:, :-1, :])
    preds = torch.argmax(output, dim=1).numpy()
    actuals = seq[0, 1:, 0].numpy()

    # Use baseline std for threshold (e.g., high deviation)
    with open('../entity_baseline.pkl', 'rb') as f:
        entity_baselines = pickle.load(f)
    threshold = entity_baselines[('hour', 'std')].mean() * 2  # Example threshold

    mismatches = np.abs(preds - actuals) > threshold
    anomalous_indices = np.where(mismatches)[0]
    anomalous_df = filtered_df.iloc[anomalous_indices]

    if not anomalous_df.empty:
        seq = anomalous_df['event'].tolist()
        llm_prompt = f"Reconstruct APT with sequence intent: {seq}"
        print(llm_prompt)
    return anomalous_df


# 4.4 Hybrid: Combine UEBA + Graph + Sequence
def hybrid_detection(filtered_df, entity_baselines):
    """Hybrid: UEBA for entities, Graph for paths, Sequence for timing."""
    # UEBA step
    ueba_anoms = ueba_detection(filtered_df, entity_baselines)

    # Graph on UEBA anomalies
    paths = graph_detection(ueba_anoms) if not ueba_anoms.empty else []

    # Sequence on paths
    if paths:
        flat_events = [event for path in paths for event in path]
        sub_df = filtered_df[filtered_df['event'].isin(flat_events)]
        seq_anoms = sequence_detection(sub_df)
        if not seq_anoms.empty:
            llm_prompt = f"Hybrid reconstruct APT: entities={seq_anoms['entity'].unique()}, paths={paths}"
            print(llm_prompt)
    return paths


# Main Execution
if __name__ == "__main__":
    # Generate and process logs
    raw_logs = generate_logs(num_logs=200, apt_inject_prob=0)
    filtered_df, grouped_entity, grouped_event = process_logs(raw_logs)

    # Compute and save baselines
    entity_baselines, event_baselines = compute_and_save_baselines(grouped_entity, grouped_event)

    # Run detections
    print("\nUEBA Detection:")
    ueba_detection(filtered_df, entity_baselines)

    print("\nGraph Detection:")
    graph_detection(filtered_df)

    print("\nSequence Detection:")
    sequence_detection(filtered_df)

    print("\nHybrid Detection:")
    hybrid_detection(filtered_df, entity_baselines)