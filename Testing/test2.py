# --------------------------------------------------------------
#  APT-Log Generator + Baseline + sklearn-only Detection
# --------------------------------------------------------------
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import pickle
import networkx as nx

from sklearn.ensemble import IsolationForest
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.preprocessing import LabelEncoder
from hmmlearn import hmm

# --------------------------------------------------------------
# 1. LOG GENERATION
# --------------------------------------------------------------
def generate_logs(num_logs=300, apt_prob=0.12):
    """Mixed system / network / firewall logs + subtle APT injection."""
    start = datetime(2025, 10, 19, 9, 0)
    entities = ['user:admin', 'user:guest', 'IP:192.168.1.100',
                'IP:192.168.1.101', 'IP:10.0.0.55']
    log_types = ['system', 'network', 'firewall']

    normal_events = {
        'system': ['login_success', 'file_access normal', 'process_start benign'],
        'network': ['connection_attempt internal', 'data_transfer low'],
        'firewall': ['allow_inbound', 'block_malware false_positive']
    }
    apt_events = ['port_scan', 'login_attempt failed',
                  'file_access sensitive_data', 'exfil_attempt',
                  'lateral_movement']

    rows = []
    for i in range(num_logs):
        ts = start + timedelta(minutes=random.randint(0, 5) * i)
        entity = random.choice(entities)
        ltype = random.choice(log_types)

        if random.random() < apt_prob:               # APT injection
            ev = random.choice(apt_events)
            anomalous = True
        else:
            ev = random.choice(normal_events[ltype]) + f" {entity}"
            anomalous = False

        rows.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M'),
            'log_type': ltype,
            'event': ev,
            'entity': entity,
            'is_anomalous': anomalous
        })

    df = pd.DataFrame(rows)
    # ---- semi-clean ----
    df.drop_duplicates(subset=['timestamp', 'event'], inplace=True)
    df.sort_values('timestamp', inplace=True)
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    df['event_len'] = df['event'].str.len()
    df.to_csv('simulated_logs.csv', index=False)
    return df


# --------------------------------------------------------------
# 2. FEATURE FILTERING & GROUPING
# --------------------------------------------------------------
def filter_and_group(df):
    le_type = LabelEncoder()
    le_ent  = LabelEncoder()
    le_evt  = LabelEncoder()

    df['type_code'] = le_type.fit_transform(df['log_type'])
    df['ent_code']  = le_ent.fit_transform(df['entity'])
    df['evt_code']  = le_evt.fit_transform(df['event'])

    # keep only numeric + target
    numeric_cols = ['hour', 'event_len', 'type_code', 'ent_code', 'evt_code']
    X = df[numeric_cols]
    y = df['is_anomalous'].astype(int)

    # select top-4 most predictive features
    selector = SelectKBest(f_classif, k=4)
    X_sel = selector.fit_transform(X, y)
    keep = [numeric_cols[i] for i in selector.get_support(indices=True)]
    print("Selected features:", keep)

    filtered = df[['timestamp', 'log_type', 'event', 'entity',
                   'is_anomalous'] + keep].copy()
    grp_entity = filtered.groupby('entity')
    grp_event  = filtered.groupby('event')
    return filtered, grp_entity, grp_event, keep


# --------------------------------------------------------------
# 3. BASELINE CALCULATION & PERSISTENCE
# --------------------------------------------------------------
def save_baselines(grp_entity, grp_event):
    # per-entity stats
    ent_stats = grp_entity.agg({
        'hour': ['mean', 'std'],
        'event_len': ['mean', 'std'],
        'event': 'count'
    }).reset_index()
    # per-event stats
    evt_stats = grp_event.agg({
        'entity': 'nunique',
        'hour': 'mean'
    }).reset_index()

    with open('../entity_baseline.pkl', 'wb') as f:
        pickle.dump(ent_stats, f)
    with open('../event_baseline.pkl', 'wb') as f:
        pickle.dump(evt_stats, f)
    print("Baselines saved (entity_baseline.pkl, event_baseline.pkl)")
    return ent_stats, evt_stats


# --------------------------------------------------------------
# 4. DETECTION – pure sklearn (no torch)
# --------------------------------------------------------------

# ---- 4.1 UEBA (IsolationForest per entity) ----
def ueba_detect(df, keep_cols):
    anomalies = []
    for ent, sub in df.groupby('entity'):
        X = sub[keep_cols].values
        if len(X) < 3:               # need enough points
            continue
        iso = IsolationForest(contamination=0.1, random_state=42)
        iso.fit(X)
        preds = iso.predict(X)       # -1 = anomaly
        anom_idx = sub.index[preds == -1].tolist()
        anomalies.extend(anom_idx)

    anom_df = df.loc[anomalies]
    if not anom_df.empty:
        seq = anom_df['event'].tolist()
        print("\n[UEBA] LLM prompt → Reconstruct APT from sequence:", seq)
    return anom_df


# ---- 4.2 Graph-based (NetworkX + IsolationForest on path stats) ----
def graph_detect(df):
    G = nx.DiGraph()
    for ent, sub in df.groupby('entity'):
        evts = sub['event'].tolist()
        for a, b in zip(evts[:-1], evts[1:]):
            G.add_edge(a, b)

    # extract simple path features for every node-pair
    path_features = []
    for src in G.nodes:
        for tgt in G.nodes:
            if src == tgt: continue
            paths = list(nx.all_simple_paths(G, src, tgt, cutoff=5))
            for p in paths:
                path_features.append({
                    'src': src, 'tgt': tgt,
                    'len': len(p),
                    'degree_src': G.degree(src),
                    'degree_tgt': G.degree(tgt)
                })
    if not path_features:
        return []

    pf = pd.DataFrame(path_features)
    iso = IsolationForest(contamination=0.15, random_state=42)
    iso.fit(pf[['len', 'degree_src', 'degree_tgt']])
    pf['anom'] = iso.predict(pf[['len', 'degree_src', 'degree_tgt']])

    anom_paths = pf[pf['anom'] == -1][['src', 'tgt', 'len']].values.tolist()
    if anom_paths:
        print("\n[GRAPH] LLM prompt → Reconstruct APT from anomalous paths:", anom_paths)
    return anom_paths

# --------------------------------------------------------------
# 4.3 Sequence (HMM – robust version)   <--- NEW
# --------------------------------------------------------------
def sequence_detect(df):
    """HMM-based sequence anomaly detection (pure sklearn-compatible)."""
    if df.empty or len(df) < 5:
        print("\n[SEQ] Not enough rows → skipping HMM")
        return pd.DataFrame()

    le = LabelEncoder()
    codes = le.fit_transform(df['event'])

    try:
        model = hmm.GaussianHMM(
            n_components=5,
            covariance_type="diag",
            n_iter=100,
            random_state=42,
        )
        X = codes.reshape(-1, 1)
        model.fit(X)

        log_likelihood, _ = model.score_samples(X)
        per_sample = np.atleast_1d(log_likelihood)

        thresh = np.percentile(per_sample, 10)
        anom_idx = np.where(per_sample < thresh)[0]

        anom_df = df.iloc[anom_idx].copy()
        if not anom_df.empty:
            seq = anom_df['event'].tolist()
            print("\n[SEQ] LLM prompt → Reconstruct APT with HMM anomalies:", seq)

        return anom_df

    except Exception as e:
        print("\n[SEQ] HMM failed (", e, ") → fallback to simple frequency check")
        rare = df['event'].value_counts()
        rare_events = rare[rare < 2].index
        anom_df = df[df['event'].isin(rare_events)].copy()
        if not anom_df.empty:
            seq = anom_df['event'].tolist()
            print("\n[SEQ-FALLBACK] LLM prompt → Reconstruct APT from rare events:", seq)
        return anom_df


# ---- 4.4 Hybrid (UEBA → Graph → Sequence) ----
def hybrid_detect(df, keep_cols):
    u = ueba_detect(df, keep_cols)
    if u.empty:
        return
    g = graph_detect(u)
    if not g:
        return
    # flatten anomalous nodes for final sequence check
    nodes = set()
    for src, tgt, _ in g:
        nodes.add(src); nodes.add(tgt)
    sub = df[df['event'].isin(nodes)]
    sequence_detect(sub)


# --------------------------------------------------------------
# 5. MAIN PIPELINE
# --------------------------------------------------------------
if __name__ == "__main__":
    # 1. generate
    raw = generate_logs(num_logs=400, apt_prob=0.13)

    # 2. filter & group
    filt, grp_ent, grp_evt, keep = filter_and_group(raw)

    # 3. baselines
    ent_base, evt_base = save_baselines(grp_ent, grp_evt)

    # 4. detections
    print("\n=== UEBA ===")
    ueba_detect(filt, keep)

    print("\n=== GRAPH ===")
    graph_detect(filt)

    print("\n=== SEQUENCE (HMM) ===")
    sequence_detect(filt)

    print("\n=== HYBRID ===")
    hybrid_detect(filt, keep)

    print("\nAll done – baselines in .pkl, logs in simulated_logs.csv")