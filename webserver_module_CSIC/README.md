# APT Detection System — CSIC 2010
### Phát triển hệ thống phân tích và truy vết tấn công mạng Advanced Persistent Threat (APT)

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Project Structure](#2-project-structure)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Dataset Setup](#5-dataset-setup)
6. [Running the Pipeline](#6-running-the-pipeline)
7. [Understanding the Output](#7-understanding-the-output)
8. [Command Reference](#8-command-reference)
9. [Common Errors & Fixes](#9-common-errors--fixes)
10. [Demo Day Guide](#10-demo-day-guide)

---

## 1. Project Overview

This system detects **Advanced Persistent Threat (APT)** attack patterns in HTTP traffic using the CSIC 2010 dataset. It combines:

- **Anomaly Detection** — Isolation Forest to flag suspicious requests
- **Timeline Analysis** — Groups requests into sessions and reconstructs APT kill chain progressions
- **Behavior Pattern Recognition** — Maps detected anomalies to OWASP Top 10 categories and APT phases
- **Evaluation Suite** — Generates ROC curve, PR curve, confusion matrix, and full metrics report

### APT Kill Chain Phases Covered

| Phase | Description |
|---|---|
| `reconnaissance` | Scanning, probing, information gathering |
| `initial_access` | Login attacks, credential stuffing |
| `execution` | Command injection, remote code execution |
| `defense_evasion` | Encoding attacks, WAF bypass attempts |
| `privilege_escalation` | Path traversal, accessing restricted files |
| `collection` | SQL injection, database exfiltration |
| `exfiltration` | Large data transfers, unusual POST bodies |

---

## 2. Project Structure

```
tuan/
│
├── data/
│   ├── normal/
│   │   ├── normalTrafficTraining.txt     ← training data (label 0)
│   │   └── normalTrafficTest.txt         ← normal test data (label 0)
│   └── anomalous/
│       └── AnomalousTrafficTest.txt      ← attack test data (label 1)
│
├── src/
│   ├── __init__.py
│   ├── csic_parser.py                    ← HTTP request parser
│   ├── data_loader.py                    ← loads & labels raw requests
│   ├── feature_extractor.py              ← extracts numerical features
│   ├── preprocessing.py                  ← scales features for ML
│   ├── baseline_trainer.py               ← Isolation Forest model
│   ├── owasp_mapper.py                   ← maps attacks to OWASP + APT phase
│   ├── timeline_analyzer.py              ← session grouping & APT chain detection
│   ├── pipeline.py                       ← end-to-end pipeline orchestrator
│   └── evaluator.py                      ← metrics, plots, JSON report
│
├── output/                               ← auto-created on first run
│   ├── detection_results.csv
│   ├── apt_chains.csv
│   ├── metrics.json
│   ├── roc_curve.png
│   ├── pr_curve.png
│   └── confusion_matrix.png
│
├── main.py                               ← entry point
└── requirements.txt
```

---

## 3. Requirements

- Python **3.10** or higher
- pip

### Python Dependencies

```
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
joblib>=1.3.0
```

---

## 4. Installation

### Step 1 — Clone or download the project

```bash
cd tuan
```

### Step 2 — Create a virtual environment

```bash
# Create environment
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — Mac / Linux
source venv/bin/activate
```

> You should see `(venv)` at the start of your terminal prompt after activation.

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Create the `src` package file

```bash
# Windows
type nul > src/__init__.py

# Mac / Linux
touch src/__init__.py
```

---

## 5. Dataset Setup

### Download CSIC 2010

Download the dataset from the official source and place the 3 files as follows:

```
data/normal/normalTrafficTraining.txt
data/normal/normalTrafficTest.txt
data/anomalous/AnomalousTrafficTest.txt
```

> **Note:** File names are case-sensitive on Linux and Mac. Make sure they match exactly.

### Verify the files are in place

```bash
# Windows
dir data\normal
dir data\anomalous

# Mac / Linux
ls data/normal
ls data/anomalous
```

Expected output:
```
normalTrafficTraining.txt
normalTrafficTest.txt

AnomalousTrafficTest.txt
```

---

## 6. Running the Pipeline

### Quick Test (recommended first run)

Run with only 500 requests to verify everything is working before committing to the full dataset:

```bash
python main.py --limit 500 --skip-eval
```

Expected output:
```
==================================================
  CSIC 2010 APT DETECTION SYSTEM
==================================================

[1/5] Loading normal training data...
      Loaded 500 normal requests
[2/5] Loading test data...
      Loaded 500 attack requests
      Loaded 500 normal test requests
[3/5] Training Isolation Forest (contamination=0.27)...
[4/5] Running detection on 1000 requests...

────────────────────────────────────────────────────────────────────────────────
  #    METHOD  SEVERITY   SCORE   OWASP                               APT PHASE
────────────────────────────────────────────────────────────────────────────────
  1    POST    CRITICAL   0.8821  A03:2021 - SQL Injection             collection
  2    GET     NORMAL     0.1200  A09:2021 - Anomalous Request         reconnaissance
  ...
```

> If the quick test passes without errors, proceed to the full run.

---

### Full Run (standard)

```bash
python main.py
```

This will:
1. Load all normal training requests
2. Load all attack + normal test requests
3. Train the Isolation Forest model
4. Run detection on every test request
5. Evaluate against ground truth labels
6. Run timeline analysis and detect APT chains
7. Save all outputs to `output/`

> **Estimated runtime:** 3–8 minutes depending on your machine.

---

### Full Run + Save Model

```bash
python main.py --save-model
```

Saves `output/model.pkl` and `output/scaler.pkl` so you can reload the trained model later without retraining.

---

## 7. Understanding the Output

After a successful run the `output/` folder contains:

### `detection_results.csv`
One row per HTTP request. The most important output file — feed this into your visualization layer.

| Column | Description |
|---|---|
| `timestamp` | Simulated request timestamp |
| `url` | Request URL |
| `method` | HTTP method (GET / POST) |
| `severity` | `NORMAL` / `WARNING` / `CRITICAL` |
| `score` | Anomaly score 0.0–1.0 (higher = more suspicious) |
| `owasp` | OWASP Top 10 attack category |
| `apt_phase` | APT kill chain phase |
| `confidence` | Confidence of the classification (0.0–1.0) |
| `true_label` | Ground truth (0=normal, 1=attack) |
| `is_attack` | `True` if model flagged as anomaly |

### `apt_chains.csv`
Sessions where multi-phase APT progression was detected. Each row is one attack session.

| Column | Description |
|---|---|
| `session_id` | Unique session identifier |
| `start_time` | First request in session |
| `end_time` | Last request in session |
| `duration_sec` | Session length in seconds |
| `phases_observed` | e.g. `reconnaissance → initial_access → collection` |
| `apt_score` | Kill chain progression score 0.0–1.0 |
| `critical_count` | Number of CRITICAL events in session |

### `metrics.json`
All evaluation metrics saved for report.

```json
{
  "precision_attack":    0.8921,
  "recall_attack":       0.8340,
  "f1_attack":           0.8620,
  "false_positive_rate": 0.0421,
  "roc_auc":             0.9340,
  "pr_auc":              0.9110,
  "true_positives":      22718,
  "false_positives":     1423
}
```

### `roc_curve.png`
Overall model quality across all sensitivity thresholds. AUC > 0.90 is excellent.

### `pr_curve.png`
Precision vs Recall trade-off. More meaningful than ROC for imbalanced datasets like CSIC 2010.

### `confusion_matrix.png`
Exact counts of correct detections, false alarms, and missed attacks at the chosen threshold.

---

## 8. Command Reference

| Command | Description |
|---|---|
| `python main.py` | Full run with evaluation |
| `python main.py --limit 500` | Test with 500 requests per file |
| `python main.py --skip-eval` | Skip evaluation (no ground truth needed) |
| `python main.py --save-model` | Save trained model to output/ |
| `python main.py --contamination 0.20` | Lower sensitivity (fewer false alarms) |
| `python main.py --contamination 0.35` | Higher sensitivity (catch more attacks) |
| `python main.py --session-gap 15` | 15-minute session window for timeline |
| `python main.py --limit 500 --skip-eval` | Quick smoke test |
| `python main.py --save-model --contamination 0.20` | Tune + save for demo |

### Contamination Guide

The `--contamination` flag tells the model what percentage of traffic it should expect to be anomalous:

| Value | Use case |
|---|---|
| `0.27` | Default — matches CSIC 2010's real attack ratio (~27%) |
| `0.20` | Fewer false alarms — use if FPR is too high |
| `0.35` | Catch more attacks — use if recall is too low |

---

## 9. Common Errors & Fixes

### `ModuleNotFoundError: No module named 'src'`
```bash
# Make sure you run from the project root directory
cd apt_detection
python main.py

# Also verify __init__.py exists
ls src/__init__.py
```

### `FileNotFoundError: data/normal/normalTrafficTraining.txt`
```bash
# Check file names match exactly (case-sensitive on Linux/Mac)
ls data/normal/
ls data/anomalous/
```

### `ValueError: Input contains NaN`
```bash
# Some requests may be empty or malformed — test with small limit first
python main.py --limit 100 --skip-eval
```

### `MemoryError` on full dataset
```bash
# Limit the dataset size if RAM is insufficient
python main.py --limit 20000
```

### `sklearn not found` or import errors
```bash
# Make sure your virtual environment is activated
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Then reinstall
pip install -r requirements.txt
```

### Evaluation gives all zeros
```bash
# Make sure you loaded files with correct labels
# normal files  → label=0
# attack file   → label=1
# Check data_loader calls in main.py
```

---


