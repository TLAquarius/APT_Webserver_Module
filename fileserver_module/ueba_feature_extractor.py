"""
=============================================================================
Module: UEBAFeatureExtractor — Behavioral Feature Engineering for UEBA
=============================================================================

Purpose:
    Transforms parsed Windows Event Log data into a multi-dimensional
    behavioral feature matrix for ML anomaly detection. Covers ALL 13
    APT-relevant Event IDs across 6 behavioral dimensions:

      1. **Volume / Velocity** — read/write/delete counts, event volume
      2. **Spatio-Temporal** — off-hour activity, circular time encoding
      3. **Variety / Context** — distinct files, LOLBin usage, admin shares
      4. **Authentication** — logon patterns, failed logons, credential abuse
      5. **Process Execution** — new processes, LOLBins, parent diversity
      6. **Persistence & Anti-Forensics** — services, tasks, log clearing

Author:  UEBA Pipeline — Phase 1
Python:  3.9+
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUSINESS_HOUR_START: int = 8
BUSINESS_HOUR_END: int = 18

ADMIN_SHARE_PATTERNS: list[str] = [
    "C$", "ADMIN$", "IPC$", "D$", "E$",
]

# Complete feature columns produced by the extractor
FEATURE_COLUMNS: list[str] = [
    # --- Volume / Velocity ---
    "total_read_operations",
    "total_write_operations",
    "total_delete_operations",
    "total_events",
    "read_write_ratio",
    # --- Variety / Context ---
    "distinct_files_accessed",
    "distinct_processes_used",
    "admin_share_access_count",
    "lolbin_event_count",
    # --- Spatio-Temporal ---
    "off_hour_activity_ratio",
    "hour_sin",
    "hour_cos",
    # --- Authentication ---
    "successful_logon_count",
    "failed_logon_count",
    "failed_logon_ratio",
    "distinct_logon_source_ips",
    "explicit_credential_count",
    # --- Process Execution ---
    "new_process_count",
    "suspicious_process_count",
    "distinct_parent_processes",
    # --- Persistence ---
    "scheduled_task_created_count",
    "service_installed_count",
    # --- Anti-Forensics ---
    "audit_log_cleared_count",
    "object_deleted_count",
    # --- Network / Share ---
    "share_session_count",
    "distinct_shares_accessed",
]


class UEBAFeatureExtractor:
    """
    Extracts behavioral features from parsed Windows Event Log data using
    tumbling time-window aggregation. Covers all 13 APT-relevant Event IDs.

    Parameters:
        time_window: Pandas-compatible frequency string ('1h', '5min', etc.)
        business_hour_start: Start of business hours (24h, default 8)
        business_hour_end: End of business hours (24h, default 18)
    """

    def __init__(
        self,
        time_window: str = "1h",
        business_hour_start: int = BUSINESS_HOUR_START,
        business_hour_end: int = BUSINESS_HOUR_END,
    ) -> None:
        self.time_window = time_window
        self.business_hour_start = business_hour_start
        self.business_hour_end = business_hour_end

        logger.info(
            "UEBAFeatureExtractor initialized — window=%s, "
            "business_hours=%02d:00–%02d:00",
            time_window, business_hour_start, business_hour_end,
        )

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract behavioral features from parsed log data.

        Args:
            df: Parsed DataFrame from FileServerLogParser.parse().

        Returns:
            Feature matrix with one row per (user, time_window).
        """
        self._validate_schema(df)

        if df.empty:
            logger.warning("Input DataFrame is empty — returning empty feature matrix.")
            return pd.DataFrame(columns=["SubjectUserName", "TimeWindow"] + FEATURE_COLUMNS)

        working_df = df.copy()
        working_df["TimeCreated"] = pd.to_datetime(
            working_df["TimeCreated"], errors="coerce"
        )
        working_df = working_df.dropna(subset=["TimeCreated"])

        # Pre-compute helper columns
        working_df["_hour"] = working_df["TimeCreated"].dt.hour
        working_df["_is_off_hour"] = ~working_df["_hour"].between(
            self.business_hour_start, self.business_hour_end - 1
        )
        working_df["_is_admin_share"] = working_df.apply(
            self._is_admin_share_row, axis=1
        )

        # Group by user and time window
        result_rows: list[dict] = []
        grouped = working_df.groupby(
            [
                "SubjectUserName",
                pd.Grouper(key="TimeCreated", freq=self.time_window),
            ]
        )

        for (user, window), group in grouped:
            if group.empty:
                continue
            row = self._compute_window_features(group)
            row["SubjectUserName"] = user
            row["TimeWindow"] = window
            result_rows.append(row)

        if not result_rows:
            logger.warning("No non-empty time windows found.")
            return pd.DataFrame(
                columns=["SubjectUserName", "TimeWindow"] + FEATURE_COLUMNS
            )

        features = pd.DataFrame(result_rows)

        # Fill any NaN with 0 for numeric columns
        for col in FEATURE_COLUMNS:
            if col in features.columns:
                features[col] = features[col].fillna(0)

        logger.info(
            "Extracted %d feature vectors for %d unique users across %d time windows.",
            len(features),
            features["SubjectUserName"].nunique(),
            features["TimeWindow"].nunique() if "TimeWindow" in features.columns else 0,
        )

        return features

    @staticmethod
    def _compute_window_features(group: pd.DataFrame) -> dict:
        """
        Compute all behavioral features for a single (user, time_window).
        """
        total_events = len(group)

        # Helper: check EventCategory column
        has_category = "EventCategory" in group.columns
        has_event_id = "EventID" in group.columns

        # ================================================================
        # 1. VOLUME / VELOCITY FEATURES (from file access events)
        # ================================================================
        total_read_ops = int(group["is_read"].sum()) if "is_read" in group.columns else 0
        total_write_ops = 0
        if "is_write" in group.columns:
            total_write_ops += int(group["is_write"].sum())
        if "is_append" in group.columns:
            total_write_ops += int(group["is_append"].sum())
        total_delete_ops = int(group["is_delete"].sum()) if "is_delete" in group.columns else 0
        read_write_ratio = total_read_ops / (total_write_ops + 1)

        # ================================================================
        # 2. VARIETY / CONTEXT FEATURES
        # ================================================================
        distinct_files = group["ObjectName"].nunique() if "ObjectName" in group.columns else 0
        distinct_processes = 0
        process_names = set()
        for col in ["ProcessName", "NewProcessName"]:
            if col in group.columns:
                process_names.update(group[col].dropna().unique())
        process_names.discard("")
        distinct_processes = len(process_names)

        admin_share_count = int(group["_is_admin_share"].sum()) if "_is_admin_share" in group.columns else 0

        # LOLBin events
        lolbin_count = 0
        if "is_lolbin" in group.columns:
            lolbin_count = int(group["is_lolbin"].sum())

        # ================================================================
        # 3. SPATIO-TEMPORAL FEATURES
        # ================================================================
        off_hour_ratio = (
            group["_is_off_hour"].sum() / total_events
            if total_events > 0 and "_is_off_hour" in group.columns
            else 0.0
        )
        median_hour = float(group["_hour"].median()) if total_events > 0 and "_hour" in group.columns else 12.0
        hour_sin = np.sin(2 * np.pi * median_hour / 24.0)
        hour_cos = np.cos(2 * np.pi * median_hour / 24.0)

        # ================================================================
        # 4. AUTHENTICATION FEATURES (from 4624/4625/4648)
        # ================================================================
        successful_logon = 0
        failed_logon = 0
        explicit_cred = 0
        logon_source_ips = set()

        if has_event_id:
            auth_mask_4624 = group["EventID"] == 4624
            auth_mask_4625 = group["EventID"] == 4625
            auth_mask_4648 = group["EventID"] == 4648

            successful_logon = int(auth_mask_4624.sum())
            failed_logon = int(auth_mask_4625.sum())
            explicit_cred = int(auth_mask_4648.sum())

            # Distinct IPs from auth events
            auth_events = group[auth_mask_4624 | auth_mask_4625]
            if "IpAddress" in group.columns and not auth_events.empty:
                ips = auth_events["IpAddress"].dropna().unique()
                logon_source_ips = set(ip for ip in ips if ip and ip != "local" and ip != "-")

        failed_logon_ratio = (
            failed_logon / (failed_logon + successful_logon)
            if (failed_logon + successful_logon) > 0
            else 0.0
        )

        # ================================================================
        # 5. PROCESS EXECUTION FEATURES (from 4688)
        # ================================================================
        new_process_count = 0
        suspicious_process_count = 0
        distinct_parents = 0

        if has_event_id:
            proc_mask = group["EventID"] == 4688
            proc_events = group[proc_mask]
            new_process_count = int(proc_mask.sum())

            if not proc_events.empty:
                # Count LOLBins specifically in process creation events
                if "is_lolbin" in proc_events.columns:
                    suspicious_process_count = int(proc_events["is_lolbin"].sum())
                if "ParentProcessName" in proc_events.columns:
                    parents = proc_events["ParentProcessName"].dropna().unique()
                    distinct_parents = len([p for p in parents if p and p != ""])

        # ================================================================
        # 6. PERSISTENCE FEATURES (from 4698/7045)
        # ================================================================
        sched_task_count = 0
        service_inst_count = 0

        if has_event_id:
            sched_task_count = int((group["EventID"] == 4698).sum())
            service_inst_count = int((group["EventID"] == 7045).sum())

        # ================================================================
        # 7. ANTI-FORENSICS FEATURES (from 1102/4660)
        # ================================================================
        log_cleared_count = 0
        obj_deleted_count = 0

        if has_event_id:
            log_cleared_count = int((group["EventID"] == 1102).sum())
            obj_deleted_count = int((group["EventID"] == 4660).sum())

        # ================================================================
        # 8. NETWORK / SHARE FEATURES (from 5140)
        # ================================================================
        share_session_count = 0
        distinct_shares = 0

        if has_event_id:
            share_mask = group["EventID"] == 5140
            share_events = group[share_mask]
            share_session_count = int(share_mask.sum())

            if not share_events.empty and "ShareName" in share_events.columns:
                shares = share_events["ShareName"].dropna().unique()
                distinct_shares = len([s for s in shares if s and s != ""])

        return {
            "total_read_operations":     total_read_ops,
            "total_write_operations":    total_write_ops,
            "total_delete_operations":   total_delete_ops,
            "total_events":              total_events,
            "read_write_ratio":          round(read_write_ratio, 4),
            "distinct_files_accessed":   distinct_files,
            "distinct_processes_used":   distinct_processes,
            "admin_share_access_count":  admin_share_count,
            "lolbin_event_count":        lolbin_count,
            "off_hour_activity_ratio":   round(off_hour_ratio, 4),
            "hour_sin":                  round(hour_sin, 4),
            "hour_cos":                  round(hour_cos, 4),
            "successful_logon_count":    successful_logon,
            "failed_logon_count":        failed_logon,
            "failed_logon_ratio":        round(failed_logon_ratio, 4),
            "distinct_logon_source_ips": len(logon_source_ips),
            "explicit_credential_count": explicit_cred,
            "new_process_count":         new_process_count,
            "suspicious_process_count":  suspicious_process_count,
            "distinct_parent_processes": distinct_parents,
            "scheduled_task_created_count": sched_task_count,
            "service_installed_count":   service_inst_count,
            "audit_log_cleared_count":   log_cleared_count,
            "object_deleted_count":      obj_deleted_count,
            "share_session_count":       share_session_count,
            "distinct_shares_accessed":  distinct_shares,
        }

    @staticmethod
    def _is_admin_share_row(row: pd.Series) -> bool:
        """Check if any path field in this row references an admin share."""
        for field in ["ObjectName", "ShareName"]:
            val = row.get(field, "")
            if isinstance(val, str) and val:
                upper = val.upper()
                if any(share.upper() in upper for share in ADMIN_SHARE_PATTERNS):
                    return True
        return False

    @staticmethod
    def _validate_schema(df: pd.DataFrame) -> None:
        """Validate that the DataFrame has minimum required columns."""
        required = {"TimeCreated", "EventID", "SubjectUserName"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(
                f"Missing required columns: {sorted(missing)}. "
                "Ensure data comes from FileServerLogParser.parse()."
            )

    def get_feature_names(self) -> list[str]:
        """Return all feature column names."""
        return FEATURE_COLUMNS.copy()

    def get_ml_feature_names(self) -> list[str]:
        """Return numeric feature columns suitable for ML input."""
        return FEATURE_COLUMNS.copy()
