"""
=============================================================================
Module: FileServerLogParser — Real Windows Event Log Ingestion & Parsing
=============================================================================

Purpose:
    Data-ingestion gateway for the UEBA pipeline. Reads real Windows Event
    Log data from `.evtx`, `.json`, or `.csv` and produces a standardized
    DataFrame covering **13 APT-relevant Event IDs** across the full
    kill-chain.

Supported Event IDs (grouped by APT phase):

    File Access & Object Monitoring:
      • 4656 — Handle Requested (pre-access reconnaissance)
      • 4658 — Handle Closed (completeness / session tracking)
      • 4660 — Object Deleted (anti-forensics via file deletion)
      • 4663 — Object Access (core: read/write/delete operations)

    Network Share / Lateral Movement:
      • 5140 — Network Share Accessed (session-level share access)
      • 5145 — Detailed File Share (per-file SMB access)

    Authentication & Credential Abuse:
      • 4624 — Successful Logon (lateral movement, logon types)
      • 4625 — Failed Logon (brute-force / password spraying)
      • 4648 — Explicit Credential Logon (Pass-the-Hash / RunAs)

    Process Execution:
      • 4688 — Process Created (LOLBin detection)

    Persistence:
      • 4698 — Scheduled Task Created
      • 7045 — Service Installed

    Anti-Forensics:
      • 1102 — Audit Log Cleared

Author:  UEBA Pipeline — Phase 1
Python:  3.9+
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AccessMask Constants — Windows NT File-Object Access Rights
# ---------------------------------------------------------------------------

ACCESS_MASK_FLAGS: dict[int, str] = {
    0x1:      "ReadData",
    0x2:      "WriteData",
    0x4:      "AppendData",
    0x8:      "ReadEA",
    0x10:     "WriteEA",
    0x20:     "Execute",
    0x40:     "DeleteChild",
    0x80:     "ReadAttributes",
    0x100:    "WriteAttributes",
    0x10000:  "DELETE",
    0x20000:  "READ_CONTROL",
    0x40000:  "WRITE_DAC",
    0x80000:  "WRITE_OWNER",
    0x100000: "SYNCHRONIZE",
}

UEBA_RELEVANT_FLAGS: dict[str, int] = {
    "is_read":      0x1,
    "is_write":     0x2,
    "is_append":    0x4,
    "is_read_ea":   0x8,
    "is_write_ea":  0x10,
    "is_delete":    0x10000,
    "is_write_dac": 0x40000,
}

# ---------------------------------------------------------------------------
# All 13 APT-relevant Event IDs
# ---------------------------------------------------------------------------
TARGET_EVENT_IDS: set[int] = {
    4624, 4625, 4648,          # Authentication
    4656, 4658, 4660, 4663,    # Object Access
    4688,                       # Process Execution
    4698,                       # Persistence (Scheduled Task)
    5140, 5145,                 # Network Share
    7045,                       # Persistence (Service Install)
    1102,                       # Anti-Forensics
}

# Event IDs that carry an AccessMask worth decoding
FILE_ACCESS_EVENT_IDS: set[int] = {4656, 4660, 4663, 5140, 5145}

# Event category mapping
EVENT_CATEGORIES: dict[int, str] = {
    4624: "authentication",
    4625: "authentication",
    4648: "authentication",
    4656: "file_access",
    4658: "file_access",
    4660: "file_access",
    4663: "file_access",
    4688: "process",
    4698: "persistence",
    5140: "file_access",
    5145: "file_access",
    7045: "persistence",
    1102: "anti_forensics",
}

# Common LOLBins (Living off the Land Binaries) for detection
LOLBIN_NAMES: set[str] = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "wmic.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "schtasks.exe", "sc.exe", "net.exe",
    "net1.exe", "psexec.exe", "psexesvc.exe", "wmiprvse.exe", "at.exe",
    "reg.exe", "tasklist.exe", "nltest.exe", "dsquery.exe", "csvde.exe",
    "ldifde.exe", "ntdsutil.exe", "procdump.exe", "7z.exe", "winrar.exe",
    "rar.exe", "tar.exe", "curl.exe", "wget.exe",
}

# Standardized output column schema
OUTPUT_COLUMNS: list[str] = [
    "TimeCreated",
    "EventID",
    "EventCategory",
    "SubjectUserName",
    "ObjectName",
    "ProcessName",
    "IpAddress",
    "AccessMask_Raw",
    # Authentication-specific
    "TargetUserName",
    "LogonType",
    "FailureReason",
    # Process-specific
    "NewProcessName",
    "CommandLine",
    "ParentProcessName",
    # Persistence-specific
    "TaskName",
    "ServiceName",
    "ServiceFileName",
    # Share-specific
    "ShareName",
]


class FileServerLogParser:
    """
    Ingests real Windows Event Log files and produces a clean, standardized
    DataFrame covering 13 APT-relevant Event IDs.

    Supported formats:
        - ``.evtx`` — native Windows Event Log binary
        - ``.json`` — JSON export from PowerShell
        - ``.csv``  — CSV export from Event Viewer / PowerShell
    """

    def __init__(self, file_path: str) -> None:
        self.file_path: Path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.file_path.resolve()}"
            )

        ext = self.file_path.suffix.lower()
        if ext == ".evtx":
            self.file_format = "evtx"
        elif ext == ".json":
            self.file_format = "json"
        elif ext == ".csv":
            self.file_format = "csv"
        else:
            raise ValueError(
                f"Unsupported file format '{ext}'. "
                "Accepted: .evtx, .json, .csv"
            )
        logger.info(
            "FileServerLogParser initialized — file=%s  format=%s",
            self.file_path.name,
            self.file_format,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self) -> pd.DataFrame:
        """
        Parse the log file and return a standardized DataFrame.

        Returns a DataFrame with one row per relevant event containing:
        TimeCreated, EventID, EventCategory, SubjectUserName, ObjectName,
        ProcessName, IpAddress, AccessMask_Raw (with decoded boolean flags
        for file-access events), plus event-specific fields like
        TargetUserName, LogonType, NewProcessName, CommandLine, etc.
        """
        dispatch = {
            "evtx": self._parse_evtx,
            "json": self._parse_json,
            "csv":  self._parse_csv,
        }
        raw_records: list[dict[str, Any]] = dispatch[self.file_format]()

        if not raw_records:
            logger.warning("No relevant events found in %s", self.file_path.name)
            return self._empty_dataframe()

        df = pd.DataFrame(raw_records)

        # Ensure TimeCreated is a proper datetime
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")

        # Decode AccessMask only for file-access events
        df = self._apply_access_mask_decoding(df)

        # Fill missing values with sensible defaults
        for col in ["ProcessName", "NewProcessName", "ParentProcessName",
                     "CommandLine", "ServiceFileName"]:
            if col in df.columns:
                df[col] = df[col].fillna("")
        df["IpAddress"] = df["IpAddress"].fillna("local")
        df["SubjectUserName"] = df["SubjectUserName"].fillna("SYSTEM")
        for col in ["TargetUserName", "LogonType", "FailureReason",
                     "TaskName", "ServiceName", "ShareName", "ObjectName"]:
            if col in df.columns:
                df[col] = df[col].fillna("")

        # Add LOLBin detection flag
        df["is_lolbin"] = df.apply(self._detect_lolbin, axis=1)

        # Sort chronologically
        df.sort_values("TimeCreated", inplace=True)
        df.reset_index(drop=True, inplace=True)

        # Log summary
        eid_counts = df["EventID"].value_counts().to_dict()
        cat_counts = df["EventCategory"].value_counts().to_dict()
        logger.info(
            "Parsed %d events from %s — %s",
            len(df), self.file_path.name,
            ", ".join(f"{eid}={cnt}" for eid, cnt in sorted(eid_counts.items())),
        )
        return df

    # ------------------------------------------------------------------
    # Format-specific parsers
    # ------------------------------------------------------------------

    def _parse_evtx(self) -> list[dict[str, Any]]:
        """Parse a raw .evtx file using python-evtx and lxml."""
        try:
            import Evtx.Evtx as evtx
            from lxml import etree
        except ImportError as exc:
            raise ImportError(
                "Required: pip install python-evtx lxml"
            ) from exc

        records: list[dict[str, Any]] = []
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        with evtx.Evtx(str(self.file_path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = etree.fromstring(xml_str.encode("utf-8"))

                    event_id_elem = root.find(".//e:System/e:EventID", ns)
                    if event_id_elem is None or event_id_elem.text is None:
                        continue
                    event_id = int(event_id_elem.text)
                    if event_id not in TARGET_EVENT_IDS:
                        continue

                    time_elem = root.find(".//e:System/e:TimeCreated", ns)
                    time_created = (
                        time_elem.get("SystemTime", "")
                        if time_elem is not None
                        else ""
                    )

                    # Build lookup dict for all <Data> elements
                    data_map: dict[str, str] = {}
                    for data_elem in root.findall(".//e:EventData/e:Data", ns):
                        name = data_elem.get("Name", "")
                        value = data_elem.text or ""
                        data_map[name] = value

                    # Also check UserData (used by some events like 1102)
                    for data_elem in root.findall(".//e:UserData//*", ns):
                        tag = data_elem.tag.split("}")[-1] if "}" in data_elem.tag else data_elem.tag
                        if data_elem.text:
                            data_map[tag] = data_elem.text

                    record_dict = self._build_record(
                        event_id, time_created, data_map
                    )
                    records.append(record_dict)

                except Exception as exc:
                    logger.debug("Skipping malformed .evtx record: %s", exc)
                    continue

        return records

    def _parse_json(self) -> list[dict[str, Any]]:
        """Parse a JSON-exported log file."""
        with open(self.file_path, "r", encoding="utf-8-sig") as f:
            raw = json.load(f)

        if isinstance(raw, dict):
            raw = [raw]

        records: list[dict[str, Any]] = []

        for entry in raw:
            event_id = self._extract_event_id_json(entry)
            if event_id not in TARGET_EVENT_IDS:
                continue

            time_created = (
                entry.get("TimeCreated")
                or entry.get("timecreated")
                or entry.get("@timestamp")
                or entry.get("SystemTime")
                or ""
            )
            if isinstance(time_created, dict):
                time_created = time_created.get("DateTime", "")

            data_map = self._flatten_json_entry(entry, event_id)
            record_dict = self._build_record(event_id, str(time_created), data_map)
            records.append(record_dict)

        return records

    def _parse_csv(self) -> list[dict[str, Any]]:
        """Parse a CSV-exported log file."""
        for encoding in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
            try:
                df = pd.read_csv(
                    self.file_path, encoding=encoding, low_memory=False
                )
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        else:
            raise ValueError(
                f"Could not read CSV file: {self.file_path}"
            )

        col_map = {c.lower().strip(): c for c in df.columns}

        event_id_col = self._find_column(col_map, [
            "eventid", "event_id", "id", "event id",
        ])
        if event_id_col is None:
            raise ValueError(
                f"Cannot find EventID column. Columns: {list(df.columns)}"
            )

        df[event_id_col] = pd.to_numeric(df[event_id_col], errors="coerce")
        df = df[df[event_id_col].isin(TARGET_EVENT_IDS)].copy()

        if df.empty:
            return []

        # Detect common columns
        time_col = self._find_column(col_map, [
            "timecreated", "time_created", "time created",
            "date and time", "datetime", "timestamp",
        ])
        user_col = self._find_column(col_map, [
            "subjectusername", "subject_user_name", "username", "user",
        ])
        object_col = self._find_column(col_map, [
            "objectname", "object_name", "relativetargetname", "filename",
        ])
        process_col = self._find_column(col_map, [
            "processname", "process_name", "newprocessname", "application",
        ])
        ip_col = self._find_column(col_map, [
            "ipaddress", "ip_address", "sourceaddress", "clientaddress",
        ])
        mask_col = self._find_column(col_map, [
            "accessmask", "access_mask", "accesslist",
        ])

        records: list[dict[str, Any]] = []
        for _, row in df.iterrows():
            event_id = int(row[event_id_col])
            data_map: dict[str, str] = {}

            # Map all available columns
            if user_col:
                data_map["SubjectUserName"] = str(row.get(user_col, ""))
            if object_col:
                data_map["ObjectName"] = str(row.get(object_col, ""))
            if process_col:
                data_map["ProcessName"] = str(row.get(process_col, ""))
            if ip_col:
                data_map["IpAddress"] = str(row.get(ip_col, ""))
            if mask_col:
                data_map["AccessMask"] = str(row.get(mask_col, ""))

            # Try to pull extra columns for specific events
            for field in ["TargetUserName", "LogonType", "NewProcessName",
                         "CommandLine", "ParentProcessName", "ShareName",
                         "RelativeTargetName", "ServiceName", "TaskName"]:
                fc = self._find_column(col_map, [field.lower()])
                if fc and fc in row.index:
                    data_map[field] = str(row[fc])

            time_created = str(row.get(time_col, "")) if time_col else ""
            record_dict = self._build_record(event_id, time_created, data_map)
            records.append(record_dict)

        return records

    # ------------------------------------------------------------------
    # Record builder for ALL Event IDs
    # ------------------------------------------------------------------

    def _build_record(
        self,
        event_id: int,
        time_created: str,
        data_map: dict[str, str],
    ) -> dict[str, Any]:
        """
        Build a standardized record from raw event fields.

        Handles all 13 Event IDs by extracting event-specific fields and
        mapping them to standardized column names.
        """
        category = EVENT_CATEGORIES.get(event_id, "unknown")

        # Base record (common to all events)
        record: dict[str, Any] = {
            "TimeCreated":     time_created,
            "EventID":         event_id,
            "EventCategory":   category,
            "SubjectUserName": data_map.get("SubjectUserName", ""),
            "ObjectName":      "",
            "ProcessName":     data_map.get("ProcessName", ""),
            "IpAddress":       data_map.get("IpAddress", ""),
            "AccessMask_Raw":  "0x0",
            "TargetUserName":  "",
            "LogonType":       "",
            "FailureReason":   "",
            "NewProcessName":  "",
            "CommandLine":     "",
            "ParentProcessName": "",
            "TaskName":        "",
            "ServiceName":     "",
            "ServiceFileName": "",
            "ShareName":       "",
        }

        # ---- File Access Events ----
        if event_id == 4663:
            record["ObjectName"] = data_map.get("ObjectName", "")
            record["AccessMask_Raw"] = data_map.get("AccessMask", "0x0")

        elif event_id == 5145:
            share = data_map.get("ShareName", "")
            rel_target = data_map.get("RelativeTargetName", "")
            record["ObjectName"] = f"{share}\\{rel_target}" if share else rel_target
            record["AccessMask_Raw"] = data_map.get("AccessMask", "0x0")
            record["ShareName"] = share

        elif event_id == 4656:
            record["ObjectName"] = data_map.get("ObjectName", "")
            record["AccessMask_Raw"] = data_map.get("AccessMask", "0x0")

        elif event_id == 4658:
            record["ObjectName"] = data_map.get("ObjectName", "")

        elif event_id == 4660:
            record["ObjectName"] = data_map.get("ObjectName", "")
            record["AccessMask_Raw"] = data_map.get("AccessMask", "0x0")

        elif event_id == 5140:
            record["ShareName"] = data_map.get("ShareName", "")
            record["ObjectName"] = data_map.get("ShareName", "")
            record["AccessMask_Raw"] = data_map.get("AccessMask", "0x0")

        # ---- Authentication Events ----
        elif event_id == 4624:
            record["TargetUserName"] = data_map.get("TargetUserName", "")
            record["LogonType"] = data_map.get("LogonType", "")
            record["SubjectUserName"] = (
                data_map.get("TargetUserName", "")
                or data_map.get("SubjectUserName", "")
            )

        elif event_id == 4625:
            record["TargetUserName"] = data_map.get("TargetUserName", "")
            record["LogonType"] = data_map.get("LogonType", "")
            record["FailureReason"] = (
                data_map.get("FailureReason", "")
                or data_map.get("Status", "")
            )
            record["SubjectUserName"] = (
                data_map.get("TargetUserName", "")
                or data_map.get("SubjectUserName", "")
            )

        elif event_id == 4648:
            record["TargetUserName"] = data_map.get("TargetUserName", "")
            record["ObjectName"] = data_map.get("TargetServerName", "")

        # ---- Process Execution Events ----
        elif event_id == 4688:
            record["NewProcessName"] = data_map.get("NewProcessName", "")
            record["CommandLine"] = data_map.get("CommandLine", "")
            record["ParentProcessName"] = data_map.get("ParentProcessName", "")
            record["ProcessName"] = data_map.get("NewProcessName", "")
            # Use creator subject as the user
            record["SubjectUserName"] = (
                data_map.get("SubjectUserName", "")
                or data_map.get("TargetUserName", "")
            )

        # ---- Persistence Events ----
        elif event_id == 4698:
            record["TaskName"] = data_map.get("TaskName", "")
            record["ObjectName"] = data_map.get("TaskName", "")

        elif event_id == 7045:
            record["ServiceName"] = data_map.get("ServiceName", "")
            record["ServiceFileName"] = data_map.get("ImagePath", data_map.get("ServiceFileName", ""))
            record["ObjectName"] = data_map.get("ServiceName", "")

        # ---- Anti-Forensics Events ----
        elif event_id == 1102:
            record["SubjectUserName"] = (
                data_map.get("SubjectUserName", "")
                or data_map.get("AccountName", "")
                or "SYSTEM"
            )
            record["ObjectName"] = "Audit Log Cleared"

        return record

    def _apply_access_mask_decoding(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Decode AccessMask into boolean flags for file-access events.
        Non-file-access events get all False flags.
        """
        df["_mask_int"] = df["AccessMask_Raw"].apply(self._hex_to_int)

        for col_name, flag_value in UEBA_RELEVANT_FLAGS.items():
            df[col_name] = (df["_mask_int"] & flag_value) != 0
            # Zero out flags for non-file-access events
            df.loc[~df["EventID"].isin(FILE_ACCESS_EVENT_IDS), col_name] = False

        df.drop(columns=["_mask_int"], inplace=True)
        return df

    @staticmethod
    def _detect_lolbin(row: pd.Series) -> bool:
        """Check if the process in this event is a known LOLBin."""
        for field in ["ProcessName", "NewProcessName", "ParentProcessName"]:
            val = row.get(field, "")
            if isinstance(val, str) and val:
                basename = val.rsplit("\\", 1)[-1].lower()
                if basename in LOLBIN_NAMES:
                    return True
        return False

    @staticmethod
    def _hex_to_int(value: Any) -> int:
        """Robustly convert a hex string to an integer."""
        if isinstance(value, (int, float)):
            return int(value)
        if not isinstance(value, str):
            return 0
        value = value.strip()
        if not value or value.lower() in ("nan", "none", "-", ""):
            return 0
        if value.startswith("%%"):
            return 0
        try:
            return int(value, 0)
        except ValueError:
            cleaned = re.sub(r"[^0-9a-fA-Fx]", "", value)
            try:
                return int(cleaned, 0)
            except ValueError:
                return 0

    @staticmethod
    def decode_access_mask(hex_value: str) -> dict[str, bool]:
        """Standalone utility to decode an AccessMask hex string."""
        mask = FileServerLogParser._hex_to_int(hex_value)
        return {
            name: (mask & flag) != 0
            for flag, name in ACCESS_MASK_FLAGS.items()
        }

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_event_id_json(entry: dict) -> int:
        """Extract EventID from various JSON formats."""
        for key in ("Id", "id", "EventID", "eventid", "event_id", "EventId"):
            if key in entry:
                try:
                    return int(entry[key])
                except (ValueError, TypeError):
                    pass
        system = entry.get("System", entry.get("system", {}))
        if isinstance(system, dict):
            eid = system.get("EventID", system.get("eventid"))
            if eid is not None:
                if isinstance(eid, dict):
                    eid = eid.get("#text", eid.get("value", 0))
                try:
                    return int(eid)
                except (ValueError, TypeError):
                    pass
        return 0

    @staticmethod
    def _flatten_json_entry(entry: dict, event_id: int = 0) -> dict[str, str]:
        """
        Flatten a JSON event entry into a key-value map.
        Handles PowerShell Properties-array format and flat-key format.
        """
        result: dict[str, str] = {}

        # All fields we care about across all Event IDs
        all_fields = [
            "SubjectUserName", "SubjectUserSid", "ObjectName",
            "ProcessName", "IpAddress", "AccessMask",
            "ShareName", "RelativeTargetName",
            "TargetUserName", "LogonType", "FailureReason", "Status",
            "NewProcessName", "CommandLine", "ParentProcessName",
            "TaskName", "ServiceName", "ImagePath", "ServiceFileName",
            "AccountName", "TargetServerName", "WorkstationName",
        ]

        # 1) Flat-key extraction
        for key in all_fields:
            for variant in (key, key.lower(), key.upper()):
                if variant in entry:
                    result[key] = str(entry[variant])
                    break

        # 2) Nested EventData
        event_data = entry.get("EventData", entry.get("eventdata", {}))
        if isinstance(event_data, dict):
            for key in all_fields:
                if key in event_data and key not in result:
                    val = event_data[key]
                    if isinstance(val, dict):
                        val = val.get("#text", str(val))
                    result[key] = str(val)

        # 3) Nested UserData (used by events like 1102)
        user_data = entry.get("UserData", entry.get("userdata", {}))
        if isinstance(user_data, dict):
            # UserData may have nested elements
            for sub_key, sub_val in user_data.items():
                if isinstance(sub_val, dict):
                    for k, v in sub_val.items():
                        if k in all_fields and k not in result:
                            result[k] = str(v)

        # 4) Properties array fallback
        properties = entry.get("Properties", entry.get("properties", []))
        if isinstance(properties, list) and not result.get("SubjectUserName"):
            if event_id == 0:
                event_id = FileServerLogParser._extract_event_id_json(entry)
            result.update(
                FileServerLogParser._map_properties_by_event(event_id, properties)
            )

        return result

    @staticmethod
    def _map_properties_by_event(
        event_id: int, properties: list
    ) -> dict[str, str]:
        """Map positional Properties array to named fields by Event ID."""
        def _val(idx: int) -> str:
            if idx < len(properties):
                item = properties[idx]
                if isinstance(item, dict):
                    return str(item.get("Value", item.get("value", "")))
                return str(item)
            return ""

        if event_id == 4663:
            return {
                "SubjectUserName": _val(1),
                "ObjectName":      _val(6),
                "AccessMask":      _val(9),
                "ProcessName":     _val(11),
            }
        elif event_id == 5145:
            return {
                "SubjectUserName":    _val(1),
                "IpAddress":          _val(5),
                "ShareName":          _val(7),
                "RelativeTargetName": _val(8),
                "AccessMask":         _val(9),
            }
        elif event_id == 4624:
            return {
                "SubjectUserName": _val(1),
                "TargetUserName":  _val(5),
                "LogonType":       _val(8),
                "IpAddress":       _val(18),
                "WorkstationName": _val(11),
                "ProcessName":     _val(17),
            }
        elif event_id == 4625:
            return {
                "SubjectUserName": _val(1),
                "TargetUserName":  _val(5),
                "LogonType":       _val(10),
                "FailureReason":   _val(7),
                "Status":          _val(7),
                "IpAddress":       _val(19),
            }
        elif event_id == 4648:
            return {
                "SubjectUserName":  _val(1),
                "TargetUserName":   _val(5),
                "TargetServerName": _val(7),
                "ProcessName":      _val(9),
            }
        elif event_id == 4688:
            return {
                "SubjectUserName":   _val(1),
                "NewProcessName":    _val(5),
                "CommandLine":       _val(8) if len(properties) > 8 else "",
                "ParentProcessName": _val(13) if len(properties) > 13 else "",
                "ProcessName":       _val(5),
            }
        elif event_id == 4656:
            return {
                "SubjectUserName": _val(1),
                "ObjectName":      _val(6),
                "AccessMask":      _val(9),
                "ProcessName":     _val(11),
            }
        elif event_id == 4660:
            return {
                "SubjectUserName": _val(1),
                "ObjectName":      _val(6),
                "ProcessName":     _val(7),
            }
        elif event_id == 4658:
            return {
                "SubjectUserName": _val(1),
                "ObjectName":      _val(5) if len(properties) > 5 else "",
            }
        elif event_id == 4698:
            return {
                "SubjectUserName": _val(1),
                "TaskName":        _val(4),
            }
        elif event_id == 5140:
            return {
                "SubjectUserName": _val(1),
                "ShareName":       _val(5),
                "IpAddress":       _val(7) if len(properties) > 7 else "",
                "AccessMask":      _val(8) if len(properties) > 8 else "",
            }
        elif event_id == 7045:
            return {
                "ServiceName":     _val(0),
                "ServiceFileName": _val(1),
                "SubjectUserName": _val(4) if len(properties) > 4 else "",
            }
        elif event_id == 1102:
            return {
                "SubjectUserName": _val(1) if len(properties) > 1 else "SYSTEM",
                "AccountName":     _val(1) if len(properties) > 1 else "",
            }
        return {}

    # ------------------------------------------------------------------
    # CSV / utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_column(
        col_map: dict[str, str], candidates: list[str]
    ) -> Optional[str]:
        """Find original column name from lowercase candidates."""
        for candidate in candidates:
            if candidate in col_map:
                return col_map[candidate]
        return None

    def _empty_dataframe(self) -> pd.DataFrame:
        """Return an empty DataFrame with the correct schema."""
        cols = OUTPUT_COLUMNS + list(UEBA_RELEVANT_FLAGS.keys()) + ["is_lolbin"]
        return pd.DataFrame(columns=cols)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def parse_log_file(file_path: str) -> pd.DataFrame:
    """Parse a log file and return a standardized DataFrame."""
    parser = FileServerLogParser(file_path)
    return parser.parse()
