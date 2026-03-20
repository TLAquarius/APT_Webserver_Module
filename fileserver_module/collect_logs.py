"""
=============================================================================
Module: collect_logs — Windows Event Log Collection for UEBA Pipeline
=============================================================================

Purpose:
    Collects real Windows Security Event Logs (Event IDs 4663 & 5145) from
    the local machine and exports them to JSON or CSV format for analysis
    by the UEBA pipeline.

    This script provides TWO collection methods:

      1. **Python-native (win32evtlog)** — Uses the ``pywin32`` library to
         query the Windows Event Log API directly. Works on any Windows
         machine with Python installed.

      2. **PowerShell fallback** — Generates and executes a PowerShell
         script using ``Get-WinEvent`` with ``FilterHashtable``. This is
         the most reliable method and works even if ``pywin32`` is not
         installed.

Requirements:
    • Must be run on Windows with **Administrator privileges** to read
      the Security log.
    • Audit Policy must be configured to log Object Access events:
      ``auditpol /set /subcategory:"File System" /success:enable /failure:enable``
      ``auditpol /set /subcategory:"File Share" /success:enable /failure:enable``

Usage:
    Interactive:
        ``python collect_logs.py``

    CLI:
        ``python collect_logs.py --method powershell --days 7 --output logs.json``
        ``python collect_logs.py --method python --days 30 --output logs.csv``

Author:  UEBA Pipeline — Phase 1
Python:  3.9+
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# All 13 APT-relevant Event IDs — the pipeline now supports all of these
TARGET_EVENT_IDS: list[int] = [
    4624, 4625, 4648,          # Authentication
    4656, 4658, 4660, 4663,    # Object Access
    4688,                       # Process Execution
    4698,                       # Persistence (Scheduled Task)
    5140, 5145,                 # Network Share
    7045,                       # Persistence (Service Install)
    1102,                       # Anti-Forensics
]

# Additional useful Event IDs (optional, for extended collection)
EXTENDED_EVENT_IDS: list[int] = [
    4624,   # Successful Logon (Lateral Movement detection)
    4625,   # Failed Logon (Brute-force / Password Spraying)
    4648,   # Explicit Credential Logon (Pass-the-Hash)
    4656,   # Handle Requested (pre-access)
    4658,   # Handle Closed
    4660,   # Object Deleted
    4663,   # Object Access (core — file read/write/delete)
    4688,   # Process Created (LOLBin detection)
    4698,   # Scheduled Task Created (Persistence)
    5140,   # Network Share Accessed (session-level)
    5145,   # Detailed File Share (core — SMB file access)
    7045,   # Service Installed (Persistence)
    1102,   # Audit Log Cleared (Anti-Forensics)
]

# Fields to extract from each event
EVENT_FIELDS: list[str] = [
    "TimeCreated",
    "EventID",
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "ObjectServer",
    "ObjectType",
    "ObjectName",
    "HandleId",
    "AccessList",
    "AccessMask",
    "ProcessId",
    "ProcessName",
    "ShareName",
    "ShareLocalPath",
    "RelativeTargetName",
    "IpAddress",
    "IpPort",
]


def is_admin() -> bool:
    """Check if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False


def check_audit_policy() -> dict[str, str]:
    """
    Check current Windows Audit Policy for Object Access categories.

    Returns:
        Dict mapping subcategory names to their audit settings.
    """
    result = {}
    try:
        output = subprocess.run(
            ["auditpol", "/get", "/category:Object Access"],
            capture_output=True, text=True, timeout=10,
        )
        if output.returncode == 0:
            for line in output.stdout.splitlines():
                line = line.strip()
                if any(kw in line.lower() for kw in ["file system", "file share", "detailed file share"]):
                    parts = line.rsplit(None, 2)
                    if len(parts) >= 2:
                        result[parts[0].strip()] = " ".join(parts[1:]).strip()
    except Exception as e:
        logger.warning("Could not check audit policy: %s", e)
    return result


def enable_audit_policy() -> bool:
    """
    Enable the required audit policies for file-server monitoring.

    Enables:
      • File System auditing (generates Event 4663)
      • File Share auditing (generates Event 5140)
      • Detailed File Share auditing (generates Event 5145)

    Returns:
        True if all policies were enabled successfully.
    """
    policies = [
        ("File System", "Tạo Event 4663 — Object Access"),
        ("File Share", "Tạo Event 5140 — Share Accessed"),
        ("Detailed File Share", "Tạo Event 5145 — Detailed Share"),
    ]

    all_ok = True
    for subcategory, description in policies:
        try:
            result = subprocess.run(
                [
                    "auditpol", "/set",
                    "/subcategory:" + subcategory,
                    "/success:enable",
                    "/failure:enable",
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                print(f"  ✅ Đã bật: {subcategory} ({description})")
            else:
                print(f"  ❌ Lỗi khi bật: {subcategory} — {result.stderr.strip()}")
                all_ok = False
        except Exception as e:
            print(f"  ❌ Lỗi: {subcategory} — {e}")
            all_ok = False

    return all_ok


# ===========================================================================
# Collection Method 1: PowerShell (Recommended)
# ===========================================================================

def collect_via_powershell(
    days: int = 7,
    output_path: str = "collected_logs.json",
    event_ids: list[int] | None = None,
    extended: bool = False,
    log_name: str = "Security",
) -> str:
    """
    Collect Windows Event Logs using PowerShell's Get-WinEvent.

    This is the RECOMMENDED method because:
      • Works without any additional Python packages.
      • PowerShell has native, optimized access to the Event Log API.
      • Supports complex filtering via FilterHashtable.
      • Handles XML parsing of EventData natively.

    The generated PowerShell script:
      1. Queries the Security log with FilterHashtable for target Event IDs.
      2. Filters by time range (last N days).
      3. Extracts all relevant fields from the event XML.
      4. Exports to JSON (or CSV) with proper encoding.

    Args:
        days: Number of days of historical logs to collect.
        output_path: Path for the output file (.json or .csv).
        event_ids: List of Event IDs to collect. Defaults to [4663, 5145].
        extended: If True, collect all APT-relevant Event IDs.
        log_name: Windows Event Log name (default: "Security").

    Returns:
        Absolute path to the exported log file.
    """
    if event_ids is None:
        event_ids = EXTENDED_EVENT_IDS if extended else TARGET_EVENT_IDS

    output_path_obj = Path(output_path).resolve()
    output_format = output_path_obj.suffix.lower()

    # Build the Event ID filter for PowerShell
    id_list = ", ".join(str(eid) for eid in event_ids)

    # Build the PowerShell script
    ps_script = textwrap.dedent(f"""\
        # ====================================================================
        # APT File Server — Windows Event Log Collection Script
        # Generated by collect_logs.py
        # Target: Event IDs {id_list} from the last {days} day(s)
        # ====================================================================

        $ErrorActionPreference = 'SilentlyContinue'

        # Time filter: last {days} day(s)
        $StartTime = (Get-Date).AddDays(-{days})

        Write-Host "[*] Thu thap log tu {log_name} log..." -ForegroundColor Cyan
        Write-Host "[*] Event IDs: {id_list}" -ForegroundColor Cyan
        Write-Host "[*] Tu: $StartTime den: $(Get-Date)" -ForegroundColor Cyan

        # Query with FilterHashtable (optimized at the API level)
        $Events = Get-WinEvent -FilterHashtable @{{
            LogName   = '{log_name}'
            ID        = {id_list}
            StartTime = $StartTime
        }} -ErrorAction SilentlyContinue

        if (-not $Events -or $Events.Count -eq 0) {{
            Write-Host "[!] CANH BAO: Khong tim thay event nao!" -ForegroundColor Yellow
            Write-Host "[!] Kiem tra:" -ForegroundColor Yellow
            Write-Host "    1. Script dang chay voi quyen Administrator" -ForegroundColor Yellow
            Write-Host "    2. Audit Policy da duoc bat:" -ForegroundColor Yellow
            Write-Host "       auditpol /set /subcategory:'File System' /success:enable /failure:enable" -ForegroundColor Yellow
            Write-Host "       auditpol /set /subcategory:'Detailed File Share' /success:enable /failure:enable" -ForegroundColor Yellow
            Write-Host "    3. SACL da duoc cau hinh tren thu muc can giam sat" -ForegroundColor Yellow
            exit 1
        }}

        Write-Host "[+] Tim thay $($Events.Count) events!" -ForegroundColor Green

        # Parse each event's XML to extract detailed fields
        $ParsedEvents = @()
        $Counter = 0

        foreach ($Event in $Events) {{
            $Counter++
            if ($Counter % 500 -eq 0) {{
                Write-Host "[*] Dang xu ly: $Counter / $($Events.Count)..." -ForegroundColor Gray
            }}

            # Parse the event XML
            [xml]$XmlData = $Event.ToXml()
            $EventData = @{{}}

            # Extract all <Data Name="..."> elements from <EventData>
            $XmlData.Event.EventData.Data | ForEach-Object {{
                if ($_.Name) {{
                    $EventData[$_.Name] = $_.'#text'
                }}
            }}

            # Build the standardized record
            $Record = [PSCustomObject]@{{
                TimeCreated       = $Event.TimeCreated.ToString('o')
                EventID           = $Event.Id
                SubjectUserSid    = $EventData['SubjectUserSid']
                SubjectUserName   = $EventData['SubjectUserName']
                SubjectDomainName = $EventData['SubjectDomainName']
                SubjectLogonId    = $EventData['SubjectLogonId']
                ObjectServer      = $EventData['ObjectServer']
                ObjectType        = $EventData['ObjectType']
                ObjectName        = $EventData['ObjectName']
                HandleId          = $EventData['HandleId']
                AccessList        = $EventData['AccessList']
                AccessMask        = $EventData['AccessMask']
                ProcessId         = $EventData['ProcessId']
                ProcessName       = $EventData['ProcessName']
                ShareName         = $EventData['ShareName']
                ShareLocalPath    = $EventData['ShareLocalPath']
                RelativeTargetName = $EventData['RelativeTargetName']
                IpAddress         = $EventData['IpAddress']
                IpPort            = $EventData['IpPort']
                MachineName       = $Event.MachineName
                LogName           = $Event.LogName
            }}

            $ParsedEvents += $Record
        }}

        Write-Host "[+] Da xu ly xong $($ParsedEvents.Count) events." -ForegroundColor Green
    """)

    # Add export command based on format
    if output_format == ".csv":
        ps_script += f"""
        # Export to CSV
        $ParsedEvents | Export-Csv -Path '{output_path_obj}' -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Da xuat ra CSV: {output_path_obj}" -ForegroundColor Green
        """
    else:
        ps_script += f"""
        # Export to JSON (depth 5 for nested structures)
        $ParsedEvents | ConvertTo-Json -Depth 5 | Out-File -FilePath '{output_path_obj}' -Encoding UTF8
        Write-Host "[+] Da xuat ra JSON: {output_path_obj}" -ForegroundColor Green
        """

    ps_script += """
        # Summary statistics
        Write-Host ""
        Write-Host "=== THONG KE ===" -ForegroundColor Cyan
        $ParsedEvents | Group-Object EventID | ForEach-Object {
            Write-Host "  Event $($_.Name): $($_.Count) records" -ForegroundColor White
        }

        # User summary
        Write-Host ""
        Write-Host "=== NGUOI DUNG ===" -ForegroundColor Cyan
        $ParsedEvents | Group-Object SubjectUserName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Count) events" -ForegroundColor White
        }

        Write-Host ""
        Write-Host "[+] HOAN THANH! File log da san sang de phan tich." -ForegroundColor Green
    """

    # Save the PowerShell script
    ps_script_path = output_path_obj.parent / "collect_events.ps1"
    with open(ps_script_path, "w", encoding="utf-8-sig") as f:
        f.write(ps_script)

    print(f"\n📜 PowerShell script đã được tạo: {ps_script_path}")
    print(f"📂 Output sẽ được lưu tại: {output_path_obj}")

    # Execute the PowerShell script
    print("\n⏳ Đang thu thập log...")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(ps_script_path),
            ],
            capture_output=False,
            timeout=600,  # 10 minute timeout
        )

        if result.returncode == 0 and output_path_obj.exists():
            file_size = output_path_obj.stat().st_size
            print(f"\n✅ Thu thập thành công! File size: {file_size / 1024:.1f} KB")
            return str(output_path_obj)
        else:
            print(f"\n⚠ PowerShell trả về mã lỗi: {result.returncode}")
            print(f"  Script đã được lưu tại: {ps_script_path}")
            print(f"  Bạn có thể chạy thủ công bằng cách mở PowerShell (Admin) và chạy:")
            print(f"    powershell -ExecutionPolicy Bypass -File \"{ps_script_path}\"")
            return str(ps_script_path)

    except subprocess.TimeoutExpired:
        print("\n⚠ Quá thời gian chờ (10 phút). Log có thể rất lớn.")
        print(f"  Chạy thủ công: powershell -ExecutionPolicy Bypass -File \"{ps_script_path}\"")
        return str(ps_script_path)
    except Exception as e:
        print(f"\n⚠ Lỗi khi chạy PowerShell: {e}")
        print(f"  Chạy thủ công: powershell -ExecutionPolicy Bypass -File \"{ps_script_path}\"")
        return str(ps_script_path)


# ===========================================================================
# Collection Method 2: Python-native (win32evtlog)
# ===========================================================================

def collect_via_python(
    days: int = 7,
    output_path: str = "collected_logs.json",
    event_ids: list[int] | None = None,
    extended: bool = False,
    log_name: str = "Security",
) -> str:
    """
    Collect Windows Event Logs using Python's win32evtlog (pywin32).

    This method uses the Windows Event Log API directly through the
    ``pywin32`` package. It's useful when PowerShell execution policies
    are restricted.

    Args:
        days: Number of days of historical logs to collect.
        output_path: Path for the output file (.json or .csv).
        event_ids: List of Event IDs to collect. Defaults to [4663, 5145].
        extended: If True, collect all APT-relevant Event IDs.
        log_name: Windows Event Log name (default: "Security").

    Returns:
        Absolute path to the exported log file.
    """
    try:
        import win32evtlog
        import win32evtlogutil
        import pywintypes
    except ImportError:
        print("❌ Package 'pywin32' chưa được cài đặt.")
        print("   Cài đặt bằng: pip install pywin32")
        print("   Hoặc sử dụng phương pháp PowerShell: --method powershell")
        sys.exit(1)

    if event_ids is None:
        event_ids = EXTENDED_EVENT_IDS if extended else TARGET_EVENT_IDS

    output_path_obj = Path(output_path).resolve()
    event_ids_set = set(event_ids)

    # Calculate time filter
    start_time = datetime.now() - timedelta(days=days)

    print(f"\n⏳ Đang thu thập log từ {log_name}...")
    print(f"   Event IDs: {', '.join(map(str, event_ids))}")
    print(f"   Từ: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    records: list[dict[str, Any]] = []
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
    except Exception as e:
        print(f"❌ Không thể mở {log_name} log: {e}")
        print("   Đảm bảo script chạy với quyền Administrator.")
        sys.exit(1)

    total_read = 0
    matched = 0

    try:
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break

            for event in events:
                total_read += 1

                # Time filter
                event_time = datetime(
                    event.TimeGenerated.year,
                    event.TimeGenerated.month,
                    event.TimeGenerated.day,
                    event.TimeGenerated.hour,
                    event.TimeGenerated.minute,
                    event.TimeGenerated.second,
                )
                if event_time < start_time:
                    continue

                # Event ID filter
                if event.EventID & 0xFFFF not in event_ids_set:
                    continue

                matched += 1
                if matched % 500 == 0:
                    print(f"   Đã thu thập: {matched} events...")

                # Extract fields from string inserts
                strings = event.StringInserts or []

                record = {
                    "TimeCreated": event_time.isoformat(),
                    "EventID": event.EventID & 0xFFFF,
                    "SourceName": event.SourceName,
                    "MachineName": event.ComputerName,
                }

                # Map string inserts based on Event ID
                eid = event.EventID & 0xFFFF
                if eid == 4663 and len(strings) >= 10:
                    record.update({
                        "SubjectUserSid": strings[0] if len(strings) > 0 else "",
                        "SubjectUserName": strings[1] if len(strings) > 1 else "",
                        "SubjectDomainName": strings[2] if len(strings) > 2 else "",
                        "SubjectLogonId": strings[3] if len(strings) > 3 else "",
                        "ObjectServer": strings[4] if len(strings) > 4 else "",
                        "ObjectType": strings[5] if len(strings) > 5 else "",
                        "ObjectName": strings[6] if len(strings) > 6 else "",
                        "HandleId": strings[7] if len(strings) > 7 else "",
                        "AccessList": strings[8] if len(strings) > 8 else "",
                        "AccessMask": strings[9] if len(strings) > 9 else "",
                        "ProcessId": strings[10] if len(strings) > 10 else "",
                        "ProcessName": strings[11] if len(strings) > 11 else "",
                    })
                elif eid == 5145 and len(strings) >= 10:
                    record.update({
                        "SubjectUserSid": strings[0] if len(strings) > 0 else "",
                        "SubjectUserName": strings[1] if len(strings) > 1 else "",
                        "SubjectDomainName": strings[2] if len(strings) > 2 else "",
                        "SubjectLogonId": strings[3] if len(strings) > 3 else "",
                        "ObjectType": strings[4] if len(strings) > 4 else "",
                        "IpAddress": strings[5] if len(strings) > 5 else "",
                        "IpPort": strings[6] if len(strings) > 6 else "",
                        "ShareName": strings[7] if len(strings) > 7 else "",
                        "RelativeTargetName": strings[8] if len(strings) > 8 else "",
                        "AccessMask": strings[9] if len(strings) > 9 else "",
                        "AccessList": strings[10] if len(strings) > 10 else "",
                    })
                elif eid == 4624 and len(strings) >= 19:
                    record.update({
                        "SubjectUserName": strings[5] if len(strings) > 5 else "",
                        "SubjectDomainName": strings[6] if len(strings) > 6 else "",
                        "LogonType": strings[8] if len(strings) > 8 else "",
                        "IpAddress": strings[18] if len(strings) > 18 else "",
                        "ProcessName": strings[17] if len(strings) > 17 else "",
                    })
                elif eid == 4688 and len(strings) >= 9:
                    record.update({
                        "SubjectUserName": strings[1] if len(strings) > 1 else "",
                        "SubjectDomainName": strings[2] if len(strings) > 2 else "",
                        "ProcessName": strings[5] if len(strings) > 5 else "",
                        "CommandLine": strings[8] if len(strings) > 8 else "",
                    })
                else:
                    # Generic: dump all string inserts
                    for i, s in enumerate(strings):
                        record[f"Field_{i}"] = s

                records.append(record)

    except Exception as e:
        print(f"\n⚠ Lỗi khi đọc log: {e}")
    finally:
        win32evtlog.CloseEventLog(handle)

    print(f"\n📊 Đã quét: {total_read:,} events tổng")
    print(f"   Matched: {matched:,} events")

    if not records:
        print("\n⚠ Không tìm thấy event nào phù hợp.")
        print("   Kiểm tra Audit Policy và SACL configuration.")
        return ""

    # Export
    _export_records(records, output_path_obj)
    return str(output_path_obj)


# ===========================================================================
# Export Helpers
# ===========================================================================

def _export_records(records: list[dict], output_path: Path) -> None:
    """Export collected records to JSON or CSV."""
    output_format = output_path.suffix.lower()

    if output_format == ".csv":
        import csv
        # Collect all possible field names
        fieldnames: list[str] = []
        for r in records:
            for k in r.keys():
                if k not in fieldnames:
                    fieldnames.append(k)

        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False, default=str)

    file_size = output_path.stat().st_size
    print(f"\n✅ Đã xuất {len(records):,} events → {output_path}")
    print(f"   File size: {file_size / 1024:.1f} KB")

    # Print summary
    from collections import Counter
    eid_counts = Counter(r.get("EventID") for r in records)
    user_counts = Counter(r.get("SubjectUserName", "N/A") for r in records)

    print(f"\n📊 Thống kê Event ID:")
    for eid, count in sorted(eid_counts.items()):
        print(f"   Event {eid}: {count:,} records")

    print(f"\n👤 Top 10 người dùng:")
    for user, count in user_counts.most_common(10):
        print(f"   {user}: {count:,} events")


# ===========================================================================
# Audit Configuration Helper
# ===========================================================================

def setup_file_auditing(target_path: str = None) -> None:
    """
    Guide the user through setting up SACL (System Access Control List)
    on a target folder for file-access auditing.

    Without SACL configuration, Windows will NOT generate Event 4663
    even if the audit policy is enabled.

    Args:
        target_path: Path to the folder to audit. If None, provides
                     general instructions.
    """
    print("\n" + "=" * 60)
    print("  HƯỚNG DẪN CẤU HÌNH SACL (System Access Control List)")
    print("=" * 60)
    print("""
    Để Windows sinh ra Event 4663 (Object Access), bạn cần:

    1. BẬT AUDIT POLICY (script này tự động thực hiện)
       auditpol /set /subcategory:"File System" /success:enable /failure:enable

    2. CẤU HÌNH SACL TRÊN THƯ MỤC CẦN GIÁM SÁT
       a. Nhấn phải vào thư mục cần giám sát → Properties
       b. Chọn tab Security → Advanced → Auditing
       c. Nhấn Add → Select a principal → Everyone → OK
       d. Type: All
       e. Tích các quyền cần giám sát:
          ☑ List folder / read data
          ☑ Create files / write data
          ☑ Create folders / append data
          ☑ Delete
          ☑ Change permissions
          ☑ Take ownership
       f. Tích "Apply to: This folder, subfolders and files"
       g. OK → Apply

    HOẶC dùng PowerShell (chạy với quyền Admin):
    """)

    if target_path:
        print(f"""
    $Path = "{target_path}"
    $Acl = Get-Acl $Path -Audit
    $Rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "ReadData,WriteData,AppendData,Delete,ChangePermissions,TakeOwnership",
        "ContainerInherit,ObjectInherit",
        "None",
        "Success,Failure"
    )
    $Acl.AddAuditRule($Rule)
    Set-Acl $Path $Acl
    Write-Host "SACL configured for: $Path"
        """)
    else:
        print("""
    # Thay <ĐƯỜNG_DẪN> bằng thư mục cần giám sát, ví dụ: C:\\Shares
    $Path = "<ĐƯỜNG_DẪN>"
    $Acl = Get-Acl $Path -Audit
    $Rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "ReadData,WriteData,AppendData,Delete,ChangePermissions,TakeOwnership",
        "ContainerInherit,ObjectInherit",
        "None",
        "Success,Failure"
    )
    $Acl.AddAuditRule($Rule)
    Set-Acl $Path $Acl
    Write-Host "SACL configured for: $Path"
        """)


# ===========================================================================
# Main Entry Point
# ===========================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Thu thập Windows Event Log cho UEBA Pipeline\n"
            "Yêu cầu chạy với quyền Administrator"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--method", "-m",
        choices=["powershell", "python"],
        default="powershell",
        help="Phương pháp thu thập: 'powershell' (khuyến nghị) hoặc 'python' (cần pywin32). Mặc định: powershell",
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        default=7,
        help="Số ngày log cần thu thập (tính từ hiện tại). Mặc định: 7",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="collected_logs.json",
        help="Đường dẫn file xuất (.json hoặc .csv). Mặc định: collected_logs.json",
    )
    parser.add_argument(
        "--extended", "-e",
        action="store_true",
        help="Thu thập thêm các Event ID mở rộng (4624, 4625, 4688, 4698, 7045, 1102...)",
    )
    parser.add_argument(
        "--setup-audit",
        action="store_true",
        help="Hiển thị hướng dẫn cấu hình Audit Policy và SACL",
    )
    parser.add_argument(
        "--enable-audit",
        action="store_true",
        help="Tự động bật Audit Policy cho Object Access (cần quyền Admin)",
    )
    parser.add_argument(
        "--audit-path",
        type=str,
        default=None,
        help="Đường dẫn thư mục để cấu hình SACL tự động",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point for log collection."""
    args = parse_arguments()

    print("\n" + "=" * 60)
    print("  🔍 APT File Server — Thu thập Windows Event Log")
    print("  UEBA Pipeline — Log Collection Module")
    print("=" * 60)

    # Check admin privileges
    if not is_admin():
        print("\n❌ CẢNH BÁO: Script KHÔNG chạy với quyền Administrator!")
        print("   Để đọc Security log, cần chạy lại với quyền Admin.")
        print("   Cách chạy:")
        print("     1. Mở PowerShell/CMD với quyền Administrator")
        print("     2. Chạy: python collect_logs.py")
        print("\n   Tiếp tục mà không có quyền Admin? (có thể không đọc được Security log)")
        try:
            response = input("   [y/N]: ").strip().lower()
            if response != "y":
                sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)

    # Setup audit if requested
    if args.setup_audit:
        setup_file_auditing(args.audit_path)
        return

    if args.enable_audit:
        print("\n🔧 Đang bật Audit Policy...")
        enable_audit_policy()
        print()

    # Check current audit policy
    print("\n📋 Kiểm tra Audit Policy hiện tại:")
    policy = check_audit_policy()
    if policy:
        for subcategory, setting in policy.items():
            status = "✅" if "success" in setting.lower() else "⚠"
            print(f"   {status} {subcategory}: {setting}")
    else:
        print("   ⚠ Không thể kiểm tra (có thể thiếu quyền)")

    # Collect logs
    print(f"\n📥 Phương pháp: {args.method.upper()}")
    print(f"   Khoảng thời gian: {args.days} ngày gần nhất")
    print(f"   Event IDs: {'Mở rộng (all APT-relevant)' if args.extended else '4663, 5145 (core)'}")
    print(f"   Output: {args.output}")

    if args.method == "powershell":
        result = collect_via_powershell(
            days=args.days,
            output_path=args.output,
            extended=args.extended,
        )
    else:
        result = collect_via_python(
            days=args.days,
            output_path=args.output,
            extended=args.extended,
        )

    if result:
        print(f"\n{'=' * 60}")
        print(f"  ✅ HOÀN THÀNH!")
        print(f"  📂 File log: {result}")
        print(f"\n  Bước tiếp theo — chạy phân tích UEBA:")
        print(f"    python main.py --file \"{result}\"")
        print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
