import json
import random
from datetime import datetime, timedelta

def generate_mock_logs():
    base_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30)
    records = []
    
    users = [f"user_{i:02d}" for i in range(1, 21)]
    users.extend(["admin_01", "admin_02"])
    
    # 1. Normal Activity
    for day in range(30):
        current_date = base_time + timedelta(days=day)
        for hour in range(8, 18): # Business hours
            # Generating 300 events per hour across all 22 users
            for _ in range(300): 
                user = random.choice(users)
                ts = current_date + timedelta(hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59))
                
                roll = random.random()
                if roll < 0.6:
                    # File Access (4663)
                    records.append({
                        "TimeCreated": ts.isoformat() + "Z",
                        "EventID": 4663,
                        "SubjectUserName": user,
                        "ObjectName": f"C:\\Shares\\Dept\\file_{random.randint(1, 200)}.docx",
                        "ProcessName": random.choice(["explorer.exe", "winword.exe", "excel.exe"]),
                        "IpAddress": "local",
                        "AccessMask": random.choice(["0x1", "0x2", "0x3"])
                    })
                elif roll < 0.8:
                    # Auth (4624)
                    records.append({
                        "TimeCreated": ts.isoformat() + "Z",
                        "EventID": 4624,
                        "SubjectUserName": user,
                        "ProcessName": "lsass.exe",
                        "IpAddress": f"10.0.{random.randint(1,5)}.{random.randint(10,50)}",
                        "TargetUserName": user,
                        "LogonType": "3"
                    })
                elif roll < 0.9:
                    # Process (4688)
                    records.append({
                        "TimeCreated": ts.isoformat() + "Z",
                        "EventID": 4688,
                        "SubjectUserName": user,
                        "ProcessName": random.choice(["notepad.exe", "calc.exe", "chrome.exe"]),
                        "NewProcessName": random.choice(["notepad.exe", "calc.exe", "chrome.exe"]),
                        "ParentProcessName": "explorer.exe",
                    })
                else:
                    # Share (5140)
                    records.append({
                        "TimeCreated": ts.isoformat() + "Z",
                        "EventID": 5140,
                        "SubjectUserName": user,
                        "ShareName": "\\\\*\\Shares",
                        "IpAddress": f"10.0.1.{random.randint(10,50)}",
                        "AccessMask": "0x1"
                    })
                    
    # 2. APT Attack Activity (Compromised User) - Day 25 off-hours
    attack_time = base_time + timedelta(days=25, hours=2)
    attacker = "user_07" # Compromised user
    
    # Brute force (4625)
    for _ in range(50):
        records.append({
            "TimeCreated": attack_time.isoformat() + "Z",
            "EventID": 4625,
            "SubjectUserName": attacker,
            "TargetUserName": attacker,
            "LogonType": "3",
            "FailureReason": "%%2313",
            "IpAddress": "185.220.101.42"
        })
        attack_time += timedelta(seconds=2)
        
    # Success logon (4624)
    records.append({
        "TimeCreated": attack_time.isoformat() + "Z",
        "EventID": 4624,
        "SubjectUserName": attacker,
        "TargetUserName": attacker,
        "LogonType": "3",
        "IpAddress": "185.220.101.42"
    })
    attack_time += timedelta(seconds=5)
    
    # LOLBin Execution (4688)
    records.append({
        "TimeCreated": attack_time.isoformat() + "Z",
        "EventID": 4688,
        "SubjectUserName": attacker,
        "ProcessName": "C:\\Windows\\System32\\powershell.exe",
        "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell -enc SQBFAFgA...",
        "ParentProcessName": "cmd.exe"
    })
    attack_time += timedelta(seconds=2)
    
    # Mass File Read (4663)
    for i in range(500):
        records.append({
            "TimeCreated": attack_time.isoformat() + "Z",
            "EventID": 4663,
            "SubjectUserName": attacker,
            "ObjectName": f"\\\\DC01\\C$\\Users\\admin\\secrets_{i}.pdf",
            "ProcessName": "C:\\Windows\\System32\\powershell.exe",
            "AccessMask": "0x1"
        })
        attack_time += timedelta(seconds=1)
        
    # Persistence (4698)
    records.append({
        "TimeCreated": attack_time.isoformat() + "Z",
        "EventID": 4698,
        "SubjectUserName": attacker,
        "TaskName": "\\Microsoft\\Windows\\Maintenance\\UpdateCheck"
    })
    attack_time += timedelta(seconds=2)
    
    # Anti-forensics (1102)
    records.append({
        "TimeCreated": attack_time.isoformat() + "Z",
        "EventID": 1102,
        "SubjectUserName": attacker,
        "AccountName": attacker
    })

    # Sort all records chronologically
    records.sort(key=lambda x: x["TimeCreated"])

    out_file = "mock_logs_large.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
        
    print(f"✅ Generated {len(records)} events and saved to {out_file}")

if __name__ == "__main__":
    generate_mock_logs()
