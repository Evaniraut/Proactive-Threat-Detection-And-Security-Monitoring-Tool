#!/usr/bin/env python3
import json
import time
import os

# Path to your real Wazuh archives
ARCHIVES_PATH = "/var/ossec/logs/archives/archives.json"
# Path to feed ML monitor.py
ML_INPUT_PATH = "/var/ossec/logs/ml_input.json"

# Mapping: Windows EventID -> severity and description for the ML Model
EVENT_MAP = {
    "4625": {"level": 5, "description": "Failed login attempt"},
    "5156": {"level": 3, "description": "Network connection permitted"},
    "5158": {"level": 4, "description": "Network connection blocked"},
    "4624": {"level": 1, "description": "Successful logon"},
}

def tail_f(file_path):
    """Generator to emulate 'tail -f'"""
    # Wait for file to exist if it doesn't
    while not os.path.exists(file_path):
        time.sleep(1)

    with open(file_path, "r") as f:
        f.seek(0, 2)  # Go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def convert_to_ml_format(wazuh_event):
    """Map Wazuh event to ML expected JSON"""
    try:
        data = json.loads(wazuh_event)
    except json.JSONDecodeError:
        return None

    # Extract eventID from Windows EventChannel structure
    win_data = data.get("data", {}).get("win", {}).get("system", {})
    event_id = str(win_data.get("eventID", "unknown"))

    # Map level & description based on ID
    rule_info = EVENT_MAP.get(event_id, {"level": 2, "description": f"Windows Event {event_id}"})

    ml_log = {
        "timestamp": data.get("timestamp"),
        "rule": {
            "level": rule_info["level"],
            "description": rule_info["description"]
        },
        "full_log": json.dumps(data),
        "location": data.get("location", "EventChannel"),
        "agent": data.get("agent", {}),
        "manager": data.get("manager", {})
    }

    return ml_log

if __name__ == "__main__":
    print(f"[*] Starting bridge: Wazuh archives -> ML input ({ML_INPUT_PATH})")
    try:
        for line in tail_f(ARCHIVES_PATH):
            ml_event = convert_to_ml_format(line.strip())
            if ml_event:
                with open(ML_INPUT_PATH, "a") as out:
                    out.write(json.dumps(ml_event) + "\n")
                print(f"[+] Converted: {ml_event['rule']['description']} (ID: {ml_event['agent'].get('id')})")
    except KeyboardInterrupt:
        print("\n[!] Bridge stopped.")
