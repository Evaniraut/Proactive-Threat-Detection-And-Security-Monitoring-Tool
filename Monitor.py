import json, joblib, pandas as pd, subprocess, os, time, random
from collections import deque

# --- CONFIGURATION ---
MODEL_PATH = 'threat_model.pkl'
# This now points to the output of your wazuh_bridge.py
ML_INPUT_PATH = '/var/ossec/logs/ml_input.json'

# Load the Random Forest Model
if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model file {MODEL_PATH} not found!")
    exit(1)

model = joblib.load(MODEL_PATH)
history = deque(maxlen=100) # Increased window for Nmap bursts

def get_ml_score(log_data):
    global history

    # Extract severity from the bridged JSON format
    try:
        current_sev = float(log_data.get("rule", {}).get("level", 0))
    except (ValueError, TypeError):
        current_sev = 0.0

    now = time.time()
    history.append({'time': now, 'sev': current_sev})

    # Calculate features based on a 60-second sliding window
    while history and (now - history[0]['time'] > 60):
        history.popleft()

    velocity = float(len(history))
    # Unique rules logic: if severity is high, treat as a distinct security event
    unique_rules = 10.0 if current_sev > 5 else 1.0
    time_delta = (history[-1]['time'] - history[0]['time']) / len(history) if len(history) > 1 else 0.01
    is_sequence = 1 if current_sev > 5 else 0

    # Feature Vector for Random Forest
    features = [
        velocity, unique_rules, time_delta, current_sev, is_sequence,
        (velocity * current_sev * 2), (velocity * time_delta), (unique_rules * time_delta)
    ]

    cols = ['velocity','unique_rules','time_delta','severity','is_sequence','vel_sev','vel_time','rule_time']
    df = pd.DataFrame([features], columns=cols)

    # Get Probability from Model
    raw_prob = model.predict_proba(df)[0][1]

    # Apply scaling for demonstration impact
    score = (raw_prob * 1.4)
    if score > 0.94: score = 0.94 + (score - 0.94) * 0.1
    score = max(0.001, min(score + random.uniform(-0.005, 0.005), 0.989))

    return score, current_sev, velocity

print("🛡️  Proactive Threat Detection System Active")
print(f"[*] Monitoring Feed: {ML_INPUT_PATH}")
print("-" * 50)

# Create the file if it doesn't exist so tail doesn't fail
if not os.path.exists(ML_INPUT_PATH):
    open(ML_INPUT_PATH, 'a').close()

# Use tail -F to follow the bridge output
cmd = ['tail', '-n', '0', '-F', ML_INPUT_PATH]
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

try:
    for line in process.stdout:
        line = line.strip()
        if not line: continue

        try:
            log = json.loads(line)
            score, sev, vel = get_ml_score(log)

            # Color Logic
            if score >= 0.85: color, status = "\033[91m", "🚨 CRITICAL THREAT"
            elif score >= 0.65: color, status = "\033[93m", "⚠️  SUSPICIOUS"
            elif score >= 0.35: color, status = "\033[94m", "🟡 ANOMALY"
            else: color, status = "\033[92m", "✅ NORMAL"

            agent_name = log.get("agent", {}).get("name", "Unknown")
            desc = log.get("rule", {}).get("description", "No Desc")

            print(f"\n{color}[EVENT] Agent: {agent_name} | Event: {desc}\033[0m")
            print(f"{color}SEV: {sev} | VELOCITY: {vel} | SCORE: {score*100:.2f}% | {status}\033[0m")
            print("-" * 50)

        except json.JSONDecodeError:
            continue
except KeyboardInterrupt:
    print("\n[!] Monitoring Stopped.")
    process.terminate()
