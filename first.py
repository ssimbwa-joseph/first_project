import os
import time
import platform
import hashlib
import psutil
import json
API_URL = "http://127.0.0.1:8000/log"
WATCH_PATH = os.path.join(os.getcwd(), "test_install_fold")
SECURITY_LOG = "security_log.txt"
BEHAVIOR_LOG = "behavior_log.txt"
LOG_FILE = "general_log.txt"
JSON_LOG = "events.json"

DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1', '.cmd']
SCAN_INTERVAL = 5
SYSTEM_TYPE = platform.system()
os.makedirs(WATCH_PATH, exist_ok=True)

def send_to_api(e_type, msg, score, extra=""):
    try:
        requests.post(API_URL, json={"event_type": e_type, "message": msg, "risk_score": score, "extra": extra}, timeout=1)
    except: pass

RISK_SCORE = 0
RISK_TYPES = set()

RISK_CATEGORIES = {
    "MALWARE": "Malware Activity",
    "EXECUTION": "Suspicious Execution",
    "FILE": "Suspicious File Activity",
    "NETWORK": "Suspicious Network Activity",
    "PROCESS": "Suspicious Process Activity",
    "PRIVACY": "Camera/Microphone Access",
    "BEHAVIOR": "Abnormal System Behavior"
}

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log(file, message):
    entry = f"[{timestamp()}] {message}"
    print(entry)
    with open(file, "a") as f:
        f.write(entry + "\n")

def log_behavior(message):
    entry = f"[{timestamp()}] {message}"
    print(entry)
    with open(BEHAVIOR_LOG, "a") as f:
        f.write(entry + "\n")

def log_json(event_type, severity, message, extra=None):
    event = {
        "timestamp": timestamp(),
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "extra": extra or {}
    }
    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")

def add_risk(points, reason, risk_type):
    global RISK_SCORE
    RISK_SCORE += points
    RISK_TYPES.add(risk_type)

    readable = RISK_CATEGORIES.get(risk_type, risk_type)

    log_behavior(
        f"RISK +{points} [{readable}]: {reason} | Total Risk: {RISK_SCORE}"
    )
    log_behavior(f"RISK +{points}: {reason}")

    log_json(
        event_type="risk_score",
        severity="info",
        message=reason,
        extra={
            "points": points,
            "total": RISK_SCORE,
            "risk_type": risk_type,
            "risk_name": readable
        }
    )
    send_to_api(e_type=risk_type, msg=reason, score=points, extra=f"Total: {RISK_SCORE}")

def get_risk_summary():
    if not RISK_TYPES:
        return "No significant risks detected"
    return ", ".join(sorted(RISK_CATEGORIES[r] for r in RISK_TYPES))

def load_malicious_hashes():
    if not os.path.exists("malicious_hashes.txt"):
        return set()
    with open("malicious_hashes.txt", "r") as f:
        return set(line.strip() for line in f if line.strip())

def sha256(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def analyze_file_behavior(file_path):
    name = os.path.basename(file_path)
    extension = os.path.splitext(name)[1].lower()

    if extension in DANGEROUS_EXTENSIONS:
        add_risk(10, f"Executable file created: {name}", "EXECUTION")

    try:
        size = os.path.getsize(file_path) / 1024
        if size == 0:
            add_risk(5, f"Empty file created: {name}", "FILE")
        elif size > 50_000:
            log_behavior(f"INFO: Large file created -> {name} ({size:.2f} KB)")
    except OSError:
        log_behavior(f"ERROR: Could not access file {name}")

    file_hash = sha256(file_path)
    if file_hash and file_hash in MALICIOUS_HASHES:
        add_risk(50, f"Malware hash match: {name}", "MALWARE")
        log(SECURITY_LOG, f"MALWARE HASH MATCH: {name} | {file_hash}")

def monitor_files(known_files):
    current_files = set(os.listdir(WATCH_PATH))
    new_files = current_files - known_files

    if new_files:
        if len(new_files) > 10:
            add_risk(20, "Mass file creation detected", "BEHAVIOR")

        for f in new_files:
            analyze_file_behavior(os.path.join(WATCH_PATH, f))

    return current_files

def monitor_processes(known):
    current = set()
    for p in psutil.process_iter(['pid', 'name']):
        try:
            current.add((p.info['pid'], p.info['name']))
        except Exception:
            pass

    new = current - known
    for pid, name in new:
        log(LOG_FILE, f"New process started: {name} (PID {pid})")
        add_risk(5, f"New process started: {name}", "PROCESS")

    return current

seen_connections = {}
def monitor_network():
    global seen_connections 
    for conn in psutil.net_connections(kind='inet'):
        try:
            pid = conn.pid if conn.pid is not None else -1
            status = conn.status

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

            conn_id = (pid, laddr, raddr)

            # Log new connections or state changes
            if conn_id not in seen_connections or seen_connections[conn_id] != status:
                # Attempt to get process name
                try:
                    proc_name = psutil.Process(pid).name() if pid > 0 else "Unknown"
                except Exception:
                    proc_name = "Unknown"

                log(LOG_FILE,f"NETWORK [{status}] {proc_name} (PID {pid}) {laddr} -> {raddr}")
                seen_connections[conn_id] = status

        except Exception:
            pass

def detect_camera_mic_usage():
    if SYSTEM_TYPE != "Windows":
        return

    keywords = ["camera", "webcam", "mic", "microphone", "audio"]
    for p in psutil.process_iter(['pid', 'name']):
        try:
            pname = p.info['name'].lower()
            for k in keywords:
                if k in pname:
                    add_risk(
                        30,
                        f"Possible camera/mic usage by {p.info['name']}",
                        "PRIVACY"
                    )
                    log_json(
                        "camera_mic_access",
                        "high",
                        "Possible camera/microphone usage detected",
                        {"pid": p.info['pid'], "process": p.info['name']}
                    )
        except Exception:
            pass

def check_risk_thresholds():
    summary = get_risk_summary()

    if RISK_SCORE >= 100:
        log(SECURITY_LOG, f"CRITICAL: High-risk behavior detected | Risks: {summary}")
    elif RISK_SCORE >= 50:
        log(SECURITY_LOG, f"WARNING: Elevated risk behavior detected | Risks: {summary}")

if __name__ == "__main__":
    print("--- Behavioral Sentinel Active ---")

    os.makedirs(WATCH_PATH, exist_ok=True)

    MALICIOUS_HASHES = load_malicious_hashes()
    log(LOG_FILE, f"Loaded {len(MALICIOUS_HASHES)} malicious hashes")

    known_files = set(os.listdir(WATCH_PATH))
    known_processes = set(
        (p.info['pid'], p.info['name'])
        for p in psutil.process_iter(['pid', 'name'])
    )

    try:
        while True:
            known_files = monitor_files(known_files)
            known_processes = monitor_processes(known_processes)
            monitor_network()
            detect_camera_mic_usage()
            check_risk_thresholds()
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("Shutting down...")
