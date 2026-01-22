import os
import time
import platform
import hashlib
import psutil

#CONFIGURATION
WATCH_PATH = os.path.join(os.getcwd(),"test_install_fold")
SECURITY_LOG= "security_log.txt"
BEHAVIOR_LOG = "behavior_log.txt"
LOG_FILE = "general_log.txt" #For process and network logs

#Behavioral Settings
DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1', '.cmd']
SCAN_INTERVAL = 5
SYSTEM_TYPE = platform.system()


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")
def log(file, message):
    """Savea alerts to a text file so you can review them later."""
    entry = f"[{timestamp()}] {message}"
    print(entry)
    with open(file, "a") as f:
        f.write(entry + "\n")

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

        
def log_behavior(message):
    entry = f"[{timestamp()}] {message}"
    print(entry)
    with open(BEHAVIOR_LOG, "a") as f:
        f.write(entry + "\n")
        
def analyze_file_behavior(file_path):
    """Analyzes a specific file for suspicious traits."""
    name = os.path.basename(file_path)
    extension = os.path.splitext(name) [1].lower()
    
    #1. Check for danerous extensions
    if extension in DANGEROUS_EXTENSIONS:
        log_behavior(f"SUSPICIOUS BEHAVIOR: Executable file created -> {name}")
    
    #2. Check file size (malware is often very small or very large)
    try:
        size = os.path.getsize(file_path) / 1024 #SIZE IN KB
        if size == 0:
            log_behavior(f"BEHAVIOR ALERT: Empty file created (potential placeholder) -> {name}")
        elif size > 50_000: #50MB
            log_behavior(f"INFO: Large file created -> {name} ({size:.2f}KB)")
    except OSError:
        log_behavior(f"ERROR: Cloud not acces {name}")
        
    #3. Check file Hash
    file_hash = sha256(file_path)
    if file_hash and file_hash in MALICIOUS_HASHES:
        log(SECURITY_LOG, f" MALWARE HASH MATCH: {name} | {file_hash}")
        
def monitor_files(known_files):
    current_files = set(os.listdir(WATCH_PATH))
    new_files = current_files - known_files
    
    if new_files:
        if len(new_files) > 10:
           log_behavior(f"WARNING: Mass file creation detected ({len(new_files)} files)")
        for file in new_files:
            full_path = os.path.join(WATCH_PATH, file)
            analyze_file_behavior(full_path)
            
    return current_files

def monitor_processes(known):
    current = set()
    for p in psutil.process_iter(['pid', 'name']):
        try:
            current.add((p.info['pid'], p.info['name']))
        except Exception:
            pass

    new = current - known
    """for proc in new:
        log(LOG_FILE, f" New process started: {proc}")"""
    
    for pid, name in new:
        log(LOG_FILE, f"New process started: {name} (PID {pid})")

    return current

def monitor_network():
    global seen_connections 
    seen_connections = {}
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

if __name__ == "__main__":
    print("--- Behavioral Sentionel Active ---")
    
    if not os.path.exists(WATCH_PATH):
        os.makedirs(WATCH_PATH)
    MALICIOUS_HASHES = load_malicious_hashes()
    log(LOG_FILE, f"Loaded {len(MALICIOUS_HASHES)} malicious hashes")
   
    known_files = set(os.listdir(WATCH_PATH))
    known_processes = set(
        (p.info['pid'], p.info['name'])
        for p in psutil.process_iter(['pid', 'name']))    
    
    try: 
        while True:
            known_files = monitor_files(known_files)
            known_processes = monitor_processes(known_processes)
            monitor_network()
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("Shutting down...")
    