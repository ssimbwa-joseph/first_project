import os
import time
import platform

#CONFIGURATION
WATCH_PATH = os.path.join(os.getcwd(),"test_install_fold")
LOG_FILE = "security_log.txt"
LOG_FILE = "behavior_log.txt"

#Behavioral Settings
DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1', '.cmd']
SYSTEM_TYPE = platform.system()

def log_event(message):
    """Savea alerts to a text file so you can review them later."""
    timetamp = time.strftime("%Y-%m-%d%H:%M:%S")
    log_entery = f"[{timestamp}] {message}"
    print(log_entery)
    with open(LOG_FILE, "a") as f:
        f.write(log_entery + "\n")
def log_behavior(message):
    """writes findings to a text file on your USB/Disk."""
    timetamp = time.strftime("%Y-%m-%d%H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}\n")

def analyze_file_behavior(file_path):
    """Analyzes a specific file for suspicious traits."""
    name = os.path.splitext(name) [1].lower()
    
    #1. Check for danerous extensions
    if extension in DANGEROUS_EXTENSIONS:
        log_behavior(f"SUSPICIOUS BEHAVIOR: Executable file created ->{name}")
    
    #2. Check file size (malware is often very small or very large)
    try:
        file_size = os.path.getsize(file_path) / 1024 #SIZE IN KB
        if file_size == 0:
            log_behavior(f"BEHAVIOR ALERT: Empty file created (potential placeholder) -> {name}")
        elif file_size > 50000: #50MB
            log_behavior(f"INFO: Large file created -> {name} ({file_size:.2f}KB)")
    except OSError:
        pass
def monitor_file(known_files):
    current_file = set(os.listdir(WATCH_PATH))
    new_file = current_files - known_files
    
    if len(new_files) > 10:
        log_behavior(f"WARNING: Mass file creation detected! ({len(new_files)} filesS)")
        for file in new_files:
            full_path = os.path.join(WATCH_PATH, file)
            analyze_file_behavior(full_path)
        return current_files
if __name__ == "__main__":
    print("---Behavioral Sentionel Active ---")
    known_file = set(os.listdir(WATCH_PATH))
    try: 
        while True:
            known_files = monitor_files(known_files)
            time.sleep(5)
    except keyboardinterrupt:
        print("Shutting down...")
    