         FIRST " How it may look like"

# Behavioral Sentinel

A lightweight **Endpoint Detection & Response (EDR)**–style monitoring tool written in Python.
This project monitors file activity, running processes, and network connections to help detect **suspicious or unknown behavior** on a system.


## Features

### File System Monitoring

* Detects **newly created files** in a watched directory
* Flags:

  * Executable files (`.exe`, `.bat`, `.ps1`, etc.)
  * Empty files (possible droppers/placeholders)
  * Unusually large files
* Detects **mass file creation events**

### Malware Hash Detection

* Calculates **SHA-256 hashes** of new files
* Compares against a user-maintained list of **known malicious hashes**
* Alerts when a hash match is found

### Process Monitoring

* Detects **new processes** started in the background
* Useful for identifying:

  * Unknown apps
  * Suspicious background services
  * Potential spyware or RATs

### Network Activity Visibility

* Displays active outbound network connections
* Shows:

  * Process ID (PID)
  * Remote IP and port
* Helps identify **unexpected data exfiltration**

### Logging

* Security alerts and behavioral events are logged to:

  * `security_log.txt`
  * `behavior_log.txt`

--

### Can Detect

* Suspicious file drops
* Known malware via hash matching
* Unknown background processes
* Suspicious network connections
* Common malware behaviors (droppers, spyware, RATs)

### Cannot Detect But for sooner improvements 

* Kernel-level rootkits
* Fully stealthy malware with elevated privileges
* Hardware-based attacks

> This tool complements system security — it does **not** replace a full antivirus or OS security features.

---

## Supported Platforms

* Windows
* Linux
* macOS

(Some features may vary depending on OS permissions.)

---

## Requirements

* Python **3.8+**
* Python package:

```bash
pip install psutil

or

python -m pip install psutil
```

---

## ⚙️ Setup & Usage

### Clone or Download

Place the script in a directory of your choice.

### Create Watch Folder

The script automatically creates:

```
test_install_fold/
```

This is the directory that will be monitored for new files.

###  (Optional) Add Malware Hashes

Create a file called:

```
malicious_hashes.txt
```

Add one SHA-256 hash per line:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

###  Run the Tool

```bash
python m.py
```

Press **CTRL+C** to stop safely.

---

##  Output Files

| File                 | Description                     |
| -------------------- | ------------------------------- |
| `security_log.txt`   | High-risk alerts and detections |
| `behavior_log.txt`   | Behavioral observations         |
| `test_install_fold/` | Monitored directory             |

---

## Security & Privacy Notes

* No data is sent externally
* No files are uploaded
* No system changes are made
* Runs entirely locally

---

##Future Improvements (Planned)

* Camera & microphone usage detection
* Automatic file quarantine
* Risk scoring system
* Startup persistence detection
* Background service mode
