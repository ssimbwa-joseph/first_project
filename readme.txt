         FIRST " How it may look like"

# Behavioral_Sentinel_Active

A lightweight **Endpoint Detection & Response (EDR)**–style monitoring tool written in Python.
This project helps monitors file activity, running processes, and network connections to help detect **suspicious or unknown behavior** on a system.

# Problems

Background activities on a computer range from necessary system maintenance to malicious surveillance. 
These software sometimes are built at somepoint they can be seen by the TaskManager, Nmap etc
If someone has installed monitoring software or has administrative access (especially on work computers). 
They can perform a wide range of tasks without your direct knowledge but for the benefit of the other party.
      *running Crypto mining on it.
      *training AI modules 
      *worms
      *Trojan Horses
      *spyware etc

# solution

The system is going to be help since for it will be fecthing the data direct from the hardware, e.g "CPU, RAM, Disk, Camera and mic, Network usage etc."
It will detect files to if they are malicious or not.
It will detect the actives which are runing on the pc and also it store the histry in its database for future forensics.

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
pip install fastapi

or

python -m pip install fastapi

---
pip install requests

or

python3 -m pip install requests
---
     For Linux user you will need add a " sude " command for admin privileges.

##  Setup & Usage

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

## GPU 
 
  *you will have to run the first_launch.bat to run the all system at once.

##  Output Files

| File                  Description                     |
| --------------------  ------------------------------- |
| `security_log.txt`    High-risk alerts and detections |
| `behavior_log.txt`    Behavioral observations         |
| `test_install_fold/`  Monitored directory             |
| `general_log.txt`     All the process out
| `event.json`          json observation

---

## Security & Privacy Notes

* No data is sent externally
* No files are uploaded
* No system changes are made
* Runs entirely locally

---

## Those have been added 

* Camera & microphone usage detection
* Automatic file quarantine
* Risk scoring system

##What to do next

Now that your environment is ready, you can start the system. Because they are separate files, you must start them in this specific order:

   * Start the Brain: Run python3 first_database_api.py
   * Start the Worker: Run python3 first.py
   * Start the View: Run python first_gui.py

##FutureT Improvements (Planned)
* Startup persistence detection
* Background service mode
*Intergrating it to work with Nmap and it can install on our system automatically with the use of API.
*Intergrating it to work with taskmanager in our GUI
*Interducing in AI and machine learning in it to work as an Anti-Virus for other malware actives.
