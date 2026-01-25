import os
import time
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import requests

API_URL = "http://127.0.0.1:8000/alerts"
class Behavioral_Sentinel_Active:
    def __init__(self, root):
        self.root = root
        self.root.title("Behavioral_Sentinel_Active - Advanced Security Hub")
        self.root.geometry("1000x750")
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # --- Top Control Bar ---
        self.control_frame = tk.Frame(self.root, bg="#2d2d2d", height=50)
        self.control_frame.pack(side="top", fill="x")

        self.status_indicator = tk.Label(self.control_frame, text="● SYSTEM ACTIVE", 
                                        fg="#00ff00", bg="#2d2d2d", font=("Arial", 10, "bold"))
        self.status_indicator.pack(side="left", padx=20, pady=10)

        self.clear_btn = tk.Button(self.control_frame, text="CLEAR ALL LOGS", command=self.clear_logs,
                                  bg="#cc0000", fg="white", font=("Arial", 9, "bold"))
        self.clear_btn.pack(side="right", padx=20, pady=10)

        # --- Main Tab System ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")

        self.tab_dashboard = self.create_tab("📊 Dashboard")
        self.tab_files = self.create_tab("📂 File System")
        self.tab_process = self.create_tab("⚙️ Processes")
        self.tab_network = self.create_tab("🌐 Network")

        # --- Dashboard Visuals ---
        self.risk_var = tk.StringVar(value="RISK SCORE: 0")
        self.risk_label = tk.Label(self.tab_dashboard, textvariable=self.risk_var, 
                                  font=("Impact", 60), fg="#00ff00", bg="black")
        self.risk_label.pack(pady=40, fill="x")
        
        self.status_log = scrolledtext.ScrolledText(self.tab_dashboard, height=12, bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.status_log.pack(padx=20, pady=10, fill="both")

        # --- Other Tab Logs ---
        self.file_log = scrolledtext.ScrolledText(self.tab_files, bg="black", fg="#00ff00", font=("Consolas", 11))
        self.file_log.pack(expand=True, fill="both")

        self.proc_log = scrolledtext.ScrolledText(self.tab_process, bg="black", fg="#33ccff", font=("Consolas", 11))
        self.proc_log.pack(expand=True, fill="both")

        self.net_log = scrolledtext.ScrolledText(self.tab_network, bg="black", fg="#ffcc00", font=("Consolas", 11))
        self.net_log.pack(expand=True, fill="both")

        # Memory for line tracking to avoid re-reading old data
        self.last_line_count = 0
        self.update_ui()

    def create_tab(self, name):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=name)
        return frame

    def clear_logs(self):
        """Wipes the UI logs and the JSON file for a fresh start."""
        for log_area in [self.status_log, self.file_log, self.proc_log, self.net_log]:
            log_area.delete(1.0, tk.END)
        
        # Optionally clear the JSON file on disk
        if os.path.exists("events.json"):
            open("events.json", "w").close()
        
        self.risk_var.set("RISK SCORE: 0")
        self.risk_label.config(fg="#00ff00")
        print("[*] Dashboard Logs Cleared")

    def update_ui(self):
        """Fetch data from the API in a background thread so the windows stays smooth."""
        def background_fetch():
            try:    
            # Added timeout=1.0 so it doesn't hang if API is slow
                response = requests.get("http://127.0.0.1:8000/alerts", timeout=1.0)
                if response.status_code == 200:
                    events = response.json()
                # We use .after to safely update the UI from a background thread
                    self.root.after(0, lambda e=events: self.render_data(e))
            except Exception as e:
                # If API fails, show offline status safely
                print(f"API Error: {e}")
                self.root.after(0, lambda: self.status_indicator.config(text="● API OFFLINE", fg="red"))

        # Start the network request in the background
        threading.Thread(target=background_fetch, daemon=True).start()
    
        # Schedule the next refresh (2 seconds)
        self.root.after(2000, self.update_ui)

    def render_data(self, events):
        """Process the data and forces it to show in the text boxes."""
        self.status_indicator.config(text="● SYSTEM ACTIVE", fg="#00ff00")
    
        # Clear old logs
        for log in [self.status_log, self.file_log, self.proc_log, self.net_log]:
            log.delete(1.0, tk.END)

        # Ensure we have data
        if not events:
            self.status_log.insert(tk.END, "Monitoring active... No threats detected yet.")
            return
        
        current_total_risk = 0
        
        for e in events:
            # MATCHING THE API KEYS: timestamp, event_type, message, risk_score
            t_stamp = e.get('timestamp', 'N/A')
            e_type = str(e.get('event_type', 'INFO')).upper()
            msg = e.get('message', 'No details provided.')
            score = e.get('risk_score', 0)

            formatted_msg = f"[{t_stamp}] {msg}\n"

            # Sorting into the correcttabs
            if e_type == "PROCESS":
                self.proc_log.insert(tk.END, formatted_msg)
                self.proc_log.see(tk.END)
                
            elif e_type in ["FILE", "EXECUTION", "MALWARE"]:
                self.file_log.insert(tk.END, formatted_msg)
                self.file_log.see(tk.END)
                
            elif e_type == "NETWORK":
                self.net_log.insert(tk.END, formatted_msg)
                self.net_log.see(tk.END)
            
            #always add to the Dashboard (All Events)        
            self.status_log.insert(tk.END, f"[{t_stamp}] {e_type}: {msg}\n")
            self.status_log.see(tk.END)
            
            current_total_risk += score
            
        #Update risk score display   
        self.risk_var.set(f"RISK SCORE: {current_total_risk}")
        if current_total_risk > 100: 
            self.risk_label.config(fg="red")
        elif current_total_risk > 50: 
            self.risk_label.config(fg="orange")
        else: 
            self.risk_label.config(fg="#00ff00")
        
if __name__ == "__main__":
    root = tk.Tk()
    app = Behavioral_Sentinel_Active(root)
    root.mainloop()