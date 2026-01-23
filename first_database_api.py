from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import uvicorn
from datetime import datetime

app = FastAPI()

def init_db():
    conn = sqlite3.connect("Behavioral_Sentinel_Active.db")
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts 
        (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, 
         event_type TEXT, message TEXT, risk_score INTEGER, extra TEXT)''')
    conn.close()

class Alert(BaseModel):
    event_type: str
    message: str
    risk_score: int
    extra: str = ""

@app.post("/log")
async def log_event(data: Alert):
    conn = sqlite3.connect("Behavioral_Sentinel_Active.db")
    conn.execute("INSERT INTO alerts (timestamp, event_type, message, risk_score, extra) VALUES (?,?,?,?,?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data.event_type, data.message, data.risk_score, data.extra))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.get("/alerts")
async def get_alerts():
    conn = sqlite3.connect("Behavioral_Sentinel_Active.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, event_type, message, risk_score, extra FROM alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [{"time": r[0], "type": r[1], "msg": r[2], "score": r[3], "extra": r[4]} for r in rows]

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8000)