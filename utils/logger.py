import json
import os
from datetime import datetime

LOG_FILE = "logs/attacks.json"

class AttackLogger:
    @staticmethod
    def log_attack(data: dict):
        if not os.path.exists("logs"):
            os.makedirs("logs")
            
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            **data
        }
        
        try:
            logs = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
            
            logs.append(log_entry)
            
            with open(LOG_FILE, "w") as f:
                json.dump(logs, f, indent=4)
        except Exception as e:
            print(f"Error logging attack: {e}")
