import json
import os
from datetime import datetime

LOG_FILE = "logs/attacks.json"

class AttackLogger:
    @staticmethod
    def log_attack(data: dict):
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            **data
        }
        
        # Always print to stdout (important for hosted logging like Vercel)
        print(f"ATTACK LOG: {json.dumps(log_entry)}")
        
        try:
            if not os.path.exists("logs"):
                os.makedirs("logs", exist_ok=True)
                
            logs = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    try:
                        logs = json.load(f)
                    except (json.JSONDecodeError, FileNotFoundError):
                        logs = []
            
            logs.append(log_entry)
            
            with open(LOG_FILE, "w") as f:
                json.dump(logs, f, indent=4)
        except Exception as e:
            # On platforms like Vercel, writing to disk might fail.
            # We've already printed to stdout, so we can just catch and ignore this.
            print(f"Warning: Could not write to attack file (this is normal on some hosts): {e}")
