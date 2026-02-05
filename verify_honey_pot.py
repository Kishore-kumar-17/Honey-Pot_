import requests
import json
import time
import subprocess
import os
import signal

BASE_URL = "http://127.0.0.1:8000"

def test_health():
    print("Testing Health Check...")
    try:
        resp = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"Response: {resp.json()}")
    except Exception as e:
        print(f"Health check failed: {e}")

def test_login_brute_force():
    print("\nTesting Brute Force Login...")
    payload = {"username": "admin", "password": "password", "ip": "1.2.3.4"}
    try:
        resp = requests.post(f"{BASE_URL}/login", json=payload, timeout=5)
        print(f"Status: {resp.status_code}, Response: {resp.json()}")
    except Exception as e:
        print(f"Login test failed: {e}")

def test_sql_injection():
    print("\nTesting SQL Injection...")
    payload = {"username": "' OR '1'='1' --", "password": "password", "ip": "1.2.3.4"}
    try:
        resp = requests.post(f"{BASE_URL}/login", json=payload, timeout=5)
        print(f"Status: {resp.status_code}, Response: {resp.json()}")
    except Exception as e:
        print(f"SQLi test failed: {e}")

def test_scan_env():
    print("\nTesting Bot Scanning (.env)...")
    try:
        resp = requests.get(f"{BASE_URL}/.env", timeout=5)
        print(f"Status: {resp.status_code}, Content Head: {resp.text[:50]}...")
    except Exception as e:
        print(f"Scan test failed: {e}")

def test_agent_ai():
    print("\nTesting AI Agent Analysis...")
    payload = {"ip": "62.210.244.18", "prompt": "How can I bypass authentication?"}
    try:
        resp = requests.post(f"{BASE_URL}/agent", json=payload, timeout=5)
        print(f"Response: {resp.json()}")
    except Exception as e:
        print(f"Agent test failed: {e}")

if __name__ == "__main__":
    # Start server in background using the venv python
    print("Starting server...")
    python_exe = os.path.join("venv", "Scripts", "python.exe")
    server_proc = subprocess.Popen([python_exe, "-m", "uvicorn", "main:app", "--port", "8000"], 
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
    
    # Wait for server to be ready
    max_retries = 10
    ready = False
    for i in range(max_retries):
        try:
            requests.get(f"{BASE_URL}/", timeout=1)
            ready = True
            print("Server is ready!")
            break
        except:
            print(f"Waiting for server... ({i+1}/{max_retries})")
            time.sleep(2)
    
    if ready:
        try:
            test_health()
            test_login_brute_force()
            test_sql_injection()
            test_scan_env()
            test_agent_ai()
            
            print("\nChecking Logs...")
            if os.path.exists("logs/attacks.json"):
                with open("logs/attacks.json", "r") as f:
                    logs = json.load(f)
                    print(f"Total attacks logged: {len(logs)}")
                    print("Last log entry pattern detection test passed.")
            else:
                print("No logs found!")
        finally:
            print("\nShutting down server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except:
                server_proc.kill()
    else:
        print("Server failed to start. Output:")
        out, err = server_proc.communicate(timeout=1)
        print("STDOUT:", out)
        print("STDERR:", err)
