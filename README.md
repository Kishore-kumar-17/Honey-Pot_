# 🛡️ Honey-Pot API

The **Honey-Pot API** is a FastAPI-based security system designed to detect, log, and analyze phishing, scams, and malicious activities. Instead of just blocking attackers, it intelligently engages them to study their behavior and improve defensive cybersecurity strategies.

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Gemini API Key (Optional, for AI Analysis)

### Installation
1.  **Open PowerShell** and navigate to the project folder:
    ```powershell
    cd "C:\Users\Kishore kumar\.gemini\antigravity\scratch\honey_pot_api"
    ```
2.  **Create a virtual environment** (if not already done):
    ```powershell
    python -m venv venv
    ```
3.  **Activate the virtual environment**:
    *   **Windows**: `.\venv\Scripts\activate`
    *   **Unix/macOS (Bash/Zsh)**: `source venv/bin/activate` (Use this ONLY on Linux/Mac)
4.  **Install dependencies**:
    ```powershell
    pip install -r requirements.txt
    ```
5.  **Configure environment**: Copy `.env.example` to `.env` and add your `GEMINI_API_KEY`.

### Running the API
```bash
uvicorn main:app --reload
```
The API will be available at `http://127.0.0.1:8000`.

## 🔌 API Endpoints

- `GET /`: Health check.
- `POST /login`: Honey-pot login endpoint to trap brute-force and SQLi.
- `GET /{path}`: Catch-all endpoint to detect bot scanning (e.g., `/.env`, `/wp-admin`).
- `POST /agent`: AI-assisted analysis of suspicious prompts.

## 📊 Logging
All detected attacks are logged in `logs/attacks.json` with details such as IP, timestamp, endpoint, and threat classification.

## 🧪 Verification
Run the verification script to test all endpoints:
```bash
python verify_honey_pot.py
```
