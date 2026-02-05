from fastapi import FastAPI, Request, Body, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
import os
from dotenv import load_dotenv

from agent.detector import ThreatDetector
from agent.classifier import ThreatClassifier, ThreatLevel, AttackType
from agent.ai_engine import AIEngine
from utils.logger import AttackLogger
from utils.response import ResponseGenerator

from fastapi.exceptions import RequestValidationError
from typing import Optional

load_dotenv()

app = FastAPI(title="Honey-Pot API")
ai_engine = AIEngine()

class AgentRequest(BaseModel):
    ip: str
    prompt: Optional[str] = "No prompt provided"
    X_API_KEY: str = "Enter Secret Key Here"

    class Config:
        extra = "allow"

class LoginRequest(BaseModel):
    username: str
    password: str
    ip: str
    X_API_KEY: str = "Enter Secret Key Here"

    class Config:
        extra = "allow"

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Log malformed requests as reconnaissance/bot scanning
    ip = request.client.host
    AttackLogger.log_attack({
        "ip": ip,
        "endpoint": str(request.url),
        "method": request.method,
        "type": "MALFORMED_REQUEST",
        "details": exc.errors(),
        "threat_level": ThreatLevel.MEDIUM,
        "attack_type": AttackType.BOT_SCANNING
    })
    
    # Return a deceptive 401 instead of a 422 to hide framework details
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "Unauthorized access", "code": 401}
    )

# Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(request: Request, api_key: str = Depends(api_key_header)):
    # Check header first, then try to get from body
    expected_key = os.getenv("API_KEY", "KISHORE-HONEY-POT-2026")
    
    # Try to extract from body if not in header
    body_key = None
    try:
        # We peek at the body; for small JSON bodies this is usually fine
        # but we have to be careful not to consume it if we don't need to.
        # However, FastAPI models already parsed it, but verify_api_key runs before.
        # So we'll check it again in the endpoint if needed, or 
        # just allow the dependency to pass if header exists.
        pass
    except:
        pass

    if api_key == expected_key:
        return api_key
    
    # If header fails, we'll let the endpoint check the body field
    return None

def check_body_key(req_key: str):
    expected_key = os.getenv("API_KEY", "KISHORE-HONEY-POT-2026")
    if req_key != expected_key:
        AttackLogger.log_attack({
            "endpoint": "BODY_API_KEY_AUTH",
            "type": "UNAUTHORIZED_ACCESS_ATTEMPT",
            "provided_key": req_key,
            "threat_level": ThreatLevel.MEDIUM,
            "attack_type": AttackType.UNKNOWN
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X_API_KEY in request body",
        )

@app.get("/", dependencies=[Depends(verify_api_key)])
async def health_check():
    return {"status": "Honey-pot API running"}

@app.post("/agent")
async def agent_analyze(req: AgentRequest, api_key: str = Depends(api_key_header)):
    # Verify key from either Header or Body
    if api_key != os.getenv("API_KEY", "KISHORE-HONEY-POT-2026"):
        check_body_key(req.X_API_KEY)
    # AI Analysis
    analysis = await ai_engine.analyze_intent(req.prompt)
    
    # Log the request
    AttackLogger.log_attack({
        "ip": req.ip,
        "endpoint": "/agent",
        "payload": req.prompt,
        "analysis": analysis
    })
    
    # Deceptive response
    return {
        "threat_level": analysis.get("threat_level", "UNKNOWN"),
        "attack_type": analysis.get("attack_type", "UNKNOWN"),
        "response": "Access denied"
    }

@app.post("/login")
async def honey_login(req: LoginRequest, request: Request, api_key: str = Depends(api_key_header)):
    # Verify key from either Header or Body
    if api_key != os.getenv("API_KEY", "KISHORE-HONEY-POT-2026"):
        check_body_key(req.X_API_KEY)
    # Detection
    is_sql_i = ThreatDetector.detect_sql_injection(req.username) or ThreatDetector.detect_sql_injection(req.password)
    
    level = ThreatLevel.LOW
    attack_type = AttackType.UNKNOWN
    
    if is_sql_i:
        level = ThreatLevel.HIGH
        attack_type = AttackType.SQL_INJECTION
    elif req.username == "admin" and req.password in ["admin123", "password", "123456"]:
        level = ThreatLevel.MEDIUM
        attack_type = AttackType.BRUTE_FORCE

    # Log
    AttackLogger.log_attack({
        "ip": req.ip,
        "endpoint": "/login",
        "payload": {"username": req.username, "password": req.password},
        "user_agent": request.headers.get("user-agent"),
        "threat_level": level,
        "attack_type": attack_type
    })
    
    # Return fake error
    return JSONResponse(status_code=401, content=ResponseGenerator.login_failure())

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Detection
    is_bot = ThreatDetector.is_bot(user_agent)
    is_path_trav = ThreatDetector.detect_path_traversal(path_name)
    
    level, attack_type = ThreatClassifier.classify({
        "is_bot": is_bot,
        "path_traversal": is_path_trav
    })
    
    # Log
    AttackLogger.log_attack({
        "ip": ip,
        "endpoint": f"/{path_name}",
        "method": request.method,
        "user_agent": user_agent,
        "threat_level": level,
        "attack_type": attack_type
    })
    
    # Deceptive response for scanning
    response_content = ResponseGenerator.scan_response(path_name)
    if isinstance(response_content, str):
        return PlainTextResponse(content=response_content)
    return JSONResponse(content=response_content)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
