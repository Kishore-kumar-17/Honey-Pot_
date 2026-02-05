import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

class AIEngine:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and api_key != "your_key_here":
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.enabled = True
        else:
            self.enabled = False

    async def analyze_intent(self, prompt: str) -> dict:
        if not self.enabled:
            return {
                "threat_level": "MEDIUM",
                "attack_type": "UNKNOWN (AI Disabled)",
                "explanation": "Gemini API key not provided."
            }

        try:
            full_prompt = f"""
            Analyze the following request to a web server for malicious intent.
            Return a JSON object with:
            - threat_level: LOW, MEDIUM, HIGH, or CRITICAL
            - attack_type: A string describing the attack (e.g., SQL_INJECTION, XSS, PROMPT_INJECTION)
            - explanation: A short reason for this classification

            Request: "{prompt}"
            """
            response = self.model.generate_content(full_prompt)
            # Simple parsing (could be improved with structured output if supported)
            # For now, just return the text or a placeholder if it fails to parse
            return {"raw_analysis": response.text}
        except Exception as e:
            return {"error": str(e), "threat_level": "UNKNOWN"}
