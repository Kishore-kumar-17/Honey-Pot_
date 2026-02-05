import re

class ThreatDetector:
    SQL_INJECTION_PATTERNS = [
        r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER).*FROM",
        r"(?i)--",
        r"(?i)OR\s+.*=.*",
        r"(?i)OR\s+['\"].*['\"]\s*=\s*['\"].*['\"]",
        r"(?i)EXEC\(",
        r"(?i)SLEEP\(\d+\)"
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"C:\\Windows\\System32"
    ]
    
    BOT_USER_AGENTS = [
        r"(?i)nmap",
        r"(?i)sqlmap",
        r"(?i)nikto",
        r"(?i)dirbuster",
        r"(?i)gobuster"
    ]

    @staticmethod
    def detect_sql_injection(content: str) -> bool:
        for pattern in ThreatDetector.SQL_INJECTION_PATTERNS:
            if re.search(pattern, content):
                return True
        return False

    @staticmethod
    def detect_path_traversal(content: str) -> bool:
        for pattern in ThreatDetector.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, content):
                return True
        return False

    @staticmethod
    def is_bot(user_agent: str) -> bool:
        for pattern in ThreatDetector.BOT_USER_AGENTS:
            if re.search(pattern, user_agent):
                return True
        return False
