from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    BOT_SCANNING = "BOT_SCANNING"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"

class ThreatClassifier:
    @staticmethod
    def classify(detection_results: dict) -> tuple[ThreatLevel, AttackType]:
        if detection_results.get("sql_injection"):
            return ThreatLevel.HIGH, AttackType.SQL_INJECTION
        if detection_results.get("path_traversal"):
            return ThreatLevel.HIGH, AttackType.PATH_TRAVERSAL
        if detection_results.get("is_bot"):
            return ThreatLevel.MEDIUM, AttackType.BOT_SCANNING
        if detection_results.get("brute_force"):
            return ThreatLevel.HIGH, AttackType.BRUTE_FORCE
        
        return ThreatLevel.LOW, AttackType.UNKNOWN
