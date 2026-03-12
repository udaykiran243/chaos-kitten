from typing import Dict, List, Any

def analyze_cors(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    aco: str = headers.get("access-control-allow-origin", "")
    acc: str = headers.get("access-control-allow-credentials", "")
    acm: str = headers.get("access-control-allow-methods", "")

    # Wildcard origin
    if aco.strip() == "*":
        findings.append({
            "issue": "Wildcard ACAO",
            "severity": "high"
        })

    # Credential exposure (avoid duplicate when wildcard origin already present)
    if acc.lower() == "true" and aco and aco.strip() != "*":
        findings.append({
            "issue": "Credentialed CORS allowed",
            "severity": "critical"
        })

    # Methods exposed
    dangerous: List[str] = ["PUT", "DELETE", "PATCH"]
    allowed_methods: List[str] = [m.strip().upper() for m in acm.split(",")]
    if any(m in allowed_methods for m in dangerous):
        findings.append({
            "issue": "Dangerous methods exposed via CORS",
            "severity": "medium"
        })

    return findings