"""Attack planning logic for Chaos Kitten."""

from typing import Any, Dict, List

import yaml
from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


@dataclass
class AttackProfile:
    """Represents a loaded attack profile from a YAML file."""

    name: str
    category: str
    severity: str
    description: str
    payloads: list[str]
    target_fields: list[str]
    success_indicators: dict[str, Any]
    remediation: str = ""
    references: list[str] = field(default_factory=list)


ATTACK_PLANNING_PROMPT = """You are a security expert analyzing an API endpoint for vulnerabilities.
Endpoint: {method} {path}
Parameters: {parameters}
Request Body: {body}

Analyze this endpoint and suggest attack vectors. Consider:
1. Parameter types and names (id, user, query suggest different attacks)
2. HTTP method (POST/PUT more likely to have injection points)
3. Authentication requirements

Return a prioritized list of attacks to try.
You must respond ONLY with a valid JSON array of objects. Do not include markdown formatting or explanations outside the JSON.
Each object must have the following keys:
- "type" (string, e.g., "sql_injection", "xss", "idor", "path_traversal")
- "name" (string, short name of the attack)
- "description" (string, what the attack does)
- "payload" (dict or string, the actual payload to send)
- "target_param" (string, the parameter or body field to target)
- "expected_status" (integer, expected HTTP status if vulnerable, e.g., 500)
- "priority" (string, "high", "medium", or "low")
"""

PAYLOAD_SUGGESTION_PROMPT = """You are an expert penetration tester.
Given the attack type '{attack_type}' and the context of the endpoint '{context}',
suggest a list of 5 specific, creative payloads to test for vulnerabilities.

Respond ONLY with a valid JSON array of strings representing the payloads. Do not include markdown blocks.
"""

REASONING_PROMPT = """You are an API security tester.
How would you test a field named '{field_name}' of type '{field_type}' for vulnerabilities?
Provide a concise, 1-2 sentence reasoning."""


class AttackPlanner:
    """Plan attacks based on API structure and context.
    
    Uses LLM reasoning to:
    - Understand endpoint semantics
    - Select appropriate attack profiles
    - Plan multi-step attack chains
    - Adapt based on responses
    """
    
    def __init__(self, endpoints: List[Dict[str, Any]], toys_path: str = "toys/") -> None:
        """Initialize the attack planner.
        
        Args:
            endpoints: List of parsed API endpoints
            toys_path: Path to the attack profiles directory
        """
        self.endpoints = endpoints
        self.toys_path = toys_path
        self.attack_profiles: List[Dict[str, Any]] = []
    
    def load_attack_profiles(self) -> None:
        """Load all attack profiles from the toys directory."""
        # TODO: Load YAML files from toys/
        raise NotImplementedError("Attack profile loading not yet implemented")
    
    def plan_attacks(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Plan attacks for a specific endpoint.
        
        Args:
            endpoint: Endpoint definition from OpenAPI parser
            
            for field_info in targetable_fields:
                field_name = field_info["name"]
                _ = field_info["type"] # Unused for now, but keeping for future type awareness
                
                # Check 1: Field name match (Exact or Fuzzy)
                # Exact match
                is_match = field_name in profile.target_fields
                
                # Fuzzy match (e.g., "user_email" matches "email" if "email" is a distinct word part)
                if not is_match:
                    # properly handle snake_case and other delimiters
                    parts = re.split(r'[^a-zA-Z0-9]', field_name.lower())
                    for target in profile.target_fields:
                        if target.lower() in parts:
                            is_match = True
                            break
                            
                if is_match:
                    # Check 2: Type compatibility (Basic)
                    # Use categories to determine if type mismatch is critical
                    # e.g., SQLi (string) vs ID (integer) - sometimes valid, sometimes not.
                    # For now, we'll be permissive but prioritize string fields for injections.
                    
                    # Logic for filtering based on method/category
                    # e.g. Don't test body interactions on GET requests unless strictly specific
                    if field_info["location"] == "body" and method == "get":
                        continue
                    schema = media_obj.get("schema") or {}
                    properties = schema.get("properties") if isinstance(schema, dict) else None
                    if isinstance(properties, dict):
                        for field_name in properties.keys():
                            fields.append((str(field_name), "body"))

        if not fields:
            fields.append(("q", "query"))

        deduped: list[tuple[str, str]] = []
        seen_fields: set[tuple[str, str]] = set()
        for field_name, location in fields:
            key = (field_name, location)
            if key not in seen_fields:
                seen_fields.add(key)
                deduped.append(key)

        return deduped

    def _field_matches_target(self, field_name: str, target_field: str) -> bool:
        field_norm = self._normalize_name(field_name)
        target_norm = self._normalize_name(target_field)

        if not field_norm or not target_norm:
            return False

        if field_norm == target_norm:
            return True

        if target_norm in field_norm or field_norm in target_norm:
            return True

        field_tokens = set(token for token in field_norm.split("_") if token)
        target_tokens = set(token for token in target_norm.split("_") if token)
        if field_tokens.intersection(target_tokens):
            return True

        for field_token in field_tokens:
            for target_token in target_tokens:
                min_len = min(len(field_token), len(target_token))
                if min_len < 2:
                    continue
                if field_token.endswith(target_token) or target_token.endswith(field_token):
                    return True

        return False

    def _normalize_name(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
        normalized = re.sub(r"_+", "_", normalized).strip("_")
        return normalized

    def _build_payload(self, field_name: str, location: str, payload: str) -> dict[str, Any]:
        # Executor handles GET payload as query params and POST/PUT/PATCH payload as JSON.
        # Keeping a dict shape across locations is the most compatible contract here.
        return {field_name: payload}

    def _expected_status(self, indicators: dict[str, Any]) -> int:
        status_codes = indicators.get("status_codes") if isinstance(indicators, dict) else None
        if isinstance(status_codes, list):
            for status_code in status_codes:
                try:
                    return int(status_code)
                except (TypeError, ValueError):
                    continue
        return 500

    def _severity_rank(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return order.get(str(severity).lower(), 4)

    def _attack_sort_key(self, attack: dict[str, Any]) -> tuple[int, str]:
        severity = str(
            attack.get("severity")
            or self._priority_to_severity(str(attack.get("priority", "medium")))
        ).lower()
        return (self._severity_rank(severity), str(attack.get("profile_name", "")))

    def _severity_to_priority(self, severity: str) -> str:
        severity = str(severity).lower()
        if severity in {"critical", "high"}:
            return "high"
        if severity == "low":
            return "low"
        return "medium"

    def _priority_to_severity(self, priority: str) -> str:
        priority = str(priority).lower()
        if priority == "high":
            return "high"
        if priority == "low":
            return "low"
        return "medium"

    def _payload_preview(self, payload: Any) -> str:
        if isinstance(payload, dict) and len(payload) == 1:
            only_value = next(iter(payload.values()))
            return str(only_value)
        return str(payload)

    def suggest_payloads(self, attack_type: str, context: dict[str, Any]) -> list[str]:
        """Generate context-specific payloads using LLM intelligence."""
        prompt = ChatPromptTemplate.from_template(PAYLOAD_SUGGESTION_PROMPT)
        chain = prompt | self.llm | JsonOutputParser()

        try:
            payloads = chain.invoke({"attack_type": attack_type, "context": json.dumps(context)})
            if isinstance(payloads, list):
                return [str(payload) for payload in payloads]
        except Exception as exc:
            logger.warning("LLM payload suggestion failed: %s", exc)

        return ["' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd"]

    def reason_about_field(self, field_name: str, field_type: str) -> str:
        """Use LLM to reason about potential vulnerabilities for a field."""
        prompt = ChatPromptTemplate.from_template(REASONING_PROMPT)
        chain = prompt | self.llm

        try:
            response = chain.invoke({"field_name": field_name, "field_type": field_type})
            return str(response.content)
        except Exception as exc:
            logger.warning("LLM field reasoning failed: %s", exc)
            return (
                f"Test '{field_name}' of type '{field_type}' "
                "with boundary values and injection strings."
            )
