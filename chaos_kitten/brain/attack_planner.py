import glob
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AttackProfile:
    """Represents a loaded attack profile from a YAML file."""
    name: str
    category: str
    severity: str
    description: str
    payloads: List[str]
    target_fields: List[str]
    success_indicators: Dict[str, Any]
    remediation: str = ""
    references: List[str] = field(default_factory=list)


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
        self.attack_profiles: List[AttackProfile] = []
        
        # Configure logging if not already configured
        # Note: Library code should generally not call basicConfig().
        # Leaving this to the application entry point.
        pass
    
    def load_attack_profiles(self) -> None:
        """Load all attack profiles from the toys directory."""
        search_path = os.path.join(self.toys_path, "*.yaml")
        yaml_files = glob.glob(search_path)
        
        if not yaml_files:
            logger.warning(f"No attack profiles found in {self.toys_path}")
            return

        for file_path in yaml_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                
                if not data:
                    logger.warning(f"Skipping empty file: {file_path}")
                    continue
                    
                # Basic validation of required fields
                required_fields = ["name", "category", "severity", "payloads", "target_fields"]
                missing = [field for field in required_fields if field not in data]
                
                if missing:
                    logger.warning(f"Skipping {file_path}: Missing required fields {missing}")
                    continue

                profile = AttackProfile(
                    name=data["name"],
                    category=data["category"],
                    severity=data["severity"],
                    description=data.get("description", ""),
                    payloads=data["payloads"],
                    target_fields=data["target_fields"],
                    success_indicators=data.get("success_indicators", {}),
                    remediation=data.get("remediation", ""),
                    references=data.get("references", [])
                )
                self.attack_profiles.append(profile)
                logger.debug(f"Loaded attack profile: {profile.name}")
                
            except Exception as e:
                logger.error(f"Failed to load attack profile from {file_path}: {e}")
        
        logger.info(f"Loaded {len(self.attack_profiles)} attack profiles")
    
    def plan_attacks(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Plan attacks for a specific endpoint.
        
        Args:
            endpoint: Endpoint definition from OpenAPI parser.
                      Expected structure:
                      {
                          "path": "/api/login",
                          "method": "post",
                          "parameters": [...],
                          "requestBody": {...} 
                      }
            
        Returns:
            List of planned attacks with payloads and expected behaviors:
            [
                {
                    "profile_name": str,
                    "endpoint": str,
                    "method": str,
                    "field": str,
                    "location": str (query/path/body),
                    "payloads": list[str],
                    "expected_indicators": dict,
                    "severity": str
                },
                ...
            ]
        """
        planned_attacks = []
        
        if not self.attack_profiles:
            self.load_attack_profiles()
            
        endpoint_path = endpoint.get("path", "")
        method = endpoint.get("method", "").lower()
        
        # Collect potential target fields from the endpoint definition
        targetable_fields = [] # (name, location, type)
        
        # 1. Check parameters (query, path, header, cookie)
        for param in endpoint.get("parameters", []):
            p_name = param.get("name")
            p_in = param.get("in")
            p_schema = param.get("schema", {})
            p_type = p_schema.get("type", "string")
            if p_name:
                targetable_fields.append({"name": p_name, "location": p_in, "type": p_type})
                
        # 2. Check request body
        request_body = endpoint.get("requestBody") or {}
        content = request_body.get("content", {})
        for content_type, media_type in content.items():
            schema = media_type.get("schema", {})
            properties = schema.get("properties", {})
            for prop_name, prop_details in properties.items():
                p_type = prop_details.get("type", "string")
                targetable_fields.append({"name": prop_name, "location": "body", "type": p_type})

        # Iterate through loaded profiles and find matches
        for profile in self.attack_profiles:
            # Special handling for GraphQL Security profile
            if profile.name == "GraphQL Security":
                # Check if endpoint path ends with /graphql
                if endpoint_path.endswith("/graphql") or "graphql" in endpoint_path.lower():
                    # Plan attacks for this endpoint
                    # GraphQL usually has a single entry point, so we attack the 'query' or body
                    attack_plan = {
                        "profile_name": profile.name,
                        "endpoint": endpoint_path,
                        "method": method,
                        "field": "query", # Virtual field name
                        "location": "graphql", # Special location for executor
                        "payloads": profile.payloads,
                        "expected_indicators": profile.success_indicators,
                        "severity": profile.severity
                    }
                    planned_attacks.append(attack_plan)
                continue

            # Special handling for file upload profile
            if profile.name == "File Upload Bypass":
                # Check if endpoint accepts multipart/form-data
                request_body = endpoint.get("requestBody") or {}
                content = request_body.get("content", {})
                if "multipart/form-data" in content or "application/octet-stream" in content:
                    # Find file fields
                    schema = content.get("multipart/form-data", {}).get("schema", {}) or \
                             content.get("application/octet-stream", {}).get("schema", {})
                    
                    properties = schema.get("properties", {})
                    for prop_name, prop_details in properties.items():
                        # Heuristic: verify if it looks like a file upload
                        # OpenAPI 3.0: type: string, format: binary
                        p_type = prop_details.get("type")
                        p_format = prop_details.get("format")
                        
                        is_file = (p_type == "string" and p_format in ("binary", "base64")) or \
                                  (prop_name.lower() in profile.target_fields)

                        if is_file:
                            attack_plan = {
                                "profile_name": profile.name,
                                "endpoint": endpoint_path,
                                "method": method,
                                "field": prop_name,
                                "location": "file", # Special location for executor
                                "payloads": profile.payloads,
                                "expected_indicators": profile.success_indicators,
                                "severity": profile.severity
                            }
                            planned_attacks.append(attack_plan)
                continue

            # ... (Standard logic for other profiles)
            
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
                        
                    attack_plan = {
                        "profile_name": profile.name,
                        "endpoint": endpoint_path,
                        "method": method,
                        "field": field_name,
                        "location": field_info["location"],
                        "payloads": profile.payloads,
                        "expected_indicators": profile.success_indicators,
                        "severity": profile.severity
                    }
                    planned_attacks.append(attack_plan)

        # Prioritize by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        planned_attacks.sort(key=lambda x: severity_order.get(x["severity"].lower(), 99))
        
        return planned_attacks
    
    def reason_about_field(self, field_name: str, field_type: str) -> str:
        """Use LLM to reason about potential vulnerabilities for a field.
        
        Example:
            field_name="age", field_type="integer"
            Returns: "I'll test negative numbers, zero, extremely large values, and strings"
        
        Args:
            field_name: Name of the field
            field_type: Data type of the field
            
        Returns:
            Reasoning about what to test
        """
        # TODO: Implement LLM reasoning in future iteration
        return f"Standard testing for {field_type} field '{field_name}'"
