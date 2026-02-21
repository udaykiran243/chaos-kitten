from __future__ import annotations

"""The Brain Orchestrator - Main agent logic using LangGraph."""

import asyncio
import json
import logging
from functools import partial
from typing import Any, Dict, List, Literal, TypedDict

try:
    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except (ImportError, TypeError):
    HAS_LANGGRAPH = False
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from chaos_kitten.brain.attack_planner import AttackPlanner

# Internal Chaos Kitten imports
from chaos_kitten.brain.openapi_parser import OpenAPIParser
# from chaos_kitten.brain.response_analyzer import ResponseAnalyzer # Deprecated/Replaced
from chaos_kitten.paws.analyzer import ResponseAnalyzer
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten.paws.executor import Executor
from chaos_kitten.brain.recon import ReconEngine

logger = logging.getLogger(__name__)
console = Console()


class AgentState(TypedDict):
    spec_path: str
    base_url: str
    endpoints: List[Dict[str, Any]]
    current_endpoint: int
    planned_attacks: List[Dict[str, Any]]
    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    recon_results: Dict[str, Any]


async def run_recon(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    # Renamed to app_config to avoid LangGraph collision
    console.print("[bold blue]🔍 Starting Reconnaissance Phase...[/bold blue]")
    try:
        engine = ReconEngine(app_config)
        
        # Run recon engine in an executor to avoid blocking the async loop
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(None, engine.run)

        if results:
            subs = len(results.get('subdomains', []))
            techs = len(results.get('technologies', {}))
            console.print(f"[green]Recon complete: Found {subs} subdomains and fingerprint info for {techs} targets[/green]")
        return {"recon_results": results}
    except Exception as e:
        logger.exception("Reconnaissance failed")
        console.print(f"[red]Reconnaissance failed: {e}[/red]")
        return {"recon_results": {}}



def parse_openapi(state: AgentState) -> Dict[str, Any]:
    try:
        parser = OpenAPIParser(state["spec_path"])
        parser.parse()
        endpoints = parser.get_endpoints()
    except Exception:
        logger.exception("Failed to parse OpenAPI spec")
        raise
    return {"endpoints": endpoints, "current_endpoint": 0}


def plan_attacks(state: AgentState) -> Dict[str, Any]:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"planned_attacks": []}

    endpoint = state["endpoints"][idx]
    
    # In future, we can inject recon data into the planner context here.
    # For now, we trust the LLM to deduce context from the endpoint itself.
    
    planner = AttackPlanner([endpoint])
    return {"planned_attacks": planner.plan_attacks(endpoint)}


async def execute_and_analyze(state: AgentState, executor: Executor) -> Dict[str, Any]:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"findings": state["findings"], "current_endpoint": idx}

    endpoint = state["endpoints"][idx]
    analyzer = ResponseAnalyzer()

    new_findings = []

    for attack in state["planned_attacks"]:
        endpoint_path = endpoint.get("path")
        if not endpoint_path:
            logger.warning("Skipping attack - endpoint missing path: %s", endpoint)
            continue
        try:
            result = await executor.execute_attack(
                method=endpoint.get("method", "GET"),
                path=endpoint_path,
                payload=attack.get("payload"),
            )
        except Exception:
            logger.exception(
                "Attack execution failed for %s %s",
                endpoint.get("method"),
                endpoint.get("path"),
            )
            continue

        payload_obj = attack.get("payload")
        if payload_obj is None:
            payload_used = ""
        elif isinstance(payload_obj, dict):
            if len(payload_obj) == 1:
                only_value = next(iter(payload_obj.values()))
                payload_used = (
                    only_value if isinstance(only_value, str) else str(only_value)
                )
            else:
                payload_used = json.dumps(payload_obj, sort_keys=True, default=str, ensure_ascii=True)
        else:
            payload_used = str(payload_obj)
        
        # Prepare params for new analyzer signature
        response_data = {
            "body": result.get("body", result.get("response_body", "")),
            "status_code": result.get("status_code", 0),
            "elapsed_ms": result.get("elapsed_ms", result.get("response_time", 0)),
        }
        
        # Attack profile is in 'attack' variable
        finding = analyzer.analyze(
            response=response_data,
            attack_profile=attack,
            endpoint=f"{endpoint.get('method')} {endpoint.get('path')}",
            payload=payload_used
        )

        if finding:
            severity_value = getattr(finding.severity, "value", finding.severity)
            severity_text = str(severity_value).lower()
            title = finding.vulnerability_type or "Potential vulnerability detected"
            description = finding.evidence or "Potential vulnerability detected"
            new_findings.append(
                {
                    "type": finding.vulnerability_type,
                    "title": title,
                    "description": description,
                    "severity": severity_text,
                    "endpoint": finding.endpoint,
                    "method": endpoint.get("method", "GET"),
                    "evidence": finding.evidence,
                    "payload": payload_used,
                    "proof_of_concept": "",
                    "remediation": (
                        finding.recommendation
                        if getattr(finding, "recommendation", "")
                        else "Review input handling and validation."
                    ),
                }
            )

    return {"findings": state["findings"] + new_findings, "current_endpoint": idx + 1}


def should_continue(state: AgentState) -> Literal["plan", "end"]:
    if state["current_endpoint"] < len(state["endpoints"]):
        return "plan"
    return "end"


class Orchestrator:
    """
    This class uses LangGraph to create an agentic workflow that:
    1. Parses the OpenAPI spec
    2. Plans attack strategies
    3. Executes attacks
    4. Analyzes results
    5. Runs chaos testing (optional)
    6. Generates reports
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        chaos: bool = False,
        chaos_level: int = 3,
    ) -> None:
        """Initialize the orchestrator.
        
        Args:
            config: Configuration dictionary from chaos-kitten.yaml
            chaos: Whether to enable chaos mode
            chaos_level: Chaos intensity from 1 to 5
        """
        self.config = config
        self.chaos = chaos
        self.chaos_level = chaos_level
        
        # State tracking
        self.vulnerabilities: List[Dict[str, Any]] = []

    async def run(self) -> Dict[str, Any]:
        """Run the full security scan.
        
        Returns:
            Scan results including vulnerabilities found
        """
        target_url = self.config.get("target", {}).get("base_url")
        if not target_url:
            raise ValueError("Target URL not configured")
            
        print(f"🚀 Starting scan against {target_url}")
        
        findings = []
        if HAS_LANGGRAPH:
            # Build the graph
            workflow = StateGraph(AgentState)

            # Nodes
            workflow.add_node("recon", partial(run_recon, app_config=self.config))
            workflow.add_node("parse", parse_openapi)
            workflow.add_node("plan", plan_attacks)
            
            # Edges
            workflow.add_edge(START, "recon")
            workflow.add_edge("recon", "parse")
            workflow.add_edge("parse", "plan")

            async with Executor(self.config) as executor:
                workflow.add_node("execute", partial(execute_and_analyze, executor=executor))
                workflow.add_edge("plan", "execute")

                workflow.add_conditional_edges(
                    "execute",
                    should_continue,
                    {
                        "plan": "plan",
                        "end": END
                    }
                )

                app = workflow.compile()
                
                # Initial state
                initial_state = {
                    "spec_path": self.config.get("target", {}).get("openapi_spec", ""),
                    "base_url": target_url,
                    "endpoints": [],
                    "current_endpoint": 0,
                    "planned_attacks": [],
                    "results": [],
                    "findings": [],
                    "recon_results": {}
                }

                # Run the agent
                final_state = await app.ainvoke(initial_state)
                findings = final_state.get("findings", [])
        else:
            print("⚠️  LangGraph not installed. Skipping standard agentic scan.")

        self.vulnerabilities = findings

        # Run chaos mode if enabled
        chaos_findings = []
        if self.chaos:
            from chaos_kitten.brain.chaos_engine import ChaosEngine
            
            engine = ChaosEngine(chaos_level=self.chaos_level)
            chaos_findings = await engine.run_chaos_tests(target_url)
            
            # Print chaos summary
            summary = engine.get_summary()
            if summary["total_findings"] > 0:
                print("\n🌪️  [CHAOS] Summary:")
                print("   Critical: {}".format(summary["by_severity"].get("critical", 0)))
                print("   High: {}".format(summary["by_severity"].get("high", 0)))
                print("   Medium: {}".format(summary["by_severity"].get("medium", 0)))
            
        return {
            "vulnerabilities": self.vulnerabilities,
            "chaos_findings": chaos_findings,
        }
