"""The Brain Orchestrator - Main agent logic using LangGraph."""

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
from chaos_kitten.brain.adaptive_planner import AdaptivePayloadGenerator
from langchain_anthropic import ChatAnthropic
# Internal Chaos Kitten imports
from chaos_kitten.brain.openapi_parser import OpenAPIParser
# from chaos_kitten.brain.response_analyzer import ResponseAnalyzer # Deprecated/Replaced
from chaos_kitten.paws.analyzer import ResponseAnalyzer
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten.paws.executor import Executor

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
    planner = AttackPlanner([endpoint])
    return {"planned_attacks": planner.plan_attacks(endpoint)}


async def execute_and_analyze(
    state: AgentState, executor: Executor, config: Dict[str, Any]
) -> Dict[str, Any]:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"findings": state["findings"], "current_endpoint": idx}

    endpoint = state["endpoints"][idx]
    analyzer = ResponseAnalyzer()
    
    adaptive_config = config.get("adaptive", {}) or config.get("agent", {}).get("adaptive", {})
    adaptive_mode = adaptive_config.get("enabled", False)
    max_rounds = adaptive_config.get("max_rounds", 3)
    
    # Initialize Adaptive Generator if needed
    adaptive_gen = None
    if adaptive_mode:
        # Default to Claude for now, could get from config
        llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=0.7)
        adaptive_gen = AdaptivePayloadGenerator(llm, max_rounds=max_rounds)

    new_findings = []
    llm_calls_count = 0

    # Create a copy of the planned attacks so we can append adaptive ones if needed
    # But typically we might want to iterate. 
    # For now, let's iterate over the planned attacks.
    # If we want to add new attacks, we should probably do it in a nested loop or extend the list.
    
    # We will process the original planned attacks. 
    # For each attack, if adaptive mode is on, we generate new payloads and execute them immediately as sub-steps.
    
    for attack in state["planned_attacks"]:
        endpoint_path = endpoint.get("path")
        if not endpoint_path:
            logger.warning("Skipping attack - endpoint missing path: %s", endpoint)
            continue
            
        current_payloads_to_run = [{"payload": attack.get("payload"), "is_adaptive": False}]
        
        # Helper to run a payload and analyze it
        async def run_single_payload(payload_val, is_adaptive=False):
            try:
                result = await executor.execute_attack(
                    method=endpoint.get("method", "GET"),
                    path=endpoint_path,
                    payload=payload_val,
                )
            except Exception:
                logger.exception(
                    "Attack execution failed for %s %s",
                    endpoint.get("method"),
                    endpoint.get("path"),
                )
                return None

            payload_used = ""
            if payload_val is None:
                payload_used = ""
            elif isinstance(payload_val, dict):
                if len(payload_val) == 1:
                    only_value = next(iter(payload_val.values()))
                    payload_used = (
                        only_value if isinstance(only_value, str) else str(only_value)
                    )
                else:
                    payload_used = json.dumps(payload_val, sort_keys=True, default=str)
            else:
                payload_used = str(payload_val)
            
            response_data = {
                "body": result.get("body", result.get("response_body", "")),
                "status_code": result.get("status_code", 0),
                "elapsed_ms": result.get("elapsed_ms", result.get("response_time", 0)),
            }
            
            # Analyze
            # Create a localized attack profile for analysis if it's adaptive
            if is_adaptive:
                # Clone the original attack profile but mark as adaptive
                analysis_attack_profile = attack.copy()
                analysis_attack_profile["name"] = f"[ADAPTIVE] {analysis_attack_profile.get('name', 'Attack')}"
            else:
                analysis_attack_profile = attack

            finding = analyzer.analyze(
                response=response_data,
                attack_profile=analysis_attack_profile,
                endpoint=f"{endpoint.get('method')} {endpoint.get('path')}",
                payload=payload_used
            )

            if finding:
                severity_value = getattr(finding.severity, "value", finding.severity)
                severity_text = str(severity_value).lower()
                title = finding.vulnerability_type or "Potential vulnerability detected"
                if is_adaptive:
                    title = f"[ADAPTIVE] {title}"
                    
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
            return response_data

        # 1. Run the initial planned payload
        original_response = await run_single_payload(attack.get("payload"), is_adaptive=False)
        
        # 2. If adaptive mode is on, generate and run variations
        if adaptive_mode and adaptive_gen and original_response and llm_calls_count < max_rounds:
             llm_calls_count += 1
             
             # Limit number of adaptive payloads per attack to max_rounds
             # The generate_payloads method returns a list of 5. We can run them.
             # We might not do recursive adaptive loops (adaptive on adaptive) for simplicity and cost, 
             # unless "rounds" implies recursion. 
             # The issue says "Cap LLM calls per endpoint with max_adaptive_rounds config". 
             # And "after each probe request... generate 5 more".
             # Let's interpret "rounds" as depth or just number of generations.
             # For now, let's do 1 level of adaptation (generate 5 variations from the original response).
             # If max_rounds > 1, maybe we pick the most interesting result and recurse?
             # To keep it simple and safe for MVP: 1 generation step producing N payloads.
             
             # Actually, if max_rounds is applied to "LLM calls per endpoint", 
             # we should probably track calls.
             # For now, let's just do one generation per planned attack.
             
             generated_payloads = adaptive_gen.generate_payloads(
                 endpoint=endpoint,
                 previous_payload=attack.get("payload"),
                 response=original_response
             )
             
             # Ensure we don't exceed some sanity limit if the LLM returns too many
             for gen_payload in generated_payloads[:max_rounds*5]: # loose cap
                 await run_single_payload(gen_payload, is_adaptive=True)

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
    5. Generates reports
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    def _build_graph(self, executor: Executor):
        if not HAS_LANGGRAPH:
            raise ImportError(
                "langgraph is not available (requires Python 3.9+). "
                "Please upgrade Python or use a compatible langgraph version."
            )
        from langgraph.graph import END, START, StateGraph
        workflow = StateGraph(AgentState)

        workflow.add_node("parse", parse_openapi)
        workflow.add_node("plan", plan_attacks)
        workflow.add_node(
            "execute_analyze", partial(execute_and_analyze, executor=executor, config=self.config)
        )

        workflow.add_edge(START, "parse")
        workflow.add_edge("parse", "plan")
        workflow.add_edge("plan", "execute_analyze")

        workflow.add_conditional_edges(
            "execute_analyze", should_continue, {"plan": "plan", "end": END}
        )
        return workflow.compile()

    async def run(self) -> Dict[str, Any]:
        console.print("[bold green]🧠 Chaos Kitten Brain Initializing...[/bold green]")

        api_config = self.config.get("api")
        target_config = self.config.get("target")

        spec_path = (
            (api_config.get("spec_path") if isinstance(api_config, dict) else None)
            or self.config.get("spec")
            or (
                target_config.get("openapi_spec")
                if isinstance(target_config, dict)
                else None
            )
        )
        target_url = (
            target_config.get("base_url")
            if isinstance(target_config, dict)
            else target_config
        ) or None

        missing_keys = []
        if not spec_path:
            missing_keys.append("api.spec_path/spec")
        if not target_url:
            missing_keys.append("target.base_url/target")

        if missing_keys:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing_keys)}. "
                f"Please ensure spec_path and target_url are provided in the config."
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:

            scan_task = progress.add_task("[cyan]Scanning endpoints...", total=None)

            async with Executor(base_url=target_url) as executor:
                initial_state: AgentState = {
                    "spec_path": spec_path,
                    "base_url": target_url,
                    "endpoints": [],
                    "current_endpoint": 0,
                    "planned_attacks": [],
                    "results": [],
                    "findings": [],
                }

                app = self._build_graph(executor)

                final_state = initial_state
                async for output in app.astream(initial_state):
                    for node_name, state_update in output.items():
                        final_state.update(state_update)

                        if "endpoints" in state_update:
                            progress.update(
                                scan_task, total=len(state_update["endpoints"])
                            )
                        if node_name == "execute_analyze":
                            progress.advance(scan_task)

        reporter_cfg = self.config.get("reporting", {})
        reporter = Reporter(
            output_path=reporter_cfg.get("output_path", "./reports"),
            output_format=reporter_cfg.get("format", "html"),
        )

        report_file = reporter.generate(
            {"vulnerabilities": final_state["findings"]}, target_url
        )

        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(
            f"[bold cyan] Report generated:[/bold cyan] [underline]{report_file}[/underline]"
        )

        return {
            "vulnerabilities": final_state["findings"],
            "summary": {
                "total_endpoints": len(final_state["endpoints"]),
                "tested_endpoints": final_state["current_endpoint"],
                "vulnerabilities_found": len(final_state["findings"]),
            },
        }
