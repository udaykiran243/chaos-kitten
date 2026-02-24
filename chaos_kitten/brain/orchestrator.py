from __future__ import annotations

"""The Brain Orchestrator - Main agent logic using LangGraph."""

import asyncio
import json
import logging
import time
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, TypedDict

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

from chaos_kitten.utils.checkpoint import (
    CheckpointData,
    calculate_config_hash,
    clean_checkpoint,
    load_checkpoint,
    save_checkpoint,
)

logger = logging.getLogger(__name__)
console = Console()

class AgentState(TypedDict):
    """The state shared between nodes in the graph."""
    targets: List[str]
    openapi_spec: Optional[Dict[str, Any]]
    attack_profiles: List[Dict[str, Any]]
    planned_attacks: List[Dict[str, Any]]
    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    recon_results: Dict[str, Any]
    nl_plan: Optional[Dict[str, Any]]  # Natural language planning results


async def run_recon(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Run the reconnaissance engine."""
    from chaos_kitten.brain.recon import ReconEngine
    
    console.print("[bold blue]🔍 Starting Reconnaissance Phase...[/bold blue]")
    if state.get("recon_results"):
        if not silent:
            console.print("[yellow]✨ Skipping recon (results loaded from checkpoint)[/yellow]")
        return {"recon_results": state["recon_results"]}

    try:
        engine = ReconEngine(app_config)
        results = await engine.run()

        if results and not silent:
            subs = len(results.get('subdomains', []))
            techs = len(results.get('technologies', {}))
            console.print(f"[green]Recon complete: Found {subs} subdomains and fingerprint info for {techs} targets[/green]")
        return {"recon_results": results}
    except Exception as e:
        logger.exception("Reconnaissance failed")
        if not silent:
            console.print(f"[red]Reconnaissance failed: {e}[/red]")
        return {"recon_results": {}}


async def parse_openapi(state: AgentState) -> Dict[str, Any]:
    """Parse the OpenAPI specification."""
    from chaos_kitten.brain.openapi_parser import OpenAPIParser
    
    console.print("[bold blue]📖 Parsing OpenAPI Specification...[/bold blue]")
    if state.get("openapi_spec"):
        return {"openapi_spec": state["openapi_spec"]}
        
    recon = state.get("recon_results", {})
    spec_path = recon.get("openapi_spec_path")
    
    if not spec_path:
        console.print("[yellow]⚠️ No OpenAPI spec found during recon. Checking config...[/yellow]")
        return {"openapi_spec": None}
        
    try:
        parser = OpenAPIParser(spec_path)
        spec = parser.parse()
        console.print(f"[green]OpenAPI spec parsed: Found {len(spec.get('paths', {}))} endpoints[/green]")
        return {"openapi_spec": spec}
    except Exception as e:
        logger.error(f"Failed to parse OpenAPI spec: {e}")
        return {"openapi_spec": {}}


async def natural_language_plan(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a high-level natural language attack plan."""
    from chaos_kitten.brain.attack_planner import AttackPlanner
    
    console.print("[bold blue]📝 Generating Natural Language Attack Plan...[/bold blue]")
    if state.get("nl_plan"):
        return {"nl_plan": state["nl_plan"]}
        
    try:
        planner = AttackPlanner(app_config)
        nl_plan = planner.generate_natural_language_plan(state.get("openapi_spec"))
        return {"nl_plan": nl_plan}
    except Exception as e:
        logger.error(f"Failed to generate NL plan: {e}")
        return {"nl_plan": None}


async def plan_attacks(state: AgentState) -> Dict[str, Any]:
    """Plan specific attack vectors based on the API spec."""
    from chaos_kitten.brain.attack_planner import AttackPlanner
    
    console.print("[bold blue]🎯 Planning Attack Vectors...[/bold blue]")
    if state.get("planned_attacks"):
        return {"planned_attacks": state["planned_attacks"]}
        
    try:
        # Actually initializing the LLM and planning
        return {"planned_attacks": [{"id": "placeholder", "type": "info_gathering", "method": "GET", "path": "/"}]}
    except Exception as e:
        logger.error(f"Failed to plan attacks: {e}")
        return {"planned_attacks": []}


async def execute_and_analyze(state: AgentState, executor: Any, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute planned attacks and analyze responses."""
    from chaos_kitten.paws.analyzer import ResponseAnalyzer
    
    console.print("[bold blue]⚔️  Executing Attacks...[/bold blue]")
    # Placeholder for actual execution logic
    return {"results": [], "findings": []}


def should_continue(state: AgentState) -> Literal["plan", "end"]:
    """Determine if more attack planning is needed."""
    return "end"


class Orchestrator:
    """Orchestrates the main agent workflow using LangGraph."""

    def __init__(self, config: Dict[str, Any], chaos: bool = False, chaos_level: int = 3, resume: bool = False):
        self.config = config
        self.chaos = chaos
        self.chaos_level = chaos_level
        self.resume = resume
        self.checkpoint_file = Path("chaos-kitten.checkpoint.json")

    async def run(self) -> Dict[str, Any]:
        """Run the full agentic workflow."""
        if not HAS_LANGGRAPH:
            console.print("[bold red]Error: langgraph is not installed.[/bold red]")
            return {"status": "failed", "error": "langgraph is not installed"}

        from chaos_kitten.paws.executor import Executor
        executor = Executor(self.config)
        
        graph = self._build_graph(executor)
        
        initial_state: AgentState = {
            "targets": [],
            "openapi_spec": None,
            "attack_profiles": [],
            "planned_attacks": [],
            "results": [],
            "findings": [],
            "recon_results": {},
            "nl_plan": None
        }

        # Handle resume
        if self.resume:
            checkpoint = load_checkpoint(self.checkpoint_file)
            if checkpoint:
                initial_state.update(checkpoint.state)
                console.print("[bold green]🔄 Resuming from checkpoint...[/bold green]")

        try:
            final_state = await graph.ainvoke(initial_state)
            
            # Save checkpoint (implied success if we got here)
            save_checkpoint(self.checkpoint_file, CheckpointData(
                config_hash=calculate_config_hash(self.config),
                timestamp=time.time(),
                state=final_state,
                completed=True
            ))

            return {
                "status": "success",
                "summary": {
                    "tested_endpoints": len(final_state.get("results", [])),
                    "vulnerabilities_found": len(final_state.get("findings", []))
                },
                "findings": final_state.get("findings", [])
            }
        except Exception as e:
            logger.exception("Orchestrator execution failed")
            return {"status": "failed", "error": str(e)}

    def _build_graph(self, executor: Any) -> StateGraph:
        """Build the LangGraph workflow."""
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("recon", partial(run_recon, app_config=self.config))
        # FIX: Added partial with app_config to parse_openapi
        workflow.add_node("parse", partial(parse_openapi, app_config=self.config)) 
        workflow.add_node("nl_plan", partial(natural_language_plan, app_config=self.config))
        workflow.add_node("plan", plan_attacks)
        workflow.add_node("execute", partial(execute_and_analyze, executor=executor, app_config=self.config))

        # Edges
        workflow.add_edge(START, "recon")
        workflow.add_edge("recon", "parse")
        workflow.add_edge("parse", "nl_plan")
        workflow.add_edge("nl_plan", "plan")
        workflow.add_edge("plan", "execute")

        workflow.add_conditional_edges(
            "execute",
            should_continue,
            {
                "plan": "plan",
                "end": END
            }
        )

        return workflow.compile()
