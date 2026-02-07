"""The Brain Orchestrator - Main agent logic using LangGraph."""

import logging
import asyncio
from typing import Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from chaos_kitten.brain.openapi_parser import OpenAPIParser
from chaos_kitten.brain.attack_planner import AttackPlanner
from chaos_kitten.paws.executor import Executor
from chaos_kitten.litterbox.reporter import Reporter

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Main agent orchestrator that coordinates attacks.
    
    This class uses LangGraph to create an agentic workflow that:
    1. Parses the OpenAPI spec
    2. Plans attack strategies
    3. Executes attacks
    4. Analyzes results
    5. Generates reports
    """
    
    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the orchestrator.
        
        Args:
            config: Configuration dictionary from chaos-kitten.yaml
        """
        self.config = config
        self.endpoints = []
        self.scan_results = {
            "vulnerabilities": [],
            "summary": {
                "total_endpoints": 0,
                "tested_endpoints": 0,
                "vuln_count": 0,
                "duration": 0
            },
            "timestamp": ""
        }
    
    async def run(self) -> dict[str, Any]:
        """Run the full security scan.
        
        Returns:
            Scan results including vulnerabilities found
        """
        import time
        from datetime import datetime
        start_time = time.time()
        self.scan_results["timestamp"] = datetime.now().isoformat()
        
        console.print("[bold green]🧠 Brain initializing...[/bold green]")
        
        # 1. Parse OpenAPI Spec
        spec_path = self.config.get("api", {}).get("spec_path") or self.config.get("spec")
        if not spec_path:
            raise ValueError("No OpenAPI spec path provided in config (api.spec_path or spec)")

        console.print(f"📋 Parsing OpenAPI spec from: [cyan]{spec_path}[/cyan]")
        
        parser = OpenAPIParser(spec_path)
        try:
            parser.parse()
            self.endpoints = parser.get_endpoints()
            console.print(f"🎯 Found [bold cyan]{len(self.endpoints)}[/bold cyan] endpoints to test.")
            self.scan_results["summary"]["total_endpoints"] = len(self.endpoints)
        except Exception as e:
            console.print(f"[bold red]❌ Failed to parse spec:[/bold red] {e}")
            return {"status": "failed", "error": str(e)}

        # 2. Plan Attacks
        console.print("[yellow]🧠 Planning attack strategies...[/yellow]")
        planner = AttackPlanner(self.endpoints)
        # planner.load_attack_profiles() # Stubbed in planner
        
        target_url = self.config.get("api", {}).get("base_url") or self.config.get("target")

        if not target_url:
             raise ValueError("No target URL provided (api.base_url or target)")

        console.print(f"🚀 Starting scan against: [cyan]{target_url}[/cyan]")

        # 3. Execute
        executor_config = self.config.get("executor", {})
        async with Executor(
            base_url=target_url,
            rate_limit=executor_config.get("rate_limit", 10),
            timeout=executor_config.get("timeout", 30)
        ) as executor:
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                
                task = progress.add_task(description="Scanning...", total=len(self.endpoints))
                
                for endpoint in self.endpoints:
                    path = endpoint["path"]
                    method = endpoint["method"]
                    progress.update(task, description=f"Scanning {method} {path}")
                    
                    # Plan for this endpoint
                    plans = planner.plan_attacks(endpoint)
                    
                    if not plans:
                        continue
                        
                    for plan in plans:
                        # Execute attack
                        payload = plan.get("payload")
                        
                        try:
                            result = await executor.execute_attack(
                                method=method,
                                path=path,
                                payload=payload
                            )
                            
                            # Simple MVP Analysis: 500 error = Potential SQLi
                            if result["status_code"] >= 500:
                                self.scan_results["vulnerabilities"].append({
                                    "type": plan["type"],
                                    "severity": "High",
                                    "endpoint": f"{method} {path}",
                                    "description": f"Potential {plan['name']} detected. Server returned {result['status_code']}.",
                                    "evidence": result["response_body"][:200]
                                })
                                console.print(f"   [red]⚠️  Vulnerability found at {method} {path}[/red]")
                                
                        except Exception as e:
                             logger.error(f"Error executing attack on {path}: {e}")
                    
                    self.scan_results["summary"]["tested_endpoints"] += 1
                    progress.advance(task)

        # 4. Report
        vuln_count = len(self.scan_results["vulnerabilities"])
        self.scan_results["summary"]["vuln_count"] = vuln_count
        self.scan_results["summary"]["duration"] = time.time() - start_time
        
        console.print(f"\n✅ Scan complete! Found [bold red]{vuln_count}[/bold red] potential vulnerabilities.")
        
        reporter_config = self.config.get("reporting", {})
        output_path = reporter_config.get("output_path", "./reports")
        format_type = reporter_config.get("format", "html")
        
        reporter = Reporter(output_path=output_path, output_format=format_type)
        report_file = reporter.generate(self.scan_results, target_url)
        
        console.print(f"📊 Report saved to: [cyan]{report_file}[/cyan]")
        
        return self.scan_results
