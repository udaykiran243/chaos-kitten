"""The Brain Orchestrator - Main agent logic using LangGraph."""

from typing import Any, Dict, List


class Orchestrator:
    """Main agent orchestrator that coordinates attacks.
    
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
        
        # TODO: Implement the main agent loop with LangGraph
        # For now, the standard scan is a placeholder
        print("\n[Standard scan placeholder — agentic brain coming soon]")

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
