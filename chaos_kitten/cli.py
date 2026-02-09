"""Chaos Kitten CLI - Command Line Interface."""

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(
    name="chaos-kitten",
    help="🐱 Chaos Kitten - The adorable AI agent that knocks things off your API tables",
    add_completion=False,
)
console = Console()

ASCII_CAT = r"""
           /\___/\  
   _      ( o . o )   
  / \      >  ^  <     ~
  | |o====/==  || \   /
  | |    /     ||  \ /
  | |   (      ||   )
  |_|    \_____oo__/
"""


@app.command()
def version():
    """Show version information."""
    from chaos_kitten import __version__
    console.print(f"[bold magenta]Chaos Kitten[/bold magenta] v{__version__}")


@app.command()
def init():
    """Initialize a new chaos-kitten.yaml configuration file."""
    config_template = '''"""# Chaos Kitten Configuration
target:
  base_url: "http://localhost:3000"
  openapi_spec: "./openapi.json"
  auth:
    type: "bearer"  # bearer, basic, oauth, none
    token: "${API_TOKEN}"

agent:
  llm_provider: "anthropic"  # anthropic, openai, ollama
  model: "claude-3-5-sonnet-20241022"
  temperature: 0.7
  max_iterations: 10

executor:
  concurrent_requests: 5
  timeout: 30
  rate_limit: 10  # requests per second

safety:
  allowed_domains:
    - "localhost"
    - "*.test.com"
  destructive_mode: false

toys:
  enabled:
    - "sql_injection"
    - "xss"
    - "idor"
  disabled:
    - "dos"

reporting:
  format: "html"
  output_path: "./reports"
  include_poc: true
  include_remediation: true
"""'''
    
    with open("chaos-kitten.yaml", "w") as f:
        f.write(config_template.strip('"""'))
    
    console.print("[green]✓[/green] Created chaos-kitten.yaml")
    console.print("Edit the file with your target API details.")


@app.command()
def scan(
    config: str = typer.Option(
        "chaos-kitten.yaml",
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    target: str = typer.Option(
        None,
        "--target",
        "-t",
        help="Target URL (overrides config)",
    ),
    spec: str = typer.Option(
        None,
        "--spec",
        "-s",
        help="Path to OpenAPI spec (overrides config)",
    ),
    output: str = typer.Option(
        "./reports",
        "--output",
        "-o",
        help="Directory to save the security report",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Format of the report (html, markdown, json, sarif)",
    ),
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Exit with code 1 if critical vulnerabilities found",
    ),
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider (openai, anthropic, ollama)",
    ),
    demo: bool = typer.Option(
        False,
        "--demo",
        help="Run scan against the demo vulnerable API",
    ),
):
    """Scan an API for security vulnerabilities."""
    console.print(Panel(ASCII_CAT, title="🐱 Chaos Kitten", border_style="magenta"))
    console.print()

    if demo:
        console.print("[bold cyan]🎮 Running in DEMO mode![/bold cyan]")
        target = target or "http://localhost:5000"
        spec = spec or "examples/sample_openapi.json"
        console.print(f"🎯 Target: {target}")
        console.print(f"📋 Spec: {spec}")
        console.print()

    # Check for API keys if using LLM providers
    import os
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        console.print("[bold red]❌ I can't see![/bold red]")
        console.print("I need an [bold]ANTHROPIC_API_KEY[/bold] or [bold]OPENAI_API_KEY[/bold] to plan my mischief.")
        console.print("[dim]Please set one in your environment or .env file.[/dim]")
        
        if not demo:
            raise typer.Exit(code=1)
        else:
            console.print("[yellow]⚠️  Proceeding anyway since we are in demo mode...[/yellow]")
    

    # Build configuration
    app_config = {}
    
    # Try to load from file
    from chaos_kitten.utils.config import Config
    config_loader = Config(config)
    try:
        app_config = config_loader.load()
    except FileNotFoundError:
        # It's okay if file doesn't exist AND we provided args
        if not target and not spec and not demo:
            console.print(f"[bold red]❌ Config file not found: {config}[/bold red]")
            console.print("Run 'chaos-kitten init' or provide --target and --spec args.")
            raise typer.Exit(code=1)
            
    # CLI args override config
    if target:
        if "target" not in app_config: app_config["target"] = {}
        app_config["target"]["base_url"] = target
        # Also support legacy api path for backward compat if needed, but prefer target
        if "api" not in app_config: app_config["api"] = {}
        app_config["api"]["base_url"] = target
        
    if spec:
        if "target" not in app_config: app_config["target"] = {}
        app_config["target"]["openapi_spec"] = spec
        # Support legacy path
        if "api" not in app_config: app_config["api"] = {}
        app_config["api"]["spec_path"] = spec
        
    if output:
        if "reporting" not in app_config: app_config["reporting"] = {}
        app_config["reporting"]["output_path"] = output

    if format:
        if "reporting" not in app_config: app_config["reporting"] = {}
        app_config["reporting"]["format"] = format

    if provider:
        if "agent" not in app_config: app_config["agent"] = {}
        app_config["agent"]["llm_provider"] = provider

    # Run the orchestrator
    from chaos_kitten.brain.orchestrator import Orchestrator
    orchestrator = Orchestrator(app_config)
    try:
        import asyncio
        asyncio.run(orchestrator.run())
    except Exception as e:
        console.print(f"[bold red]❌ Scan failed:[/bold red] {e}")
        # import traceback
        # console.print(traceback.format_exc())
        raise typer.Exit(code=1)

@app.command()
def meow():
    """🐱 Meow!"""
    console.print(Panel(ASCII_CAT, title="🐱 Meow!", border_style="magenta"))
    console.print("[italic]I'm going to knock some vulnerabilities off your API table![/italic]")


if __name__ == "__main__":
    app()
