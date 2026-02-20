# Developer Guide (Contributors and Extenders)

This guide is for developers who want to contribute to Chaos Kitten or extend it with new attack profiles, payload libraries, and runtime capabilities.

If you're new to the repo, skim the README first. For deeper dives, start with:

- [`README.md`](../README.md) (overview and quickstart)
- [`docs/getting_started.md`](./getting_started.md) (local install and first scan)
- [`docs/architecture.md`](./architecture.md) (how the runtime fits together)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`docs/contributing_guide.md`](./contributing_guide.md) (contribution workflow)

This guide describes the current codebase at a high level. Internal module names and file locations may change over time; when in doubt, prefer your local file tree and `rg`/IDE search over hard-coded paths.

**Note:** File names, optional dependency extras, and internal wiring may change between releases. Treat any paths and module names in this guide as examples, and confirm against your local checkout.

## Table of contents

- [Quickstart for contributors](#quickstart-for-contributors)
- [System architecture overview](#system-architecture-overview)
- [Local development setup](#local-development-setup)
- [Project structure walkthrough](#project-structure-walkthrough)
- [CLI usage](#cli-usage)
- [Library usage (internal API)](#library-usage-internal-api)
- [Adding new attack profiles (YAML)](#adding-new-attack-profiles-yaml)
- [Adding payloads to `naughty_strings.json`](#adding-payloads-to-naughty_stringsjson)
- [LLM debugging tips](#llm-debugging-tips)
- [Code style and testing expectations](#code-style-and-testing-expectations)
- [Common troubleshooting](#common-troubleshooting)

## Quickstart for contributors

1. Clone the repo and create a virtualenv.
2. Install dev dependencies (`python -m pip install -e '.[dev]'`).
3. Run `pytest` to ensure your environment is healthy.
4. Start the demo API (`examples/demo_api`) and run a demo scan (see [Verify your setup](#verify-your-setup-optional-smoke-test)).
5. Make a small change and follow the PR workflow in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## System architecture overview

A scan typically looks like this:

1. The CLI loads a config and builds a runtime configuration.
2. The Brain parses your OpenAPI/Swagger spec into a list of endpoints.
3. The Brain plans attacks for each endpoint (rule-based today; LLM-driven planning is an extension point).
4. The Paws execute HTTP requests against the target.
5. The Brain analyzes responses and turns them into findings.
6. The Litterbox generates a report (HTML/Markdown/JSON/SARIF).

Orchestration is implemented in `chaos_kitten/brain/orchestrator.py`.

ASCII view of the runtime modules:

```
repo root
  ├─ chaos_kitten/            # core Python package
  │   ├─ brain/               # parsing, planning, orchestration, analysis
  │   ├─ paws/                # HTTP + browser execution
  │   └─ litterbox/           # report generation
  ├─ toys/                    # YAML/JSON attack content
  └─ tests/                   # pytest
```

This tree is illustrative; see [`docs/architecture.md`](./architecture.md) for the canonical and up-to-date project layout.

For more detail (including a fuller diagram and data flow), see [`docs/architecture.md`](./architecture.md).

Note: Some extension areas (LLM-driven planning and browser-based validation) are under active development and may evolve quickly. If you're building a large feature in those areas, check the issue tracker first to avoid duplicating ongoing work.

## Local development setup

### Prerequisites

- Python 3.10+
- Git

Optional:

- Playwright (only needed for browser-based validation; current browser automation is still an extension point)

### Clone and install

On current `main`, development dependencies are installed via the `dev` extra. If you hit an extras-related error, open `pyproject.toml` and use the extras defined under `[project.optional-dependencies]`.

**Note:** The examples `.[dev]` and `.[dev,browser]` must match extras actually defined in your `pyproject.toml`.

```bash
git clone https://github.com/mdhaarishussain/chaos-kitten.git
cd chaos-kitten

python -m venv .venv
source .venv/bin/activate

# On Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

python -m pip install -U pip
python -m pip install -e '.[dev]'
```

If you're working on browser automation:

```bash
python -m pip install -e '.[dev,browser]'
python -m playwright install
```

### Environment variables

Chaos Kitten reads provider credentials from environment variables.

For a starter file you can copy into a local `.env`, see `.env.example` in the repo root.

Most contributors will set *one* cloud LLM provider key:

- `ANTHROPIC_API_KEY` (Anthropic)
- `OPENAI_API_KEY` (OpenAI)

If you use a remote LLM provider (Anthropic/OpenAI), set the corresponding API key. Some scan modes and configurations require a valid key, while demo/heuristic modes may run with reduced capabilities. For the most accurate behavior, trust `chaos-kitten scan --help` and the CLI output over this document.

The config loader also expands `${VARNAME}` syntax inside `chaos-kitten.yaml` (see `chaos_kitten/utils/config.py`).

Note: The CLI does not automatically load a `.env` file. If you prefer `.env`, load it into your shell (for example via `direnv`, your IDE, or your task runner). For a quick local shell setup:

```bash
# In bash/zsh:
set -a
source .env
set +a
```

The canonical list of dependencies and dev tooling is in `pyproject.toml`.

### Run tests

```bash
pytest
```

### Verify your setup (optional smoke test)

1. Start the demo API (terminal 1):

   ```bash
   cd examples/demo_api
   python -m pip install -r requirements.txt
   python app.py
   ```

2. Run a demo scan (terminal 2, repo root):

   ```bash
   chaos-kitten version
   chaos-kitten scan --demo --output ./reports --format json
   ```

If the scan completes and writes a report under `./reports`, your environment is ready.

## Project structure walkthrough

The paths below match the current source tree.

### `chaos_kitten/` (library + CLI)

- `chaos_kitten/cli.py`
  - Typer CLI entrypoint (`chaos-kitten`).
  - Handles config merging between `chaos-kitten.yaml` and CLI flags.
- `chaos_kitten/utils/config.py`
  - Loads YAML config and expands `${ENV_VAR}` values.
- `chaos_kitten/brain/`
  - `openapi_parser.py`: parses OpenAPI 3.x and Swagger 2.0 into a normalized list of endpoints.
  - `orchestrator.py`: coordinates the scan loop (parse → plan → execute/analyze → report); currently implemented with LangGraph (see [`docs/architecture.md`](./architecture.md) for details).
  - `attack_planner.py`: attack planning (currently rule-based; extension point for loading/selecting `toys/*.yaml`).
  - `response_analyzer.py`: heuristics/regex-based response analysis into typed findings.
- `chaos_kitten/paws/`
  - `executor.py`: async HTTP executor using `httpx`.
  - `browser.py`: browser automation placeholder (Playwright) for client-side validation.
- `chaos_kitten/litterbox/`
  - `reporter.py`: report generation (HTML/Markdown/JSON/SARIF) + templates.

### `toys/` (attack library)

The `toys/` directory contains attack profiles as YAML files and shared payload datasets.

- `toys/*.yaml`: attack profiles (SQLi, XSS, SSRF, etc.)
- `toys/data/naughty_strings.json`: categorized string payload library
- `toys/data/common_passwords.txt`: password list used by some profiles

### `examples/`

- `examples/demo_api/`: intentionally vulnerable Flask API used for local testing.
- `examples/sample_openapi.json`: OpenAPI spec for the demo API.

### `tests/`

Pytest test suite. Patterns to copy when adding new tests:

- unit tests with mocking for orchestrator flow: `tests/test_brain.py`
- CLI integration test using `typer.testing.CliRunner`: `tests/test_integration_scan.py`

## CLI usage

### Common commands

```bash
# Print version
chaos-kitten version

# Generate a starter config
chaos-kitten init

# Run against the demo API
chaos-kitten scan --demo
```

### Scan with explicit target/spec

This is the most reproducible way to run locally (especially for contributors):

```bash
chaos-kitten scan \
  --target http://localhost:5000 \
  --spec examples/sample_openapi.json \
  --output ./reports \
  --format html
```

Report formats supported by the reporter (see `chaos-kitten scan --help` or `chaos_kitten/litterbox/reporter.py` for the authoritative list) are:

- `html`
- `markdown`
- `json`
- `sarif`

For the full contributor workflow (formatting, linting, type-checking, tests), see [Code style and testing expectations](#code-style-and-testing-expectations).

If you need to invoke Chaos Kitten programmatically instead of via the CLI, see [Library usage (internal API)](#library-usage-internal-api).

## Library usage (internal API)

This section is intended primarily for core maintainers and advanced experiments.

### Preferred: invoke the CLI (stable)

Chaos Kitten is CLI-first. For most automation, invoke the CLI from your code:

```python
import subprocess

subprocess.run(
    [
        "chaos-kitten",
        "scan",
        "--demo",
        "--format",
        "json",
        "--output",
        "./reports",
    ],
    check=True,
)
```

### Maintainer-only: Orchestrator (unstable)

Use this only when working on Chaos Kitten internals.

Chaos Kitten is importable as a Python library. One internal entrypoint used by the CLI is the Brain `Orchestrator`.

**Warning:** The imports and return structures in the examples below are internal and may change between releases without deprecation. Do not rely on these interfaces for production integrations. For stable integrations, prefer invoking scans via the CLI (`chaos-kitten scan`). If you embed internals in automation, pin a specific Chaos Kitten version.

Preferred (mirrors the CLI): reuse YAML config loading logic. This assumes a `Config` helper similar to the current `chaos_kitten.utils.config.Config`; adjust the import/usage to match your checkout if it differs.

```python
import asyncio

from chaos_kitten.brain.orchestrator import Orchestrator
from chaos_kitten.utils.config import Config

config = Config("chaos-kitten.yaml").load()
results = asyncio.run(Orchestrator(config).run())
print(results["summary"])
```

For quick experiments, you can also construct a minimal config dict directly. This style is more likely to break across versions; prefer the YAML-based `Config` loader for anything beyond quick local experiments.

```python
import asyncio

from chaos_kitten.brain.orchestrator import Orchestrator

config = {
    "target": {
        "base_url": "http://localhost:5000",
        "openapi_spec": "examples/sample_openapi.json",
    },
    "reporting": {"format": "json", "output_path": "./reports"},
}

results = asyncio.run(Orchestrator(config).run())
print(results["summary"])
```

Notes for extenders:

- The library-level API is still evolving; treat imports like `Orchestrator` as internal building blocks rather than a stable public API.
- When implementing auth, timeouts, or rate limiting, ensure `target.auth.*` and executor settings are threaded from config into `Executor` construction (see `chaos_kitten/brain/orchestrator.py` for current wiring).
- Attack planning is currently rule-based in `AttackPlanner.plan_attacks`. Whether YAML attack profiles in `toys/` are auto-loaded depends on the current `AttackPlanner` implementation.

## Adding new attack profiles (YAML)

Attack profiles live in `toys/*.yaml`. Each file describes:

- metadata (`name`, `category`, `severity`, `description`)
- which input fields to target (`target_fields`)
- payloads to try (`payloads`)
- what “success” looks like (`success_indicators`)
- remediation guidance (`remediation`)

How `target_fields` are matched (query params vs JSON body fields vs headers) depends on the current `AttackPlanner` implementation. Typically they are matched by parameter name or JSON path; check `chaos_kitten/brain/attack_planner.py` for authoritative behavior.

Always open an existing profile in `toys/` and mirror its structure; the template below illustrates the concepts but may omit newer required fields. For a concrete example, start with `toys/sql_injection_basic.yaml`.

**Important:** Adding a YAML file under `toys/` by itself may not change scan behavior. Profiles are loaded/selected according to the current `AttackPlanner` implementation (and may require analyzer support in `ResponseAnalyzer`) before they affect scans.

A common end-to-end change looks like:

1. Add `toys/my_profile.yaml`.
2. Update `AttackPlanner` to load/select the profile (for example by category or endpoint metadata).
3. Update `ResponseAnalyzer` (or a dedicated analyzer) so it can recognize the vulnerability.
4. Add unit tests that cover planner selection and analyzer behavior.

**Common required fields (based on existing profiles):** `name`, `category`, `severity`, `payloads`, `success_indicators`, `remediation`.

**Common optional fields:** `description`, `target_fields`, `references`, `cat_message`, plus any future analyzer-specific metadata.

### Minimal profile template

Create a new file like `toys/header_injection.yaml`:

```yaml
name: "Header Injection"
category: "injection"
severity: "high"
description: "Tests for CRLF/header injection patterns"

target_fields:
  - "url"
  - "redirect"
  - "callback"

payloads:
  - "\\r\\nX-Test: injected"
  - "%0d%0aX-Test: injected"

success_indicators:
  status_codes:
    - 200
    - 302
  response_contains:
    - "X-Test"

remediation: |
  Reject CR/LF characters in untrusted inputs and ensure headers are
  constructed using safe framework APIs.
```

In this example, the payloads use a literal CRLF sequence (`"\\r\\n"`) and its URL-encoded form (`"%0d%0a"`) to attempt to inject a new HTTP header (`X-Test`).

### Conventions and best practices

1. Keep payloads safe by default.
   - Avoid destructive payloads (DELETE/DROP) unless explicitly gated by a “destructive mode”.
2. Prefer a clear `category` string over adding new ad-hoc keys.
   - Existing examples: `injection`, `authentication`, `request-forgery`, `file-access`.
3. Keep `success_indicators` conservative.
   - “Response contains X” is often enough to flag a likely finding, but avoid overly broad substrings that cause noise.
4. Include a `remediation` section.
   - This is often the most useful part of the report for end users.

### How profiles are used in code

Current behavior (see `chaos_kitten/brain/attack_planner.py`):

- `AttackPlanner.load_attack_profiles()` is currently a no-op (YAML profiles are not loaded automatically).
- `AttackPlanner.plan_attacks()` is currently a simple heuristic stub.

To make a new YAML profile affect scans, implement loading/selection in `AttackPlanner` and ensure analysis logic recognizes the vulnerability.

When you add a new YAML profile, you will usually also want to:

- update `AttackPlanner` to load and select it
- update `ResponseAnalyzer` to recognize the vulnerability (or implement a new analyzer)

After adding or changing a profile, add or update tests under `tests/` (for example, planner selection logic or response analysis) so the behavior stays verifiable over time.

### Validation and testing

There isn't a dedicated profile schema validator yet. For now:

1. Make sure the YAML parses:

   ```bash
   python -c 'import yaml; yaml.safe_load(open("toys/sql_injection_basic.yaml"))'
   ```

2. Add or update a unit test that loads your new YAML file and asserts required keys exist (`name`, `category`, `severity`, `payloads`, `success_indicators`, `remediation`).

## Adding payloads to `naughty_strings.json`

The shared payload library lives at `toys/data/naughty_strings.json`.

Current behavior: this file is not loaded automatically by the planner/analyzers yet. If you want new payloads or categories here to affect scans, wire it into `AttackPlanner` (and/or analyzers) and add tests.

File shape (simplified example; inspect `toys/data/naughty_strings.json` in your checkout for the current structure):

The snippet below is only a highly simplified sketch and is not a schema. The actual file may contain additional metadata, fields, or categories. Always open `toys/data/naughty_strings.json` in your checkout and mirror the real structure there.

```json
{
  "categories": {
    "sql_injection": ["..."],
    "xss": ["..."],
    "path_traversal": ["..."]
  }
}
```

To see real-world examples, open `toys/data/naughty_strings.json` and look at an existing category like `xss` or `sql_injection`, then mirror that structure when adding your own payloads.

When extending the dataset, treat the `categories` map as the primary payload structure; other top-level fields (like `name`/`description`/`version`) are informational metadata.

### Adding a new payload

1. Choose the right category under `categories`.
   - If you create a new category, keep the name short and snake-cased.
2. Add your payload as a JSON string.
   - Remember to escape backslashes (`\\`) and double quotes (`\"`).
3. Keep entries focused.
   - A payload should test one idea; prefer multiple small payloads over one mega-string.

Adding a new category here does not automatically make the planner or analyzers use it. If the new category should drive attack selection, update the relevant logic under `chaos_kitten/brain` and add tests under `tests/`.

Example patch (adding a CRLF payload):

This diff is a conceptual example; in your tree you may need to create the `header_injection` category or use a different existing category name to match the real file.

```diff
diff --git a/toys/data/naughty_strings.json b/toys/data/naughty_strings.json
@@
   "categories": {
@@
     "header_injection": [
+      "\\r\\nX-Test: injected"
     ]
   }
```

After editing, validate the JSON (this catches missing commas and escaping errors):

```bash
python -m json.tool toys/data/naughty_strings.json > /dev/null
```

If a new payload category changes planner selection or analyzer behavior, add/update tests under `tests/` to cover the new behavior.

## LLM debugging tips

LLM-driven planning is under active development. Today, the scan loop is primarily:

- spec parsing (OpenAPIParser)
- rule-based attack planning (AttackPlanner)
- HTTP execution (Executor)
- response heuristics (ResponseAnalyzer)

**Current behavior:** At the time of writing, the main scan loop is typically driven by built-in heuristics in `AttackPlanner.plan_attacks`. The `agent` settings in `chaos-kitten.yaml` are not yet fully wired into planning.

**Experimental work:** LLM-based planning is being wired in behind the `agent` config block. See [`docs/architecture.md`](./architecture.md) for up-to-date design notes.

That said, contributors frequently work on LLM integration in `AttackPlanner` and/or the LangGraph workflow.

LLM settings live under `agent` in `chaos-kitten.yaml` (see the template created by `chaos-kitten init`):

Always check the config template produced by `chaos-kitten init` for the authoritative set of LLM-related keys, as names and behavior may change.

```yaml
agent:
  llm_provider: "anthropic"  # e.g., anthropic, openai (check current docs/config)
  model: "your-llm-model-name"  # replace with a model supported by your provider
  temperature: 0
  max_iterations: 4
```

For implementation details, see how config is loaded in `chaos_kitten/utils/config.py` and how planning/orchestration is implemented under `chaos_kitten/brain`. When in doubt, `rg agent\.llm_provider` is usually the fastest way to find the current wiring.

Practical debugging tips:

1. Make runs deterministic while debugging.
   - Set your model temperature to `0` (in config) once LLM planning is wired in.
   - The config template created by `chaos-kitten init` includes `agent.llm_provider`, `agent.model`, `agent.temperature`, and `agent.max_iterations`.
2. Reduce the blast radius.
   - Run against the demo API (`examples/demo_api`) and keep to a small spec.
3. Log prompts and decisions.
   - For local experiments, add `logging.basicConfig(level=logging.DEBUG)` in your entrypoint and emit the exact prompt + parsed response.
4. Add “golden” prompt tests.
   - If you’re changing prompts, add unit tests that validate structured outputs (rather than snapshotting full free-form text).
5. Watch for rate limits and retries.
   - LLM provider errors can look like network timeouts; capture the exception type and any provider request IDs.

## Code style and testing expectations

### Style

Tooling is configured in `pyproject.toml`:

- Black (`[tool.black]`) for formatting
- Ruff (`[tool.ruff]`) for linting
- Mypy (`[tool.mypy]`) for type checking

For the authoritative contributor checklist (and any future pre-commit/CI-only steps), see [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`docs/contributing_guide.md`](./contributing_guide.md).

The commands below are a quick reference; if they ever diverge from the contribution docs, trust those docs and `pyproject.toml`.

Recommended local commands (scope to files you changed when possible):

```bash
black .
ruff check .
mypy chaos_kitten
```

Black and Ruff are the primary style/lint tools, and Mypy is the preferred type checker. Depending on the current CI configuration, some or all of them may also run in GitHub Actions, but running them locally is still the fastest way to catch issues before review.

Before opening a PR, run:

```bash
black .
ruff check .
mypy chaos_kitten
pytest
```

### Testing

Run the full test suite:

```bash
pytest
```

When you change behavior:

- add or update unit tests in `tests/`
- prefer small, focused tests
- use mocking for network calls (see `tests/test_brain.py`)
- keep integration tests hermetic (the demo API is used for this in `tests/test_integration_scan.py`)
- when you add or change attack profiles, payload categories, or planner/analyzer logic, add or update tests to cover the new behavior

## Common troubleshooting

Some items below reference current module paths and dependencies. If something doesn't match your checkout, use your IDE or `rg` to find the current code path and adjust the commands accordingly.

### `chaos-kitten scan` exits because no API key is set

- Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in your environment.
- If you're running in demo mode (`--demo`), the CLI will proceed without a key, but you may still see a warning.

### Config values like `${API_TOKEN}` are empty

The config loader only expands values from the process environment; it does not read a `.env` file.

- Ensure the environment variable is exported before you run `chaos-kitten scan`.

### OpenAPI parsing failures

`OpenAPIParser` uses `prance` with an OpenAPI validator backend.

Common causes:

- invalid OpenAPI/Swagger JSON/YAML
- missing external `$ref` files
- relative paths in `$ref` that don’t resolve from your current working directory

Example for the current tree (adjust the import path if necessary):

```bash
python -c 'from chaos_kitten.brain.openapi_parser import OpenAPIParser; p=OpenAPIParser("examples/sample_openapi.json"); p.parse(); print(len(p.get_endpoints()))'
```

Note: Internal module paths like `chaos_kitten.brain.openapi_parser` may change between versions. If this command fails with an `ImportError`, use your IDE or `rg OpenAPIParser` to find the current module and update the import path.

### Report generation errors

If you see template-related errors, confirm the templates exist (by default under):

- `chaos_kitten/litterbox/templates/report.html`
- `chaos_kitten/litterbox/templates/report.md`

### Connection errors to your API

- Confirm the base URL is reachable from your machine.
- If you're using the demo API, start it from `examples/demo_api`.

```bash
cd examples/demo_api
python -m pip install -r requirements.txt
python app.py
```

### New attack profile or payload not taking effect

- Verify your YAML/JSON parses (see the validation commands earlier in this guide).
- Check `AttackPlanner` selection logic and `ResponseAnalyzer` behavior to confirm your new category/profile is referenced.
- Add or run unit tests that explicitly load your new profile and assert it is selected for at least one endpoint.

### Playwright issues

If you installed `.[browser]`, ensure you also installed the browser binaries:

```bash
python -m playwright install
```

### Test failures / CI failures

- Re-run the failing test with more output: `pytest -vv`.
- If you changed CLI behavior, run the integration test: `pytest -vv tests/test_integration_scan.py`.
- If CI fails on formatting or linting, run the exact local commands in [Code style and testing expectations](#code-style-and-testing-expectations).
