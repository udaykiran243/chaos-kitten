# Getting Started with Chaos Kitten 🐱

Welcome to Chaos Kitten! This guide will help you get up and running quickly.

## Prerequisites

- Python 3.10 or higher
- An API to test (preferably a local development server)
- An LLM API key (Anthropic or OpenAI)

## Installation

### Option 1: pip (Recommended)

```bash
pip install chaos-kitten
```

### Option 2: From Source

```bash
git clone https://github.com/mdhaarishussain/chaos-kitten.git
cd chaos-kitten
pip install -e .        # Standard install (no browser)
# Optional: browser exploit validation
pip install -e .[browser]
playwright install chromium
```

### Option 3: Docker (Recommended for Isolation)

To run Chaos Kitten in a containerized environment (ensuring all dependencies, including browsers for XSS testing, are isolated):

**Using Docker Compose (Easiest)**

This spins up both the scanner and a vulnerable demo API:

```bash
# Set your API key environment variable first
export ANTHROPIC_API_KEY=your_key_here
# OR
export OPENAI_API_KEY=your_key_here

# Start the demo environment
docker-compose up -d demo-api

# Run a scan against the demo API
docker-compose run chaos-kitten scan --demo
```

**Using Standalone Docker**

Build the image:
```bash
docker build -t chaos-kitten .
```

Run a scan (mounting your current directory for config and reports):
```bash
docker run --rm \
  -v $(pwd)/chaos-kitten.yaml:/app/chaos-kitten.yaml \
  -v $(pwd)/reports:/app/reports \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  chaos-kitten scan
```

## Quick Start

### 1. Initialize Configuration

```bash
chaos-kitten init
```

This creates a `chaos-kitten.yaml` configuration file.

### 2. Edit Configuration

Open `chaos-kitten.yaml` and update:

```yaml
target:
  base_url: "http://localhost:3000"  # Your API URL
  openapi_spec: "./openapi.json"      # Path to OpenAPI spec

agent:
  llm_provider: "anthropic"
  model: "claude-3-5-sonnet-20241022"
```

### 3. Set API Key

Create a `.env` file:

```bash
ANTHROPIC_API_KEY=your_key_here
```

### 4. Run a Scan

```bash
chaos-kitten scan
```

## 5. API Spec Diff Scanning (CI/CD Integration)

**Test only what changed between API versions** — perfect for continuous security in CI/CD pipelines.

### What is Diff Mode?

Instead of rescanning your entire API on every deployment, diff mode:
- Compares two OpenAPI specs (old version vs new version)
- Identifies what changed (added endpoints, modified parameters, removed auth)
- **Flags removed authentication as CRITICAL** immediately without testing
- Tests only the delta endpoints, skipping unchanged ones

### Usage

```bash
chaos-kitten diff \
  --old api_v1.json \
  --new api_v2.json \
  --base-url https://api.example.com
```

### Example Output

```
📊 Computing API diff...

╭─ API Spec Diff ─────────────────────────────────╮
│ Diff Summary:                                   │
│                                                 │
│ 📊 Total endpoints in old spec: 50              │
│ 📊 Total endpoints in new spec: 52              │
│                                                 │
│ ➕ Added endpoints:  3                          │
│ ➖ Removed endpoints: 1                         │
│ 🔄 Modified endpoints: 4                        │
│ ✓ Unchanged endpoints: 47                       │
╰─────────────────────────────────────────────────╯

🚨 1 CRITICAL security regression(s) detected!
  • DELETE /api/admin/users: Authentication requirement removed — potential security regression
    - 🚨 CRITICAL: Authentication requirement removed

✓ Delta mode: Testing 7 changed endpoints, skipping 47 unchanged
🎯 Starting security scan on changed endpoints...
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--old` | Path to old OpenAPI spec (required) | - |
| `--new` | Path to new OpenAPI spec (required) | - |
| `--base-url` | Base URL for the API | - |
| `--full` | Override delta mode and test all endpoints | `false` |
| `--fail-on-critical` | Exit with code 1 if critical issues found | `false` |
| `--output` | Directory to save report | `./reports` |
| `--format` | Report format (html, markdown, json, sarif) | `html` |

### CI/CD Integration Example

**GitHub Actions:**

```yaml
- name: API Security Regression Test
  run: |
    chaos-kitten diff \
      --old ./specs/production_v1.json \
      --new ./specs/staging_v2.json \
      --base-url https://staging-api.example.com \
      --fail-on-critical \
      --format sarif \
      --output ./security-reports
      
- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: ./security-reports/chaos-kitten.sarif
```

### When to Use Diff Mode

✅ **Use diff mode when:**
- Deploying a new API version in CI/CD
- You want fast feedback (only test what changed)
- Detecting security regressions is critical

❌ **Use full scan when:**
- First time scanning an API
- Major refactoring or architecture changes
- You want comprehensive coverage

## Understanding Results

### Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| CRITICAL | 🔴 | Immediate action required |
| HIGH | 🟠 | Should be fixed soon |
| MEDIUM | 🟡 | Should be addressed |
| LOW | 🟢 | Minor issues |

### Sample Output

```
🐱 Chaos Kitten v1.0.0
📋 Parsing OpenAPI spec...
🎯 Found 12 endpoints

🐾 Testing /api/login
   ⚠️  I knocked this vase over! (SQL Injection)
   Severity: CRITICAL
```

## Next Steps

- [Architecture Overview](./architecture.md)
- [Configuration Reference](./configuration.md)
- [Contributing Guide](../CONTRIBUTING.md)

## Need Help?

- Open an [Issue](https://github.com/mdhaarishussain/chaos-kitten/issues)
- Join our [Discussions](https://github.com/mdhaarishussain/chaos-kitten/discussions)
