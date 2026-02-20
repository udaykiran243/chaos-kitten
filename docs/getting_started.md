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
pip install -e .
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

### 5. Chaos Mode (Negative Testing)

Chaos Mode goes beyond known attack signatures by generating structurally invalid inputs to discover unknown crashes, 500 errors, and hidden behaviors.

```bash
# Enable chaos mode alongside normal scanning
chaos-kitten scan --chaos --target http://localhost:5000

# Adjust chaos intensity (1 = gentle, 5 = maximum carnage)
chaos-kitten scan --chaos --chaos-level 5 --target http://localhost:5000
```

Chaos Mode tests for:
- **Wrong types:** Sending strings where integers are expected, arrays instead of objects, etc.
- **Boundary extremes:** Int32 min/max, float overflow (1e308), very long strings (100K chars)
- **Null and missing:** Null bytes, null values, missing required fields
- **Unicode edge cases:** Zero-width chars, direction overrides, emoji floods, unpaired surrogates
- **Header mutations:** Missing Content-Type, XML Content-Type (for XXE), mismatched Content-Length

Example findings unique to Chaos Mode:
```
[CHAOS] server_error on POST /api/users — Null value
[CHAOS] response_time_outlier on POST /api/products — Very long string (100K)
[CHAOS] information_leak on POST /api/orders — Float overflow boundary
```

Chaos levels:
| Level | Mode | Description |
|-------|------|-------------|
| 1 | Gentle | Basic type mismatches |
| 2 | Moderate | Boundary values + nulls |
| 3 | Aggressive | Unicode + control chars + large inputs |
| 4 | Destructive | Overflow + injection + nested attacks |
| 5 | Maximum Carnage | Everything at once |

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
