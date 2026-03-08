# Chaos Kitten — Competitive Analysis & Strategic Roadmap

**Date:** February 19, 2026  
**Author:** @mdhaarishussain  
**Scope:** Full competitive landscape analysis; feature gap issues created; innovation roadmap defined

---

## 1. Executive Summary

Two significant competitors have been identified in the AI-powered API security testing space: **Shannon AI** (KeygraphHQ/shannon, 23.4k GitHub stars) and **Pentellia** (announced at India AI Impact Summit, February 19–20 2026, Bharat Mandapam, New Delhi — no public technical data available yet).

Shannon AI represents the most direct technical competitor. After a full feature audit, **13 gap issues** and **6 innovation issues** were created on this repository to close parity gaps and establish differentiated capabilities that no competitor currently offers.

**Strategic conclusion:** Chaos Kitten can outcompete Shannon AI by leaning into its Python-first, community-extensible, LLM-native architecture. Shannon is closed-form and OWASP-hardcoded. Chaos Kitten's extensible toy system, adaptive LLM payloads, and natural language targeting are advantages Shannon cannot replicate without a full rewrite.

---

## 2. Competitor Profiles

### 2.1 Shannon AI

| Property | Details |
|---|---|
| **Repository** | [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) |
| **Stars** | 23,400+ (as of Feb 19 2026) |
| **License** | AGPL-3.0 (Lite) / Commercial (Pro) |
| **Language** | TypeScript (87%), JavaScript (7%), Shell (4%) |
| **LLM Backend** | Anthropic Claude Agent SDK |
| **Architecture** | Multi-agent, 4-phase: Recon → Parallel Vuln Analysis → Parallel Exploitation → Report |
| **Pricing** | ~$50/engagement (Pro); free tier limited |
| **Benchmark** | 96.15% on XBOW hint-free benchmark |
| **Scan Duration** | 1–1.5 hours per engagement |

**Shannon's 4-Phase Architecture:**

```
Phase 1: Reconnaissance
  └─ Nmap port scan + Subfinder subdomain enum + WhatWeb fingerprinting

Phase 2: Parallel Vulnerability Analysis
  └─ Concurrent agents per category: Injection / XSS / SSRF / Auth

Phase 3: Parallel Exploitation
  └─ Attempt to prove each finding with a real working exploit
  └─ "No Exploit, No Report" policy

Phase 4: Reporting
  └─ Markdown report with PoC, CVSS, remediation
```

**Shannon's Confirmed Coverage:**
- SQL Injection
- XSS (reflected, stored)
- SSRF
- Broken Authentication / Authorization
- IDOR
- Mass Assignment
- JWT attacks

**Shannon's Key Unique Features:**
- White-box mode only (requires source code access)
- "No Exploit, No Report" — proves exploitability before reporting
- 2FA/TOTP authentication support
- Workspace checkpointing and resume
- CI/CD pipeline integration (Pro tier)
- Parallel agent execution (concurrent per vulnerability category)
- Schemathesis integration for schema-based fuzzing
- LLM data flow analysis — trace input to dangerous sinks (Pro only)

**Shannon's Hard Limitations:**
- TypeScript only — inaccessible to Python security community
- **Black-box testing not supported** — cannot test deployed APIs without source code
- No GraphQL support
- No extensible attack profiles — OWASP categories are hardcoded
- Expensive at scale ($50/engagement)
- No community contribution mechanism
- No concept of API versioning or regression testing
- Cannot be directed by natural language intent

---

### 2.2 Pentellia

Pentellia was announced at the **India AI Impact Summit 2026** (February 19–20, Bharat Mandapam, New Delhi). As of this writing, no technical documentation, GitHub repository, or product specifications have been publicly indexed.

**Status:** Monitor post-summit. Update this document once technical capabilities are disclosed.

---

## 3. Feature Gap Analysis

### 3.1 Shannon Has / Chaos Kitten Lacks — Closed by Issues

These gaps have been addressed with GitHub issues catalogued below. All follow the Apertre 3.0 format.

| Feature | Shannon | Chaos Kitten | Issue | Priority |
|---|---|---|---|---|
| SSRF detection profile | ✅ | ❌ | [#139](https://github.com/mdhaarishussain/chaos-kitten/issues/139) | Medium |
| JWT attacks (alg:none, confusion, kid injection) | ✅ | ❌ | [#140](https://github.com/mdhaarishussain/chaos-kitten/issues/140) | Medium |
| IDOR detection profile | ✅ | ❌ | [#141](https://github.com/mdhaarishussain/chaos-kitten/issues/141) | Easy |
| Mass assignment vulnerability profile | ✅ | ❌ | [#142](https://github.com/mdhaarishussain/chaos-kitten/issues/142) | Easy |
| Reconnaissance phase (recon module) | ✅ | ❌ | [#143](https://github.com/mdhaarishussain/chaos-kitten/issues/143) | Hard |
| Browser automation / real exploit validation | ✅ | ❌ | [#144](https://github.com/mdhaarishussain/chaos-kitten/issues/144) | Hard |
| 2FA/TOTP authentication support | ✅ | ❌ | [#145](https://github.com/mdhaarishussain/chaos-kitten/issues/145) | Medium |
| Scan checkpointing & resume | ✅ | ❌ | [#146](https://github.com/mdhaarishussain/chaos-kitten/issues/146) | Medium |
| Parallel vulnerability execution | ✅ | ❌ | [#147](https://github.com/mdhaarishussain/chaos-kitten/issues/147) | Hard |
| CI/CD integration (SARIF, JUnit, GitHub Actions) | ✅ (Pro) | ❌ | [#148](https://github.com/mdhaarishussain/chaos-kitten/issues/148) | Hard |

### 3.2 Chaos Kitten Has / Shannon Lacks — Preserve & Advertise

| Feature | Chaos Kitten | Shannon |
|---|---|---|
| Black-box API testing (no source code needed) | ✅ | ❌ |
| GraphQL-specific testing (#135/#136) | ✅ | ❌ |
| Extensible YAML attack profiles (Toy Box) | ✅ | ❌ |
| Python-based (accessible to security community) | ✅ | ❌ |
| Custom attack profiles without code changes | ✅ | ❌ |
| Interactive REPL for real-time exploration | ✅ | ❌ |
| Zero cost per engagement | ✅ | ❌ ($50/run) |
| Community contribution model | ✅ | ❌ |

---

## 4. Innovation Roadmap — Beyond Parity

These six innovations go beyond what Shannon offers and establish capabilities no current competitor provides. They were created as GitHub issues and should be treated as the highest strategic priority after parity gaps are closed.

### 4.1 LLM-Powered Adaptive Payload Mutation — Issue [#149](https://github.com/mdhaarishussain/chaos-kitten/issues/149) 🔥

**The idea:** After a probe request, the LLM analyzes the response (status, body, headers, field types) and dynamically generates new targeted payloads in real time — payloads that have never existed in any static wordlist.

**Why it wins:** Shannon uses Claude only for orchestration. Chaos Kitten can use the LLM as a payload generator that adapts to each unique API's behavior. No other tool does this.

```
probe GET /users/1 → { "role": "user", "id": 1 }
LLM: "The role field is interesting — test: role=admin, role=superuser, role=0, role=null"
Next requests → [tries all LLM-generated mutations]
```

### 4.2 Multi-Endpoint Attack Chain Orchestration — Issue [#150](https://github.com/mdhaarishussain/chaos-kitten/issues/150) 🔥

**The idea:** Build a graph of API endpoints from the OpenAPI spec. Use the LLM to reason about multi-hop attack chains — create user → extract ID → exploit ID in different endpoint.

**Why it wins:** Tests the most dangerous real-world vulnerability patterns (auth bypass chains, privilege escalation chains) that single-endpoint tools completely miss. No open-source tool does this automatically.

```
POST /auth/register → { id: 42, token: "abc" }
  ↓ chain: use id=42 to probe id=43
GET /users/43/data → 200 OK  ← IDOR confirmed
  ↓ chain: extract data to probe admin endpoint
POST /admin/impersonate → { userId: 43 } → 200 OK  ← privilege escalation
```

### 4.3 API Spec Diff Scanning — Issue [#151](https://github.com/mdhaarishussain/chaos-kitten/issues/151)

**The idea:** Feed two OpenAPI specs (v1 and v2). Chaos Kitten tests only what changed — new endpoints, modified parameters, removed authentication — skipping the 90% that's unchanged.

**Why it wins:** Shannon has no concept of versioning. This makes Chaos Kitten the only tool purpose-built for continuous security in CI/CD. Removed auth requirements are flagged as CRITICAL without even making a request.

### 4.4 Natural Language Attack Targeting — Issue [#152](https://github.com/mdhaarishussain/chaos-kitten/issues/152) 🔥

**The idea:** A `--goal` flag that accepts plain English. The LLM reads the endpoint list and translates your intent into a concrete attack plan.

**Why it wins:** No other pentest tool — Shannon, ZAP, Burp, or otherwise — accepts human intent as input. This uniquely bridges expert-level testing with newcomer accessibility.

```bash
chaos-kitten run --spec api.json \
  --goal "check if admin endpoints are accessible to regular users"

chaos-kitten run --spec api.json \
  --goal "find all payment endpoints and test if prices can be negative or manipulated"
```

### 4.5 Community Toy Marketplace — Issue [#153](https://github.com/mdhaarishussain/chaos-kitten/issues/153)

**The idea:** A GitHub-backed registry of community attack profiles. Install, search, and publish toy profiles like npm packages.

**Why it wins:** Shannon cannot be extended. Chaos Kitten's community-driven attack library grows permanently. Network effects create a moat that no closed-source competitor can replicate.

```bash
chaos-kitten toys search graphql
chaos-kitten toys install graphql-introspection-advanced
chaos-kitten toys publish ./toys/my_custom_attack.yaml
```

### 4.6 Chaos Mode (Property-Based Negative Fuzzing) — Issue [#154](https://github.com/mdhaarishussain/chaos-kitten/issues/154)

**The idea:** Beyond known attack signatures, randomly generate structurally invalid inputs — wrong types, null, boundary extremes, massive strings, Unicode edge cases — to find undocumented crashes and hidden behaviors.

**Why it wins:** Shannon only tests for known OWASP categories. Chaos Mode finds the unknown unknowns. The name "Chaos Kitten" is literally made for this feature.

```bash
chaos-kitten run --spec api.json --chaos --chaos-level 3
# [CHAOS] POST /users { "age": null } → 500 Internal Server Error
# [CHAOS] POST /users { "name": "A"×100000 } → 30s timeout (possible ReDoS)
```

---

## 5. Full Issue Inventory

### Gap-Closing Issues (Parity with Shannon)

| Issue | Title | Difficulty | Label |
|---|---|---|---|
| [#139](https://github.com/mdhaarishussain/chaos-kitten/issues/139) | SSRF Detection Attack Profile | Medium | toys |
| [#140](https://github.com/mdhaarishussain/chaos-kitten/issues/140) | JWT Attacks Profile | Medium | toys |
| [#141](https://github.com/mdhaarishussain/chaos-kitten/issues/141) | IDOR Attack Profile | Easy | toys |
| [#142](https://github.com/mdhaarishussain/chaos-kitten/issues/142) | Mass Assignment Profile | Easy | toys |
| [#143](https://github.com/mdhaarishussain/chaos-kitten/issues/143) | Reconnaissance Phase | Hard | — |
| [#144](https://github.com/mdhaarishussain/chaos-kitten/issues/144) | Browser Automation / Playwright | Hard | feature-paws |
| [#145](https://github.com/mdhaarishussain/chaos-kitten/issues/145) | 2FA/TOTP Authentication Support | Medium | feature-paws |
| [#146](https://github.com/mdhaarishussain/chaos-kitten/issues/146) | Scan Checkpointing & Resume | Medium | — |
| [#147](https://github.com/mdhaarishussain/chaos-kitten/issues/147) | Parallel Vulnerability Execution | Hard | — |
| [#148](https://github.com/mdhaarishussain/chaos-kitten/issues/148) | CI/CD Integration (SARIF/JUnit) | Hard | — |

### Innovation Issues (Beyond Shannon)

| Issue | Title | Difficulty | Impact |
|---|---|---|---|
| [#149](https://github.com/mdhaarishussain/chaos-kitten/issues/149) | LLM Adaptive Payload Mutation | Hard | 🔥 Flagship |
| [#150](https://github.com/mdhaarishussain/chaos-kitten/issues/150) | Multi-Endpoint Attack Chaining | Hard | 🔥 Flagship |
| [#151](https://github.com/mdhaarishussain/chaos-kitten/issues/151) | API Spec Diff Scanning | Hard | High |
| [#152](https://github.com/mdhaarishussain/chaos-kitten/issues/152) | Natural Language Attack Targeting | Hard | 🔥 Flagship |
| [#153](https://github.com/mdhaarishussain/chaos-kitten/issues/153) | Community Toy Marketplace | Hard | High |
| [#154](https://github.com/mdhaarishussain/chaos-kitten/issues/154) | Chaos Mode (Negative Fuzzing) | Hard | High |

---

## 6. Competitive Positioning Summary

```
                    COVERAGE
         Low ◄─────────────────────► High
          │                            │
 Static   │   ZAP / Burp Suite         │
 tools    │   (spray & pray)           │
          │                            │
 H        │              Shannon AI    │
 i        │         (OWASP-hardcoded,  │
 g        │          source-only,      │
 h        │          expensive)        │
          │                            │
 I        │        ★ CHAOS KITTEN ★    │
 n        │   (black-box, extensible,  │
 t        │    community-driven,       │
 e        │    LLM-native,             │
 l        │    adaptive,               │
 l        │    natural language)       │
 i        │                            │
 g        │                            │
 e        │                            │
 n        │                            │
 c        │                            │
 e        │                            │
          │                            │
         Low ◄─────────────────────► High
```

**Our moat in one sentence:** Shannon is an expensive, closed-form, white-box-only TypeScript tool. Chaos Kitten is a free, endlessly extensible, black-box Python tool that thinks in natural language and grows smarter with every community contribution.

---

## 7. Recommended Execution Order

### Sprint 1 — Foundation (Apertre 3.0 target)
Priority: Close easy/medium parity gaps that unblock contributors.

1. [#141](https://github.com/mdhaarishussain/chaos-kitten/issues/141) IDOR Profile (Easy)
2. [#142](https://github.com/mdhaarishussain/chaos-kitten/issues/142) Mass Assignment Profile (Easy)
3. [#139](https://github.com/mdhaarishussain/chaos-kitten/issues/139) SSRF Profile (Medium)
4. [#140](https://github.com/mdhaarishussain/chaos-kitten/issues/140) JWT Attacks Profile (Medium)
5. [#145](https://github.com/mdhaarishussain/chaos-kitten/issues/145) 2FA/TOTP Support (Medium)
6. [#146](https://github.com/mdhaarishussain/chaos-kitten/issues/146) Checkpointing (Medium)

### Sprint 2 — Strategic Depth
Priority: Flagship innovations that establish competitive moat.

7. [#149](https://github.com/mdhaarishussain/chaos-kitten/issues/149) LLM Adaptive Payload Mutation 🔥
8. [#152](https://github.com/mdhaarishussain/chaos-kitten/issues/152) Natural Language Targeting 🔥
9. [#154](https://github.com/mdhaarishussain/chaos-kitten/issues/154) Chaos Mode
10. [#148](https://github.com/mdhaarishussain/chaos-kitten/issues/148) CI/CD Integration

### Sprint 3 — Architecture (Hard, High Reward)

11. [#150](https://github.com/mdhaarishussain/chaos-kitten/issues/150) Attack Chain Orchestration 🔥
12. [#147](https://github.com/mdhaarishussain/chaos-kitten/issues/147) Parallel Execution
13. [#143](https://github.com/mdhaarishussain/chaos-kitten/issues/143) Reconnaissance Phase
14. [#144](https://github.com/mdhaarishussain/chaos-kitten/issues/144) Browser Automation

### Sprint 4 — Ecosystem

15. [#151](https://github.com/mdhaarishussain/chaos-kitten/issues/151) API Diff Scanning
16. [#153](https://github.com/mdhaarishussain/chaos-kitten/issues/153) Community Toy Marketplace

---

## 8. Notes on Pentellia

Pentellia was announced on February 19, 2026 at the India AI Impact Summit (Bharat Mandapam, New Delhi). As of the time of writing, no technical specifications, GitHub repository, or pricing have been publicly disclosed.

**Action:** Re-evaluate in 2–4 weeks once post-summit coverage is indexed. Update this document accordingly. Watch for:
- Target market positioning (enterprise vs. developer)
- Black-box vs. white-box approach
- Language/stack
- LLM backend
- Pricing model

If Pentellia targets the same developer-facing API security market, the advantages documented in Section 3.2 and Section 4 remain our primary defensive moat.
