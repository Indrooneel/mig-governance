# mig-governance

**The AI agent firewall. Graph-based content-level governance for any automation.**

AGT checks if your agent can use a tool.  
MIG checks what your agent **sends through** that tool.

```bash
pip install mig-governance
```

---

## Why MIG?

Your agent has permission to send emails. Great.  
But it just attached the entire customer database.  
AGT said **ALLOW**. MIG says **DENY**.

Your automation can trigger payments. Great.  
But it just wired $50,000 to an unverified vendor.  
Your workflow said **proceed**. MIG says **APPROVAL REQUIRED**.

**No LLM in the decision loop. Deterministic. Graph-based. Fail-closed.**

---

## Quick Start

### Three lines to govern any action:

```python
from mig_governance import Governor

gov = Governor()
result = gov.validate("Send salary data to external@gmail.com")

print(result.decision)     # DENY
print(result.risk_score)   # 90
print(result.policy_id)    # DEFAULT-DENY-001
```

### Decorator — wrap any function:

```python
from mig_governance import Governor, ActionDenied

gov = Governor()

@gov.guard
def send_email(to, subject, body):
    email_api.send(to, subject, body)

# Safe — executes normally
send_email("team@company.com", "Meeting", "See you at 3pm")

# Dangerous — blocked before execution
try:
    send_email("external@gmail.com", "Data", "SSN: 123-45-6789")
except ActionDenied as e:
    print(e)  # MIG DENIED: PII + external destination
```

### Server mode — for any automation platform:

```bash
pip install mig-governance[server]
mig-governance serve
```

MIG is now running at `http://localhost:8000/validate`

Add this URL as an HTTP step in **Zapier**, **Make.com**, **Relevance AI**, **n8n**, or **Power Automate**. Your automation is governed.

```bash
# Test it
curl -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -d '{"text": "Read current sales report"}'
# → {"decision": "ALLOW", "risk_score": 10, ...}

curl -X POST http://localhost:8000/validate \
  -H "Content-Type: application/json" \
  -d '{"text": "Send salary data to external@gmail.com"}'
# → {"decision": "DENY", "risk_score": 90, ...}
```

---

## Three modes, one package

| Mode | For | How |
|------|-----|-----|
| **Library** | Python developers | `from mig_governance import Governor` |
| **Decorator** | Framework developers | `@gov.guard` on any function |
| **Server** | Automation platforms | `mig-governance serve` → HTTP API |

Exposing MIG to the Cloud (ngrok)

MIG runs on your local machine. Cloud automation platforms (Zapier, Make, n8n, Relevance AI) cannot reach `localhost`. To connect them, you need a tunnel. [ngrok](https://ngrok.com) is the simplest solution (free tier works).

**Step 1 – Install ngrok**  
Download from [ngrok.com/download](https://ngrok.com/download), unzip, and authenticate:
```bash
ngrok config add-authtoken YOUR_AUTH_TOKEN   # get your token from the ngrok dashboard after sign‑up
```

Step 2 – Start MIG server
In one terminal:

```bash
mig-governance serve
```

Step 3 – Expose the server
In another terminal:

```bash
ngrok http 8000
```

You'll see a public URL like https://abc123.ngrok.io. That URL securely forwards to your local MIG server.

Step 4 – Use the public URL in automation tools
In Zapier, Make, n8n, etc., create an HTTP request:

· Method: POST
· URL: https://your-ngrok-url/validate
· Headers: Content-Type: application/json
· Body: {"text": "The action to validate"}

The response contains decision (ALLOW/DENY/APPROVAL), risk_score, and full audit details.

Note: The free ngrok URL changes each time you restart. For production workloads, consider a static tunnel or deploy MIG on a cloud VM.

---

## What MIG catches that others don't

| Check | Microsoft AGT | MIG |
|-------|--------------|-----|
| Tool permissions | ✅ | — |
| **Content/payload inspection** | ❌ | ✅ |
| **PII detection in actions** | ❌ | ✅ |
| **Risk scoring (0-100)** | ❌ | ✅ |
| **Operator approval workflow** | ❌ | ✅ |
| **Graph-based policy matching** | ❌ | ✅ |
| Full audit trail | ✅ | ✅ |
| Deterministic decisions | ✅ | ✅ |

MIG doesn't replace AGT. MIG is the **layer on top** — content inspection that permission checking can't provide.

---

## Architecture

```
Action comes in
    ↓
┌─────────────────────────────────┐
│  8-Step Validation Pipeline     │
│                                 │
│  1. PII Detection               │
│  2. Action Classification       │
│  3. Payload Analysis            │
│  4. Semantic Matching (ChromaDB)│
│  5. Graph Policy Match (NetworkX│
│  6. Risk Scoring                │
│  7. Override Evaluation         │
│  8. Audit Logging               │
└─────────────────────────────────┘
    ↓
┌────────┬────────┬──────────┐
│ ALLOW  │  DENY  │ APPROVAL │
│ Safe   │ Blocked│ Needs    │
│ proceed│ stopped│ human OK │
└────────┴────────┴──────────┘
```

**Powered by:**
- **NetworkX** — graph-based policy matching (not flat rules)
- **ChromaDB** — semantic similarity (not just keywords)
- **SQLite** — full audit trail (every decision logged)

---

## Works with any automation platform

**Zapier** → Add "Webhooks by Zapier" step → POST to `http://localhost:8000/validate`

**Make.com** → Add "HTTP Request" module → POST to `http://localhost:8000/validate`

**Relevance AI** → Add custom tool → HTTP POST to `http://localhost:8000/validate`

**n8n** → Add "HTTP Request" node → POST to `http://localhost:8000/validate`

**Power Automate** → Add "HTTP" action → POST to `http://localhost:8000/validate`

**LangGraph** → Use decorator:
```python
from mig_governance.integrations.langgraph import mig_tool

@mig_tool(gov)
def my_tool(param):
    ...
```

---

## Custom policies

Create your own policy pack:

```json
{
    "name": "My Company Policies",
    "policies": [
        {
            "id": "MYCO-DENY-001",
            "description": "Block sending financial data externally",
            "action_type": "share_document",
            "direction": "DENY",
            "keywords": ["financial", "revenue", "salary", "budget"],
            "conditions": {"destination": "external"}
        },
        {
            "id": "MYCO-ALLOW-001",
            "description": "Allow reading any internal reports",
            "action_type": "read_data",
            "direction": "ALLOW",
            "keywords": ["read", "view", "report", "summary"]
        }
    ]
}
```

```python
gov = Governor(policies="./my_policies.json")
```

---

## Free vs Pro

| Feature | Free (local) | Pro (hosted) |
|---------|-------------|--------------|
| Graph engine | NetworkX | Neo4j |
| Embeddings | ChromaDB | sentence-transformers |
| PII detection | ✅ | ✅ |
| Payload analysis | ✅ | ✅ |
| Risk scoring | ✅ | ✅ |
| Audit trail | SQLite | Cloud DB |
| Drift detection | — | ✅ |
| Equipment profiles | — | ✅ |
| Semantic matching | Basic | Full Cypher |
| Dashboard | — | ✅ Web UI |
| Price | Free | Contact us |


## Known Limitations

MIG is early and we'd rather you know exactly what it does and doesn't do.

- **In-memory graph (free tier):** policies load from JSON on startup. 
  Restart the process, the graph rebuilds. Persistent graph state 
  requires the Pro engine (Neo4j).
- **Semantic matching is basic:** ChromaDB local embeddings catch 
  rephrasing, but adversarial prompt obfuscation is not fully covered. 
  Pair MIG with input validation; don't treat it as your only layer.
- **English-only keywords:** policy keyword matching assumes English 
  payloads. Multilingual support is on the roadmap.
- **Not yet independently audited:** the pipeline is tested 
  (see test results), but no third-party security audit has been 
  performed. Don't deploy as the sole control in safety-critical 
  systems yet.
- **localhost server has no auth:** `mig-governance serve` is meant 
  for local/tunneled use. Put it behind auth before exposing publicly.
  Don't deploy as the sole control in safety-critical systems yet.
  MIG is designed as one layer in a defense-in-depth strategy.

Found something else? Open an issue — honest bug reports make this better.


```python
# Free — runs locally
gov = Governor(policies="./policies.json")

# Pro — connects to hosted MIG engine
gov = Governor(api_key="gal_live_xxxxx")
```

---

## Framework alignment

MIG architecture aligns with:

- **NIST 800-207** — Policy Decision Point + Policy Enforcement Point
- **OWASP Agentic Top 10 (2026)** — mitigates ASI01, ASI02, ASI03, ASI06
- **Anthropic Zero Trust for AI Agents** — least agency, architecturally enforced
- **IEC 62443** — zone-conduit enforcement for OT/ICS
- **CISA Agentic AI Guidance** — deterministic governance at execution boundary

---

## Installation

```bash
# Core SDK
pip install mig-governance

# With server mode
pip install mig-governance[server]

# With LangGraph integration
pip install mig-governance[langgraph]

# Everything
pip install mig-governance[all]
```

---

## API Reference

### `Governor(policies=None, api_key=None)`

Main governance class.

- `gov.validate(action, context=None)` → `Decision`
- `gov.guard` → decorator for any function
- `gov.get_audit(limit=50)` → list of recent decisions
- `gov.get_policies()` → list of loaded policies
- `gov.get_stats()` → governance statistics

### `Decision`

- `.decision` → "ALLOW", "DENY", or "APPROVAL"
- `.risk_score` → 0-100
- `.policy_id` → matched policy ID
- `.checks` → list of pipeline check results
- `.flags` → list of triggered flags
- `.is_allowed` / `.is_denied` / `.needs_approval` → bool

### Server endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/validate` | Validate an action |
| GET | `/health` | System status |
| GET | `/policies` | List policies |
| GET | `/audit` | Decision history |
| GET | `/stats` | Governance statistics |
| GET | `/graph` | Policy graph structure |
| GET | `/docs` | Interactive API docs |

---

## Built by

**House of Galatine** — Execution control for critical infrastructure and AI agents.

Built by a mechanical engineer who understands what happens when ungoverned commands reach controllers.

- Website: [houseofgalatine.com](https://houseofgalatine.com)
- Playground: [houseofgalatine.com/playground](https://houseofgalatine.com/playground)
- Email: neel@houseofgalatine.com
- Patent: USPTO Provisional #63/821,489

---

## License

Business Source License 1.1 (BSL)

Free to use for any purpose. Cannot be offered as a competing commercial governance-as-a-service product.

Converts to Apache 2.0 on June 1, 2029.

For commercial licensing: neel@houseofgalatine.com
