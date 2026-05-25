# Graph D&R: AI-Powered Graph-Based Detection & Response

A practical adapter-based architecture for turning logs, endpoint events, SDLC signals, and AI agent traces into explainable security graphs.

**Blog post:** [The Graph Isn't Enough](https://2amsecurity.substack.com)

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  SaaS Logs   │  │ macOS eslog  │  │  AppSec /    │  │ Agent/MCP    │
│  (JSONL)     │  │ (JSON)       │  │  CI/CD       │  │ Telemetry    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │
       ▼                 ▼                 ▼                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                        ADAPTER LAYER                             │
│      Entity model + Parser + Heuristics (per source)            │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                        SHARED ENGINE                             │
│      Graph Builder + Serializer + LLM Analyzer                  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ Verdict + MITRE│
                  │ + Explanation  │
                  │ + Actions      │
                  └────────────────┘
```

The graph builder doesn't know what a "user," "process," or "agent" is. Entity meaning lives in the adapter. Relationship structure lives in the shared engine. Adding a new log source means writing ~200 lines of adapter code.

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

Run a specific adapter:

```bash
python main.py agent        # Multi-agent/MCP only
python main.py saas macos   # SaaS + macOS
```

## Adapters

| Adapter | Entities | Scenario | Heuristics |
|---------|----------|----------|------------|
| **SaaS** | User, Session, IP, APICall, Resource | Insider threat via Tor | Tor+sensitive access, bulk data access, priv escalation chain |
| **macOS** | Process, File, Network | Infostealer (FreeVPN.app) | osascript chains, LaunchAgent persistence, credential access, exfil pattern |
| **Multi-Agent** | Agent, ToolCall, MCPServer, Resource, Prompt | Prompt injection via MCP | Injection→sensitive, cross-agent escalation, multi-server lateral, exfil via tool |
| **AppSec** | Repo, Commit, PR, Pipeline, Finding, Dependency, Deploy | SQLi + secret shipped to prod | Critical finding in prod, pipeline bypass, secret in commit, vuln dependency, unreviewed PR |

## Project Structure

```
graph-dr/
├── core.py                 # Shared engine (graph builder, serializer, analyzer)
├── main.py                 # CLI runner
├── requirements.txt
├── adapters/
│   ├── saas.py             # SaaS application logs adapter
│   ├── macos.py            # macOS Endpoint Security adapter
│   ├── agent.py            # Multi-agent / MCP adapter
│   └── appsec.py           # AppSec / CI/CD adapter
└── README.md
```

## Writing a New Adapter

Each adapter provides three things:

1. **Entity model**: dataclasses with a `node_id` field
2. **Parser**: `parse_xxx(event) -> (nodes, rels)` 
3. **Heuristics**: class with methods that return suspicious subgraphs

```python
from dataclasses import dataclass
from typing import Optional
from core import Rel, SecurityGraph, _h

@dataclass
class MyEntity:
    node_id: str
    name: str
    # ... your fields

def parse_my_source(event: dict) -> tuple[list, list]:
    nodes, rels = [], []
    # extract entities and relationships
    return nodes, rels

class MyHeuristics:
    def __init__(self, g: SecurityGraph):
        self.g = g
        self.G = g.G

    def suspicious_pattern(self):
        results = []
        # graph traversal to find suspicious neighborhoods
        return results
```

## How It Works

The core insight: **the graph is the compression layer, not the detection layer.**

For traditional telemetry (endpoints, SaaS), graph structure carries the signal. `WINWORD.EXE → cmd.exe → powershell.exe → C2` is suspicious regardless of context.

For AI agent telemetry, graph structure is necessary but not sufficient. The graph captures *what* happened. But the security questions are about *why*: was the instruction injected? Did the delegation cross a permission boundary? Is the action consistent with the stated intent? Those require semantic reasoning on top of the graph.

The pipeline:
1. **Parse** log events into entities and relationships
2. **Build** a graph with identity resolution and property merging
3. **Extract** suspicious subgraphs via structural heuristics
4. **Analyze** with an LLM (or rule-based fallback) for semantic verdict

## License

MIT
