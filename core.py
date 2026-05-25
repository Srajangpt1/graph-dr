"""
Graph D&R Core Engine
=====================
Shared infrastructure for all adapters:
  - SecurityGraph: log-source-agnostic graph builder
  - serialize(): subgraph → structured text for LLM analysis
  - analyze(): rule-based analysis (LLM fallback for testability)
  - Rel: relationship dataclass
  - _h(): identity hash helper
"""

import json
import hashlib
import networkx as nx
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rel:
    """A relationship between two entities."""
    source_id: str
    target_id: str
    rel_type: str
    timestamp: Optional[str] = None


def _h(s: str) -> str:
    """Hash a string into a 16-char hex identity key."""
    return hashlib.sha256(s.encode()).hexdigest()[:16]


class SecurityGraph:
    """
    Log-source-agnostic graph builder.

    Nodes accumulate properties over time.
    Edges are typed and timestamped.
    Identity resolution happens at the adapter level;
    the graph builder just merges by node_id.

    The graph builder does not know what a "user," "process,"
    or "agent" is. It reads node.__dict__ and stores everything
    as attributes. Entity meaning lives in the adapter.
    """

    def __init__(self):
        self.G = nx.MultiDiGraph()
        self._registry = {}

    def ingest(self, nodes: list, rels: list):
        for node in nodes:
            nid = node.node_id
            ntype = type(node).__name__
            attrs = {k: v for k, v in node.__dict__.items()
                     if v is not None and v != '' and v != [] and v is not False}
            attrs['node_type'] = ntype

            if nid in self._registry:
                existing = self.G.nodes[nid]
                for k, v in attrs.items():
                    if k not in existing or not existing[k]:
                        existing[k] = v
                # Always upgrade node_type from Unknown to real type
                if existing.get('node_type') == 'Unknown' and ntype != 'Unknown':
                    existing['node_type'] = ntype
                    self._registry[nid] = ntype
            else:
                self.G.add_node(nid, **attrs)
                self._registry[nid] = ntype

        for r in rels:
            for nid in [r.source_id, r.target_id]:
                if nid not in self._registry:
                    self.G.add_node(nid, node_type='Unknown', node_id=nid)
                    self._registry[nid] = 'Unknown'
            self.G.add_edge(r.source_id, r.target_id,
                           rel_type=r.rel_type, timestamp=r.timestamp)

    def neighborhood(self, node_id: str, depth: int = 3) -> nx.MultiDiGraph:
        """Extract local neighborhood around a node."""
        nodes = set()
        frontier = {node_id}
        for _ in range(depth):
            nxt = set()
            for n in frontier:
                nodes.add(n)
                nxt.update(self.G.successors(n))
                nxt.update(self.G.predecessors(n))
            frontier = nxt - nodes
        nodes.update(frontier)
        return self.G.subgraph(nodes).copy()

    def stats(self) -> dict:
        tc, ec = {}, {}
        for _, a in self.G.nodes(data=True):
            t = a.get('node_type', '?')
            tc[t] = tc.get(t, 0) + 1
        for _, _, d in self.G.edges(data=True):
            t = d.get('rel_type', '?')
            ec[t] = ec.get(t, 0) + 1
        return {'nodes': self.G.number_of_nodes(),
                'edges': self.G.number_of_edges(),
                'node_types': tc, 'edge_types': ec}


def serialize(subgraph: nx.MultiDiGraph) -> str:
    """Convert a subgraph to structured text for LLM analysis."""
    out = ["=== ENTITIES ==="]
    by_type = {}
    for n, a in subgraph.nodes(data=True):
        by_type.setdefault(a.get('node_type', '?'), []).append((n, a))
    for t, nodes in by_type.items():
        out.append(f"\n[{t}]")
        for nid, a in nodes:
            props = {k: v for k, v in a.items()
                     if k not in ('node_id', 'node_type') and v}
            out.append(f"  {nid}: {json.dumps(props, default=str)}")

    out.append("\n=== RELATIONSHIPS ===")
    edges = sorted(subgraph.edges(data=True),
                   key=lambda e: e[2].get('timestamp', ''))
    for s, d, data in edges:
        sa, da = subgraph.nodes[s], subgraph.nodes[d]
        def lbl(a):
            for k in ['email', 'agent_name', 'tool_name', 'server_name',
                       'image', 'resource_name', 'path', 'dst_ip',
                       'content_summary', 'session_id', 'endpoint', 'ip_address']:
                v = a.get(k)
                if v: return str(v).split('/')[-1][:45]
            return a.get('node_type', '?')
        out.append(f"  [{data.get('timestamp','')}] "
                   f"{lbl(sa)} --{data.get('rel_type','')}--> {lbl(da)}")
    return '\n'.join(out)


def analyze(serialized: str, reason: str, rules: list[tuple]) -> dict:
    """
    Analyze a serialized subgraph.

    In production: sends to Claude API with a structured prompt.
    Here: uses rule-based matching for testability.

    `rules` is a list of (keyword, technique, score, explanation, action) tuples.
    """
    s = serialized.lower()
    techniques, risk, explanations, actions = [], 0, [], []

    for keyword, technique, score, explanation, action in rules:
        if keyword in s:
            techniques.append(technique)
            risk += score
            explanations.append(explanation)
            if action:
                actions.append(action)

    verdict = "malicious" if risk >= 60 else "suspicious" if risk >= 30 else "benign"
    return {
        "verdict": verdict,
        "risk_score": min(risk, 100),
        "mitre_techniques": techniques,
        "explanation": ". ".join(explanations) + "." if explanations else "No indicators.",
        "recommended_actions": actions,
        "confidence": round(min(risk / 110, 0.95), 2),
    }


def run_adapter(name, events, parser, heuristic_class, rules):
    """Run a complete adapter pipeline and print results."""
    sep = "=" * 65
    print(f"\n{sep}")
    print(f"  {name}")
    print(sep)

    graph = SecurityGraph()
    for ev in events:
        nodes, rels = parser(ev)
        graph.ingest(nodes, rels)

    s = graph.stats()
    print(f"\n  Graph: {s['nodes']} nodes, {s['edges']} edges")
    for t, c in sorted(s['node_types'].items()):
        print(f"    {t:18s}: {c}")
    for t, c in sorted(s['edge_types'].items()):
        print(f"    {t:22s}: {c}")

    h = heuristic_class(graph)
    all_findings = []
    for method_name in [m for m in dir(h) if not m.startswith('_')]:
        method = getattr(h, method_name)
        if callable(method):
            try:
                results = method()
                if results:
                    print(f"  ✓ {method_name}: {len(results)} finding(s)")
                    all_findings.extend(results)
                else:
                    print(f"  · {method_name}: 0")
            except TypeError:
                pass

    print(f"\n  Total suspicious subgraphs: {len(all_findings)}")

    if not all_findings:
        print("  No findings.")
        return

    all_findings.sort(key=lambda f: f.number_of_nodes(), reverse=True)
    best = all_findings[0]
    serialized = serialize(best)

    print(f"\n  Largest subgraph: {best.number_of_nodes()} nodes, {best.number_of_edges()} edges")
    for line in serialized.split('\n'):
        print(f"    {line}")

    verdict = analyze(serialized, name, rules)

    print(f"\n  {'─' * 45}")
    print(f"  VERDICT: {verdict['verdict'].upper()} ({verdict['risk_score']}/100)")
    print(f"  MITRE:   {', '.join(verdict['mitre_techniques'])}")
    print(f"  EXPLAIN: {verdict['explanation']}")
    for a in verdict['recommended_actions']:
        print(f"  ACTION:  → {a}")

    return verdict
