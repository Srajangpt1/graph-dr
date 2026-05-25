#!/usr/bin/env python3
"""
Unified AI-Powered Graph D&R Pipeline
======================================
Run all adapters against synthetic test data.

Usage:
    python main.py              # Run all adapters
    python main.py saas         # Run only SaaS adapter
    python main.py macos        # Run only macOS adapter
    python main.py agent        # Run only multi-agent adapter
    python main.py appsec       # Run only AppSec adapter
"""

import sys
from core import run_adapter

from adapters.saas import parse_saas, SaaSHeuristics, saas_test_events, SAAS_RULES
from adapters.macos import parse_macos, MacOSHeuristics, macos_test_events, MACOS_RULES
from adapters.agent import parse_agent, AgentHeuristics, agent_test_events, AGENT_RULES
from adapters.appsec import parse_appsec, AppSecHeuristics, appsec_test_events, APPSEC_RULES


ADAPTERS = {
    "saas": (
        "SaaS: Insider threat via Tor",
        saas_test_events, parse_saas, SaaSHeuristics, SAAS_RULES,
    ),
    "macos": (
        "macOS: Infostealer (FreeVPN.app)",
        macos_test_events, parse_macos, MacOSHeuristics, MACOS_RULES,
    ),
    "agent": (
        "Multi-Agent: Prompt injection via MCP",
        agent_test_events, parse_agent, AgentHeuristics, AGENT_RULES,
    ),
    "appsec": (
        "AppSec: SQLi + secret shipped to prod",
        appsec_test_events, parse_appsec, AppSecHeuristics, APPSEC_RULES,
    ),
}


def main():
    selected = sys.argv[1:] if len(sys.argv) > 1 else list(ADAPTERS.keys())

    # Validate
    for s in selected:
        if s not in ADAPTERS:
            print(f"Unknown adapter: {s}")
            print(f"Available: {', '.join(ADAPTERS.keys())}")
            sys.exit(1)

    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  AI-POWERED GRAPH D&R PIPELINE                              ║")
    print(f"║  Adapters: {' · '.join(selected):50s}║")
    print("╚═══════════════════════════════════════════════════════════════╝")

    results = {}
    for key in selected:
        name, events_fn, parser, heuristics, rules = ADAPTERS[key]
        results[key] = run_adapter(name, events_fn(), parser, heuristics, rules)

    print(f"\n{'═' * 65}")
    print("SUMMARY")
    print(f"{'═' * 65}")
    for key in selected:
        r = results.get(key)
        if r:
            v = r['verdict'].upper()
            s = r['risk_score']
            marker = "🔴" if v == "MALICIOUS" else "🟡" if v == "SUSPICIOUS" else "🟢"
            label = ADAPTERS[key][0].split(":")[0]
            print(f"  {marker} {label:15s} → {v} ({s}/100)")
    print(f"{'═' * 65}")


if __name__ == "__main__":
    main()
