"""
LangGraph Orchestration — Builds the AutonomSOC multi-agent pipeline.

BUG FIXED: The original initial_state was missing the `case_id` field
that is now required in SOCState. Added it with uuid generation.

Pipeline flow:
    IdentityMonitor
        ↓ (if should_escalate=True)
    BehaviorAnalyzer → ThreatIntelRAG → CorrelationAgent → ResponseAgent → ReportingAgent
        ↓ (if should_escalate=False)
    END  (short-circuit — saves LLM compute on normal events)
"""

import json
import uuid
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from langgraph.graph import StateGraph, END
from agents.state import SOCState
from agents import (
    identity_monitor_agent,
    behavior_analyzer_agent,
    threat_intel_agent,
    correlation_agent,
    response_agent,
    reporting_agent,
)


def should_continue(state: SOCState) -> str:
    """
    Conditional router after IdentityMonitor.
    Normal events (should_escalate=False) skip all remaining 5 agents.
    This saves ~80% of LLM compute on typical SOC traffic.
    """
    return "continue" if state.get("should_escalate") else "end"


def build_pipeline():
    """
    Compiles the LangGraph multi-agent pipeline.

    Returns a compiled graph ready for .invoke(initial_state).
    """
    graph = StateGraph(SOCState)

    # Register all 6 agent nodes
    graph.add_node("identity_monitor",  identity_monitor_agent)
    graph.add_node("behavior_analyzer", behavior_analyzer_agent)
    graph.add_node("threat_intel",      threat_intel_agent)
    graph.add_node("correlation",       correlation_agent)
    graph.add_node("response",          response_agent)
    graph.add_node("reporting",         reporting_agent)

    # Entry point
    graph.set_entry_point("identity_monitor")

    # Conditional edge: escalate or short-circuit
    graph.add_conditional_edges(
        "identity_monitor",
        should_continue,
        {"continue": "behavior_analyzer", "end": END},
    )

    # Sequential edges for the rest
    graph.add_edge("behavior_analyzer", "threat_intel")
    graph.add_edge("threat_intel",      "correlation")
    graph.add_edge("correlation",       "response")
    graph.add_edge("response",          "reporting")
    graph.add_edge("reporting",         END)

    return graph.compile()


def run_pipeline(log_file: str = None, single_event: dict = None):
    """CLI runner — processes log file or single event dict."""
    pipeline = build_pipeline()

    if log_file:
        with open(log_file) as f:
            all_events = json.load(f)
    elif single_event:
        all_events = [single_event]
    else:
        print("Provide --log-file or --single-event"); return

    print(f"\n🚀 AutonomSOC Pipeline")
    print(f"   Events total  : {len(all_events)}")
    print(f"   Anomalies     : {sum(1 for e in all_events if e.get('is_anomaly'))}\n")

    anomalous = [e for e in all_events if e.get("is_anomaly") or e.get("risk_score", 0) > 40][:5]
    results = []

    for i, event in enumerate(anomalous):
        case_id = f"DEMO-SOC-{str(uuid.uuid4())[:8].upper()}"
        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(anomalous)}] {event.get('event_id','?')[:12]} — case: {case_id}")

        initial_state: SOCState = {
            "raw_events":       all_events,
            "current_event":    event,
            "identity_alert":   None,
            "behavior_score":   None,
            "threat_intel":     None,
            "correlation":      None,
            "response_actions": None,
            "final_report":     None,
            "risk_level":       "LOW",
            "should_escalate":  False,
            "case_id":          case_id,
            "pipeline_log":     [],
        }

        result = pipeline.invoke(initial_state)

        if result.get("should_escalate"):
            score = result["identity_alert"]["adjusted_risk_score"]
            print(f"🚨 {result['risk_level']} | {score:.1f}/100")
            for line in result["pipeline_log"]:
                print(f"   {line}")
            print(f"\n--- REPORT ---\n{result['final_report'][:600]}...\n")
        else:
            print("✅ CLEARED — no escalation")

        results.append(result)

    # Save results
    out = [
        {"event_id": r["current_event"].get("event_id"),
         "case_id":  r.get("case_id"),
         "risk":     r["risk_level"],
         "escalated":r["should_escalate"],
         "report":   r["final_report"],
         "log":      r["pipeline_log"]}
        for r in results
    ]
    with open("pipeline_results.json", "w") as f:
        json.dump(out, f, indent=2)

    esc = sum(1 for r in results if r.get("should_escalate"))
    print(f"\n✅ Done. Escalated: {esc}/{len(results)}")
    print("   Results → pipeline_results.json")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-file",     default="../data/synthetic_logs.json")
    ap.add_argument("--single-event", type=json.loads, default=None)
    args = ap.parse_args()
    run_pipeline(log_file=args.log_file, single_event=args.single_event)
