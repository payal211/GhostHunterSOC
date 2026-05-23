"""
Agent 3: Threat Intel RAG — Enriches alerts with MITRE ATT&CK intelligence.
Uses ChromaDB for vector search + Ollama LLM for reasoning.

BUG FIXED: The original imported `from rag.chroma_store import setup_chroma`
using an absolute path that breaks when running from inside the agents/ package.
Fixed to use sys.path manipulation consistently.
"""

import json, sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from .state import SOCState
from .llm_config import get_agent_llm
from rag.chroma_store import setup_chroma, query_threat_intel


def threat_intel_agent(state: SOCState) -> SOCState:
    """
    Queries ChromaDB for relevant MITRE ATT&CK techniques,
    then uses LLM to synthesise a threat assessment.

    Input  (from SOCState):  current_event, identity_alert
    Output (into SOCState):  threat_intel dict
    """
    if not state.get("should_escalate"):
        return state

    event     = state["current_event"]
    alert     = state.get("identity_alert", {})
    log       = state["pipeline_log"].copy()
    log.append("[ThreatIntel] Querying MITRE ATT&CK knowledge base...")

    anomalies = alert.get("anomalies_detected", [])

    # Build semantic query from event context
    query = (
        f"Identity type: {event.get('identity_type', 'unknown')}. "
        f"Anomalies: {', '.join(anomalies)}. "
        f"Event type: {event.get('event_type', 'unknown')}. "
        f"Attack type: {event.get('attack_type', 'unknown')}. "
        f"Geography: {event.get('geo', 'unknown')}. "
        f"Days dormant: {event.get('days_since_last_active', 0)}."
    )

    # ChromaDB vector search
    try:
        collection  = setup_chroma()
        threat_docs = query_threat_intel(collection, query, n_results=3)
    except Exception as e:
        threat_docs = [{"technique_id": "ERROR", "content": str(e), "tactic": "Unknown"}]
        log.append(f"[ThreatIntel] ⚠ ChromaDB unavailable: {e}")

    threat_intel = {
        "relevant_techniques": threat_docs,
        "query_used":          query,
    }

    # LLM synthesis — reasons over ChromaDB results to produce threat assessment
    try:
        llm = get_agent_llm("threat_intel", temperature=0.1)

        prompt = f"""You are a threat intelligence analyst at a financial services SOC (American Express).

Observed event anomalies:
{json.dumps(anomalies, indent=2)}

Relevant MITRE ATT&CK techniques from knowledge base:
{chr(10).join([
    f"- {t['technique_id']} ({t['tactic']}): {t['content'][:250]}"
    for t in threat_docs
])}

Provide a concise threat assessment (3-4 sentences):
1. Which MITRE technique is most likely being used and why?
2. What is the attacker's probable objective in a financial services context?
3. Urgency level: LOW / MEDIUM / HIGH / CRITICAL?
4. One specific recommended immediate action."""

        assessment = llm.invoke(prompt)
        threat_intel["threat_assessment"]  = assessment.strip()
        threat_intel["primary_technique"]  = threat_docs[0]["technique_id"] if threat_docs else "UNKNOWN"
        threat_intel["primary_tactic"]     = threat_docs[0]["tactic"]        if threat_docs else "Unknown"

    except Exception as e:
        threat_intel["threat_assessment"] = (
            f"ChromaDB: {len(threat_docs)} techniques matched. LLM offline: {e}"
        )
        threat_intel["primary_technique"] = threat_docs[0]["technique_id"] if threat_docs else "UNKNOWN"
        threat_intel["primary_tactic"]    = threat_docs[0]["tactic"]        if threat_docs else "Unknown"

    log.append(
        f"[ThreatIntel] Primary: {threat_intel['primary_technique']} "
        f"({threat_intel['primary_tactic']}) | {len(threat_docs)} techniques matched"
    )
    return {**state, "threat_intel": threat_intel, "pipeline_log": log}
