"""
Agent 3: Threat Intel RAG — Enriches alerts with MITRE ATT&CK intelligence.
Uses the built-in MITREEngine for semantic mapping + Ollama LLM for reasoning.

BUG FIXED: The original imported `from rag.chroma_store import setup_chroma`
using an absolute path that breaks when running from inside the agents/ package.
This now uses `mitre.mitre_engine` directly.
"""

import json

from .state import SOCState
from .llm_config import get_agent_llm
from mitre.mitre_engine import MITREEngine

_mitre_engine = None

def get_mitre_engine() -> MITREEngine:
    global _mitre_engine
    if _mitre_engine is None:
        _mitre_engine = MITREEngine()
    return _mitre_engine


def threat_intel_agent(state: SOCState) -> SOCState:
    """
    Queries the MITRE engine for relevant ATT&CK techniques,
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

    # MITRE engine semantic mapping
    try:
        engine = get_mitre_engine()
        mitre_result = engine.map_event({
            "anomalies_detected": anomalies,
            "event_type": event.get("event_type"),
            "attack_type": event.get("attack_type"),
            "identity_type": event.get("identity_type"),
            "geo": event.get("geo",""),
            "days_since_last_active": event.get("days_since_last_active", 0),
        })
        threat_docs = mitre_result.get("all_techniques", [])[:3]
        if not threat_docs:
            threat_docs = [{
                "technique_id": mitre_result.get("primary_technique", "UNKNOWN"),
                "technique_name": mitre_result.get("primary_technique_name", "Unknown"),
                "tactic": mitre_result.get("primary_tactic", "Unknown"),
                "description": mitre_result.get("primary_remediation", "No details available."),
            }]
    except Exception as e:
        threat_docs = [{
            "technique_id": "ERROR",
            "technique_name": "Unknown",
            "tactic": "Unknown",
            "description": str(e),
        }]
        log.append(f"[ThreatIntel] ⚠ MITRE engine unavailable: {e}")

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
    f"- {t.get('technique_id','UNKNOWN')} ({t.get('tactic','Unknown')}): {t.get('description', t.get('content',''))[:250]}"
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
