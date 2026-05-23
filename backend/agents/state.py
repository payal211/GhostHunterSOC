"""Shared SOC pipeline state schema used by all 6 agents."""

from typing import TypedDict, List, Dict, Any, Optional


class SOCState(TypedDict):
    """
    Shared state passed through all agents in the LangGraph pipeline.
    Each agent reads from this and writes its output back into it.
    Nothing is lost between agents — full context always available.
    """
    # ── Input ────────────────────────────────────────────────────────
    raw_events:    List[Dict[str, Any]]   # Sliding window of recent events (for baseline)
    current_event: Dict[str, Any]         # The event being analysed right now

    # ── Agent outputs (accumulated as pipeline progresses) ────────────
    identity_alert:   Optional[Dict]      # Agent 1: anomalies, adjusted_risk_score
    behavior_score:   Optional[Dict]      # Agent 2: llm_behavior_score, deviations
    threat_intel:     Optional[Dict]      # Agent 3: primary_technique, threat_assessment
    correlation:      Optional[Dict]      # Agent 4: attack_narrative, blast_radius
    response_actions: Optional[Dict]      # Agent 5: playbooks_executed, mttc_seconds
    final_report:     Optional[str]       # Agent 6: full markdown incident report

    # ── Pipeline metadata ─────────────────────────────────────────────
    risk_level:     str         # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    should_escalate: bool       # False = pipeline short-circuits after Agent 1
    case_id:        Optional[str]         # DEMO-SOC-XXXXXXXX
    pipeline_log:   List[str]             # Audit trail of every agent decision
