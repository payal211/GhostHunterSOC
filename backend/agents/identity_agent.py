"""Agent 1: Identity Monitor — Detects IAM and NHI anomalies."""

import json
from datetime import datetime
from .state import SOCState
from .llm_config import get_llm


def identity_monitor_agent(state: SOCState) -> SOCState:
    event = state["current_event"]
    log = state["pipeline_log"].copy()
    log.append(f"[IdentityMonitor] Processing event: {event.get('event_id', 'N/A')}")

    alert = {
        "event_id": event.get("event_id"),
        "identity_id": event.get("identity_id") or event.get("user"),
        "identity_type": event.get("identity_type", "human"),
        "anomalies_detected": [],
        "initial_risk_score": event.get("risk_score", 0),
        "timestamp": event.get("time"),
    }

    # Rule-based fast detection
    if event.get("geo") in ["RU", "CN", "KP", "IR", "BR"]:
        alert["anomalies_detected"].append("ANOMALOUS_GEO: Access from high-risk country")

    if event.get("days_since_last_active", 0) > 90:
        alert["anomalies_detected"].append(
            f"DORMANT_IDENTITY: {event['days_since_last_active']} days inactive"
        )

    if event.get("mfa_used") is False and event.get("event_type") == "authentication":
        alert["anomalies_detected"].append("MFA_BYPASS: Authentication without MFA")

    ts = event.get("time", "")
    if ts:
        hour = datetime.fromisoformat(ts.replace("Z", "")).hour
        if hour < 6 or hour > 22:
            alert["anomalies_detected"].append(f"OFF_HOURS_ACCESS: Activity at {hour:02d}:00 UTC")

    if event.get("bytes_out", 0) > 100000:
        alert["anomalies_detected"].append(f"LARGE_DATA_TRANSFER: {event['bytes_out']} bytes")

    if "scope_added" in event and event.get("total_scopes", 0) > 2:
        alert["anomalies_detected"].append(f"SCOPE_CREEP: Now has {event['total_scopes']} OAuth scopes")

    if event.get("context") == "unknown_external" and event.get("identity_type") == "api_key":
        alert["anomalies_detected"].append("API_KEY_EXTERNAL_USE: CI/CD key used from external context")

    is_anomaly = len(alert["anomalies_detected"]) > 0 or event.get("risk_score", 0) > 40

    if not is_anomaly:
        log.append("[IdentityMonitor] No anomalies detected — skipping pipeline")
        return {**state, "identity_alert": None, "should_escalate": False, "pipeline_log": log}

    # LLM enrichment
    if alert["anomalies_detected"]:
        try:
            llm = get_llm("mistral", temperature=0.1)
            prompt = f"""You are a SOC analyst reviewing an IAM/NHI security event.

Event Details:
{json.dumps(event, indent=2)}

Detected Anomalies:
{chr(10).join(alert["anomalies_detected"])}

In 2-3 sentences, explain why this event is suspicious and what threat it may indicate.
Be specific to the financial services context. Be concise."""

            explanation = llm.invoke(prompt)
            alert["llm_explanation"] = explanation.strip()
        except Exception as e:
            alert["llm_explanation"] = f"[LLM unavailable: {e}] Rule-based detection active."

    risk_score = event.get("risk_score", 0) + len(alert["anomalies_detected"]) * 10
    alert["adjusted_risk_score"] = min(risk_score, 100)
    alert["should_escalate"] = alert["adjusted_risk_score"] > 40

    risk_level = "LOW"
    if alert["adjusted_risk_score"] > 80:
        risk_level = "CRITICAL"
    elif alert["adjusted_risk_score"] > 60:
        risk_level = "HIGH"
    elif alert["adjusted_risk_score"] > 40:
        risk_level = "MEDIUM"

    log.append(
        f"[IdentityMonitor] Risk: {risk_level} ({alert['adjusted_risk_score']:.1f}) "
        f"| Anomalies: {len(alert['anomalies_detected'])}"
    )

    return {
        **state,
        "identity_alert": alert,
        "risk_level": risk_level,
        "should_escalate": alert["should_escalate"],
        "pipeline_log": log,
    }