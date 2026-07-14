"""Agent 2: Behavior Analyzer — Baselines identity behavior and scores deviation."""

import re
from datetime import datetime
from .state import SOCState
from .llm_config import get_agent_llm


def behavior_analyzer_agent(state: SOCState) -> SOCState:
    """
    Profiles each identity's normal behavior from historical events
    and scores how anomalous the current event is (0–100).

    Input  (from SOCState):  current_event, raw_events, identity_alert
    Output (into SOCState):  behavior_score dict
    """
    if not state.get("should_escalate"):
        return state

    event    = state["current_event"]
    all_evts = state.get("raw_events", [])
    log      = state["pipeline_log"].copy()
    log.append("[BehaviorAnalyzer] Building behavioral profile...")

    identity_id = event.get("identity_id") or event.get("user")

    # Build baseline from normal (non-anomalous) events for this identity
    historical = [
        e for e in all_evts
        if (e.get("identity_id") == identity_id or e.get("user") == identity_id)
        and not e.get("is_anomaly", False)
        and e.get("event_id") != event.get("event_id")
    ]

    behavior_profile = {
        "identity_id":           identity_id,
        "historical_event_count": len(historical),
        "baseline_established":  len(historical) > 5,
    }

    if historical:
        normal_ips       = list({e.get("src_ip")    for e in historical if e.get("src_ip")})
        normal_geos      = list({e.get("geo")        for e in historical if e.get("geo")})
        normal_endpoints = list({e.get("endpoint")   for e in historical if e.get("endpoint")})
        normal_hours     = [
            datetime.fromisoformat(e["time"].replace("Z", "")).hour
            for e in historical if e.get("time")
        ]

        behavior_profile["normal_ips"]        = normal_ips[:5]
        behavior_profile["normal_geos"]       = normal_geos
        behavior_profile["normal_endpoints"]  = normal_endpoints[:5]
        behavior_profile["normal_hour_range"] = (
            (min(normal_hours), max(normal_hours)) if normal_hours else (8, 18)
        )

        # Rule-based deviation detection
        deviations = []
        if event.get("src_ip") and event["src_ip"] not in normal_ips:
            deviations.append(f"New IP: {event['src_ip']} (normal: {normal_ips[:2]})")
        if event.get("geo") and event["geo"] not in normal_geos:
            deviations.append(f"New geography: {event['geo']} (normal: {normal_geos})")
        if (event.get("endpoint") and event["endpoint"] not in normal_endpoints
                and "/admin" in (event.get("endpoint") or "")):
            deviations.append(f"Unusual admin endpoint: {event['endpoint']}")

        behavior_profile["deviations"]      = deviations
        behavior_profile["deviation_count"] = len(deviations)

        # LLM behavior scoring
        try:
            llm = get_agent_llm("behavior_analyzer", temperature=0.1)
            prompt = f"""You are analysing identity behaviour for anomaly detection in a financial services SOC.

Identity: {identity_id}
Historical baseline ({len(historical)} events):
  Normal IPs   : {normal_ips[:3]}
  Normal Geos  : {normal_geos}
  Normal Hours : {min(normal_hours) if normal_hours else 'N/A'}–{max(normal_hours) if normal_hours else 'N/A'} UTC

Current Event:
  IP   : {event.get('src_ip')}
  Geo  : {event.get('geo')}
  Time : {event.get('time')}

Deviations detected: {deviations}

Rate the behavioural anomaly on a scale of 0–100 and explain in 2 sentences.
Respond in this EXACT format (no other text):
SCORE: [number]
REASONING: [explanation]"""

            response  = llm.invoke(prompt)
            lines     = response.strip().split("\n")
            score_ln  = next((l for l in lines if l.startswith("SCORE:")),    "SCORE: 50")
            reason_ln = next((l for l in lines if l.startswith("REASONING:")), "REASONING: Deviation detected.")
            match = re.search(r"\d+", score_ln)
            behavior_profile["llm_behavior_score"] = int(match.group()) if match else 50
            behavior_profile["llm_reasoning"]      = reason_ln.replace("REASONING:", "").strip()

        except Exception as e:
            behavior_profile["llm_behavior_score"] = min(50 + len(deviations) * 15, 100)
            behavior_profile["llm_reasoning"]      = f"Rule-based: {len(deviations)} deviations from baseline."

    else:
        # No historical data — identity has never been seen before
        behavior_profile["deviations"]         = ["NO_BASELINE: Identity has no historical activity"]
        behavior_profile["llm_behavior_score"] = 65
        behavior_profile["llm_reasoning"]      = "No historical baseline available — cannot determine normal pattern."

    log.append(
        f"[BehaviorAnalyzer] Score: {behavior_profile.get('llm_behavior_score', 'N/A')}/100 "
        f"| Deviations: {len(behavior_profile.get('deviations', []))}"
    )
    return {**state, "behavior_score": behavior_profile, "pipeline_log": log}
