"""Agent 4: Correlation Agent — Chains events into attack narratives and maps kill chain."""

import json
from .state import SOCState
from .llm_config import get_agent_llm


def correlation_agent(state: SOCState) -> SOCState:
    """
    Links related events into a complete attack story and calculates blast radius.
    Also writes results to Neo4j attack graph.

    Input  (from SOCState):  current_event, raw_events, identity_alert, threat_intel
    Output (into SOCState):  correlation dict (attack_narrative, blast_radius_score, ...)
    """
    if not state.get("should_escalate"):
        return state

    event   = state["current_event"]
    all_e   = state.get("raw_events", [])
    log     = state["pipeline_log"].copy()
    log.append("[Correlation] Building attack chain and narrative...")

    identity_id = event.get("identity_id") or event.get("user")
    attack_type = event.get("attack_type")

    # Find related anomalous events: same attack type, same identity, or same src IP
    related = [
        e for e in all_e
        if e.get("event_id") != event.get("event_id")
        and e.get("is_anomaly")
        and (
            e.get("attack_type")  == attack_type
            or e.get("identity_id") == identity_id
            or e.get("src_ip")     == event.get("src_ip")
        )
    ]

    affected_ids = list({
        e.get("identity_id") or e.get("user")
        for e in related
        if e.get("identity_id") or e.get("user")
    })
    affected_eps = list({e.get("endpoint") for e in related if e.get("endpoint")})

    correlation = {
        "primary_event_id":    event.get("event_id"),
        "related_event_count": len(related),
        "affected_identities": affected_ids[:10],
        "affected_endpoints":  affected_eps[:10],
        "blast_radius_score":  min(len(affected_ids) * 20 + len(affected_eps) * 10, 100),
        "attack_chain_events": [e.get("event_id") for e in related[:5]],
    }

    # LLM attack narrative
    try:
        llm = get_agent_llm("correlation", temperature=0.2)
        mitre_techs = [
            t["technique_id"]
            for t in state.get("threat_intel", {}).get("relevant_techniques", [])
        ]

        prompt = f"""You are a senior threat analyst building an incident timeline for financial SOC.

Primary Event:
{json.dumps(event, indent=2)}

Related events found : {len(related)}
Affected identities  : {affected_ids[:5]}
Affected endpoints   : {affected_eps[:5]}
MITRE techniques     : {mitre_techs}
Attack type          : {attack_type}

Write a concise attack narrative (4-5 sentences) describing:
1. How the attack likely started (initial access method)
2. What the attacker did next (lateral movement / privilege escalation)
3. What the attacker's goal appears to be
4. The potential impact to  financial systems

Use active voice. Be specific. Reference actual identities and endpoints from the data."""

        narrative = llm.invoke(prompt)
        correlation["attack_narrative"] = narrative.strip()

    except Exception as e:
        correlation["attack_narrative"] = (
            f"Attack chain: {len(related)} related events across "
            f"{len(affected_ids)} identities and {len(affected_eps)} endpoints. "
            f"LLM offline: {e}"
        )

    # Write to Neo4j attack graph
    try:
        import sys, os
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from neo4j.graph_builder import AttackGraphBuilder
        db = AttackGraphBuilder()
        db.ingest_pipeline_result({**state, "correlation": correlation})
        db.close()
        log.append("[Correlation] ✅ Neo4j graph updated")
    except Exception as e:
        log.append(f"[Correlation] ⚠ Neo4j write skipped: {e}")

    log.append(
        f"[Correlation] Chain: {len(related)} events "
        f"| Blast radius: {correlation['blast_radius_score']}/100"
    )
    return {**state, "correlation": correlation, "pipeline_log": log}
