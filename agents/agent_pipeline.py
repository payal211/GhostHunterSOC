"""
AutonomSOC — LangGraph Multi-Agent Pipeline
Full 6-agent pipeline: IdentityMonitor → BehaviorAnalyzer → ThreatIntelRAG
                        → Correlation → Response → Reporting

Integrates: Ollama LLMs | ChromaDB RAG | Neo4j Graph | MITRE Engine | TheHive

Run:
    python agent_pipeline.py --log-file ../data/synthetic_logs.json
    python agent_pipeline.py --kafka   # consume from Kafka
"""

import json, os, re, sys
from typing import TypedDict, List, Dict, Any, Optional, Annotated
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langgraph.graph import StateGraph, END

from attack_graph.neo4j_graph import AttackGraphDB
from mitre.mitre_engine import MITREEngine

OLLAMA_HOST  = os.getenv("OLLAMA_HOST","http://localhost:11434")
NEO4J_URI    = os.getenv("NEO4J_URI","bolt://localhost:7687")
NEO4J_USER   = os.getenv("NEO4J_USER","neo4j")
NEO4J_PASS   = os.getenv("NEO4J_PASSWORD","autonomsoc2026")
THEHIVE_URL  = os.getenv("THEHIVE_URL","http://localhost:9000")
THEHIVE_KEY  = os.getenv("THEHIVE_KEY","")

# ── Ollama helpers ──────────────────────────────────────────────────────────────

def _normalize_ollama_model(model: str) -> str:
    if not model:
        return model
    return model if ":" in model else f"{model}:latest"

# ── Shared State ──────────────────────────────────────────────────────────────
class SOCState(TypedDict):
    raw_events:       List[Dict[str, Any]]
    current_event:    Dict[str, Any]
    identity_alert:   Optional[Dict]
    behavior_score:   Optional[Dict]
    threat_intel:     Optional[Dict]
    correlation:      Optional[Dict]
    response_actions: Optional[Dict]
    final_report:     Optional[str]
    risk_level:       str
    should_escalate:  bool
    case_id:          Optional[str]
    pipeline_log:     List[str]

# ── LLM Factory ──────────────────────────────────────────────────────────────
def llm(model="llama3.1", temperature=0.1):
    normalized = _normalize_ollama_model(model)
    return OllamaLLM(model=normalized, temperature=temperature,
                     base_url=OLLAMA_HOST, timeout=120)

# ── Singletons (loaded once) ──────────────────────────────────────────────────
_neo4j: Optional[AttackGraphDB] = None
_mitre: Optional[MITREEngine]   = None

def get_neo4j() -> AttackGraphDB:
    global _neo4j
    if _neo4j is None:
        _neo4j = AttackGraphDB(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    return _neo4j

def get_mitre() -> MITREEngine:
    global _mitre
    if _mitre is None:
        _mitre = MITREEngine()
    return _mitre

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 1 — Identity Monitor
# ─────────────────────────────────────────────────────────────────────────────
def identity_monitor_agent(state: SOCState) -> SOCState:
    event = state["current_event"]
    log   = state["pipeline_log"].copy()
    log.append(f"[IdentityMonitor] Processing: {event.get('event_id','?')[:12]}")

    alert = {
        "event_id":       event.get("event_id"),
        "identity_id":    event.get("identity_id") or event.get("user","unknown"),
        "identity_type":  event.get("identity_type","unknown"),
        "timestamp":      event.get("time"),
        "anomalies_detected": [],
        "initial_risk_score": event.get("risk_score", 0),
    }

    # Rule-based detection
    geo = event.get("geo","")
    if geo in ["RU","CN","KP","IR","BR","NG","VN"]:
        alert["anomalies_detected"].append(f"ANOMALOUS_GEO: {geo} is high-risk country")

    if event.get("days_since_last_active",0) > 90:
        alert["anomalies_detected"].append(
            f"DORMANT_IDENTITY: {event['days_since_last_active']} days inactive")

    if event.get("mfa_used") is False and event.get("event_type") == "authentication":
        alert["anomalies_detected"].append("MFA_BYPASS: Authentication without MFA")

    ts = event.get("time","")
    if ts:
        try:
            hour = datetime.fromisoformat(ts.replace("Z","")).hour
            if hour < 6 or hour > 22:
                alert["anomalies_detected"].append(f"OFF_HOURS_ACCESS: Activity at {hour:02d}:00 UTC")
        except Exception:
            pass

    if event.get("bytes_out",0) > 100_000:
        alert["anomalies_detected"].append(
            f"LARGE_TRANSFER: {event['bytes_out']:,} bytes exfiltrated")

    if event.get("context") == "unknown_external" and event.get("identity_type") == "api_key":
        alert["anomalies_detected"].append("API_KEY_EXTERNAL_USE: CI/CD key from unknown external context")

    scopes = event.get("total_scopes",0)
    if scopes > 2 and event.get("event_type") == "oauth_scope_grant":
        alert["anomalies_detected"].append(f"SCOPE_CREEP: OAuth now has {scopes} permission scopes")

    is_anomaly = (len(alert["anomalies_detected"]) > 0 or
                  event.get("risk_score",0) > 40 or
                  event.get("is_anomaly", False))

    if not is_anomaly:
        log.append("[IdentityMonitor] Normal — skipping pipeline")
        return {**state, "identity_alert": None, "should_escalate": False, "pipeline_log": log}

    # LLM enrichment
    if alert["anomalies_detected"]:
        try:
            m = llm("mistral")
            prompt = (
                "You are a financial SOC analyst. Review this security event and explain "
                "in 2-3 sentences why it is suspicious and what threat it may indicate.\n\n"
                f"Event: {json.dumps(event, indent=2)}\n"
                f"Anomalies: {chr(10).join(alert['anomalies_detected'])}\n\n"
                "Be concise and specific to financial services."
            )
            alert["llm_explanation"] = m.invoke(prompt).strip()
        except Exception as e:
            alert["llm_explanation"] = f"[LLM offline] Rule-based: {len(alert['anomalies_detected'])} anomalies."

    base_score = event.get("risk_score", 0)
    boost      = len(alert["anomalies_detected"]) * 12
    adj_score  = min(base_score + boost, 100)
    alert["adjusted_risk_score"] = adj_score

    risk = ("CRITICAL" if adj_score > 80 else
            "HIGH"     if adj_score > 60 else
            "MEDIUM"   if adj_score > 40 else "LOW")

    log.append(f"[IdentityMonitor] ALERT {risk} ({adj_score:.1f}) | {len(alert['anomalies_detected'])} anomalies")
    return {**state,
            "identity_alert": alert,
            "risk_level": risk,
            "should_escalate": adj_score > 40,
            "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 2 — Behavior Analyzer
# ─────────────────────────────────────────────────────────────────────────────
def behavior_analyzer_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return state

    event = state["current_event"]
    all_e = state.get("raw_events", [])
    log   = state["pipeline_log"].copy()
    log.append("[BehaviorAnalyzer] Building behavioral profile...")

    identity_id = event.get("identity_id") or event.get("user","?")
    historical  = [e for e in all_e
                   if (e.get("identity_id")==identity_id or e.get("user")==identity_id)
                   and not e.get("is_anomaly") and e.get("event_id")!=event.get("event_id")]

    profile = {
        "identity_id": identity_id,
        "historical_count": len(historical),
        "baseline_established": len(historical) > 5,
    }

    if historical:
        norm_ips  = list({e.get("src_ip") for e in historical if e.get("src_ip")})
        norm_geos = list({e.get("geo") for e in historical if e.get("geo")})
        norm_eps  = list({e.get("endpoint") for e in historical if e.get("endpoint")})
        hours     = [datetime.fromisoformat(e["time"].replace("Z","")).hour
                     for e in historical if e.get("time")]
        profile.update({"normal_ips": norm_ips[:5], "normal_geos": norm_geos,
                         "normal_endpoints": norm_eps[:5],
                         "normal_hour_range": (min(hours),max(hours)) if hours else (8,18)})
        devs = []
        if event.get("src_ip") and event["src_ip"] not in norm_ips:
            devs.append(f"New IP: {event['src_ip']} (normal: {norm_ips[:2]})")
        if event.get("geo") and event["geo"] not in norm_geos:
            devs.append(f"New geo: {event['geo']} (normal: {norm_geos})")
        if event.get("endpoint") and event["endpoint"] not in norm_eps and "admin" in (event.get("endpoint") or ""):
            devs.append(f"Sensitive endpoint: {event['endpoint']}")
        profile["deviations"] = devs

        try:
            m = llm("mistral")
            prompt = (
                f"Identity: {identity_id}\n"
                f"Baseline ({len(historical)} events): IPs={norm_ips[:3]}, Geos={norm_geos}, "
                f"Hours={min(hours) if hours else 'N/A'}-{max(hours) if hours else 'N/A'}\n"
                f"Current: IP={event.get('src_ip')}, Geo={event.get('geo')}, Time={event.get('time')}\n"
                f"Deviations: {devs}\n\n"
                "Rate the behavioral anomaly 0-100. Respond ONLY:\n"
                "SCORE: [number]\nREASONING: [one sentence]"
            )
            resp  = m.invoke(prompt).strip()
            score_m = re.search(r"SCORE:\s*(\d+)", resp)
            reason_m = re.search(r"REASONING:\s*(.+)", resp)
            profile["behavior_score"] = int(score_m.group(1)) if score_m else 50
            profile["reasoning"] = reason_m.group(1).strip() if reason_m else resp
        except Exception as e:
            profile["behavior_score"] = 50 + len(devs) * 15
            profile["reasoning"] = f"Rule-based: {len(devs)} deviations."
    else:
        profile["deviations"] = ["NO_BASELINE: No historical data for this identity"]
        profile["behavior_score"] = 65
        profile["reasoning"] = "No baseline — cannot determine normal behavior."

    log.append(f"[BehaviorAnalyzer] Score: {profile.get('behavior_score')}/100 | Deviations: {len(profile.get('deviations',[]))}")
    return {**state, "behavior_score": profile, "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 3 — Threat Intel RAG
# ─────────────────────────────────────────────────────────────────────────────
def threat_intel_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return state

    event = state["current_event"]
    alert = state.get("identity_alert", {})
    log   = state["pipeline_log"].copy()
    log.append("[ThreatIntel] Querying MITRE ATT&CK knowledge base...")

    # Use MITRE engine (ChromaDB RAG + rules)
    engine  = get_mitre()
    mapping = engine.map_event({**event, "anomalies_detected": alert.get("anomalies_detected",[])})
    
    # Defensive check: mapping might be None
    if mapping is None:
        mapping = {
            "primary_technique": "UNKNOWN",
            "primary_technique_name": "Unknown Technique",
            "primary_tactic": "unknown",
            "primary_confidence": 0.0,
            "all_techniques": [],
            "primary_pci_mapping": "PCI DSS 8.x",
        }

    # LLM threat assessment
    try:
        m = llm("llama3.1")
        top_techs = mapping.get("all_techniques", [])[:3] if mapping.get("all_techniques") else []
        techs_text = "\n".join(f"- {t.get('technique_id','?')}: {t.get('technique_name','?')} ({t.get('tactic','?')})"
                               for t in top_techs)
        prompt = (
            "You are a threat intelligence analyst at a financial services SOC.\n\n"
            f"Observed anomalies: {', '.join(alert.get('anomalies_detected',[]))}\n"
            f"Top MITRE techniques matched:\n{techs_text}\n\n"
            "In 3-4 sentences:\n"
            "1. What attack technique is most likely?\n"
            "2. What is the attacker's probable objective at a financial institution?\n"
            "3. What is the urgency? (CRITICAL/HIGH/MEDIUM/LOW)"
        )
        assessment = m.invoke(prompt).strip()
    except Exception as e:
        assessment = (f"MITRE mapping complete. Primary technique: {mapping.get('primary_technique','?')}. "
                      f"Tactic: {mapping.get('primary_tactic','?')}. LLM offline: {e}")

    threat_intel = {**mapping, "threat_assessment": assessment}
    log.append(f"[ThreatIntel] Primary: {mapping.get('primary_technique','?')} | Confidence: {mapping.get('primary_confidence',0.0):.2f}")
    return {**state, "threat_intel": threat_intel, "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 4 — Correlation
# ─────────────────────────────────────────────────────────────────────────────
def correlation_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return state

    event = state["current_event"]
    all_e = state.get("raw_events", [])
    log   = state["pipeline_log"].copy()
    log.append("[Correlation] Building attack chain...")

    identity_id = event.get("identity_id") or event.get("user","?")
    attack_type = event.get("attack_type")

    related = [e for e in all_e
               if e.get("event_id") != event.get("event_id") and e.get("is_anomaly") and (
                   e.get("attack_type") == attack_type or
                   e.get("identity_id") == identity_id or
                   e.get("src_ip") == event.get("src_ip"))]

    affected_ids = list({e.get("identity_id") or e.get("user") for e in related if e.get("identity_id") or e.get("user")})
    affected_eps = list({e.get("endpoint") for e in related if e.get("endpoint")})
    blast_radius = min(len(affected_ids)*20 + len(affected_eps)*10, 100)

    corr = {
        "primary_event_id":  event.get("event_id"),
        "related_events":    len(related),
        "affected_identities": affected_ids[:10],
        "affected_endpoints":  affected_eps[:10],
        "blast_radius_score":  blast_radius,
        "attack_chain_ids":    [e.get("event_id") for e in related[:5]],
    }

    try:
        m = llm("llama3.1", temperature=0.2)
        threat_data = state.get("threat_intel") or {}
        techs = [t.get("technique_id","?") for t in threat_data.get("all_techniques",[]) if t]
        prompt = (
            f"Senior threat analyst building an incident timeline for Financial organization SOC.\n\n"
            f"Primary Event: {json.dumps(event, indent=2)}\n"
            f"Related events found: {len(related)}\n"
            f"Affected identities: {affected_ids[:5]}\n"
            f"Affected endpoints: {affected_eps[:5]}\n"
            f"MITRE techniques: {techs}\n\n"
            "Write a 4-5 sentence attack narrative describing:\n"
            "1. Initial access method\n2. Attacker actions (lateral movement/escalation)\n"
            "3. Likely objective\n4. Potential impact to Financial organization\nUse active voice."
        )
        corr["attack_narrative"] = m.invoke(prompt).strip()
    except Exception as e:
        corr["attack_narrative"] = (
            f"Attack chain: {len(related)} related events across {len(affected_ids)} "
            f"identities and {len(affected_eps)} endpoints. LLM offline: {e}")

    # Write to Neo4j
    try:
        db = get_neo4j()
        db.ingest_pipeline_result({**state, "correlation": corr,
                                    "case_id": state.get("case_id","UNKNOWN")})
    except Exception as e:
        log.append(f"[Correlation] Neo4j write failed: {e}")

    log.append(f"[Correlation] Chain: {len(related)} events | Blast: {blast_radius}/100")
    return {**state, "correlation": corr, "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 5 — Response
# ─────────────────────────────────────────────────────────────────────────────
def response_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return state

    event       = state["current_event"]
    risk_level  = state.get("risk_level","MEDIUM")
    attack_type = event.get("attack_type","")
    identity_id = event.get("identity_id") or event.get("user","?")
    id_type     = event.get("identity_type","unknown")
    log         = state["pipeline_log"].copy()
    log.append("[Response] Selecting SOAR playbooks...")

    ts = datetime.utcnow().isoformat()+"Z"

    PLAYBOOKS = {
        "rotate_credential":  {"name":"Credential Rotation",
            "result":f"EXECUTED: Rotated credential for {identity_id}. Old token invalidated.",
            "severity":["HIGH","CRITICAL"],"types":["api_key","service_account","oauth_token","certificate"]},
        "disable_account":    {"name":"Account Suspension",
            "result":f"EXECUTED: Suspended {identity_id} pending investigation.",
            "severity":["CRITICAL"],"types":["service_account","human"]},
        "revoke_oauth_scopes":{"name":"OAuth Scope Revocation",
            "result":f"EXECUTED: Revoked excess OAuth scopes for {identity_id}.",
            "severity":["MEDIUM","HIGH","CRITICAL"],"types":["oauth_token"]},
        "block_ip":           {"name":"IP Block",
            "result":f"EXECUTED: Blocked {event.get('src_ip','?')} at perimeter firewall.",
            "severity":["HIGH","CRITICAL"],"types":["api_key","service_account","oauth_token","human"]},
        "force_mfa":          {"name":"Force MFA Re-Auth",
            "result":f"EXECUTED: MFA re-auth forced for {identity_id}. Session invalidated.",
            "severity":["MEDIUM","HIGH","CRITICAL"],"types":["human","service_account"]},
        "alert_owner":        {"name":"Notify Identity Owner",
            "result":f"EXECUTED: Owner of {identity_id} notified. ServiceNow ticket created.",
            "severity":["LOW","MEDIUM","HIGH","CRITICAL"],"types":["api_key","service_account","oauth_token","human"]},
        "thehive_alert":      {"name":"TheHive Case Created",
            "result":f"EXECUTED: Incident case opened in TheHive for {identity_id}.",
            "severity":["HIGH","CRITICAL"],"types":["api_key","service_account","oauth_token","human","certificate"]},
    }

    ATTACK_FILTER = {
        "dormant_nhi_reactivation": ["rotate_credential","disable_account","alert_owner","thehive_alert"],
        "oauth_scope_creep":        ["revoke_oauth_scopes","alert_owner","thehive_alert"],
        "api_key_exfiltration":     ["rotate_credential","block_ip","alert_owner","thehive_alert"],
        "golden_ticket":            ["disable_account","block_ip","force_mfa","alert_owner","thehive_alert"],
    }

    selected = []
    allowed  = ATTACK_FILTER.get(attack_type, list(PLAYBOOKS.keys()))
    for pb_id in allowed:
        pb = PLAYBOOKS.get(pb_id, {})
        if risk_level in pb.get("severity",[]) and id_type in pb.get("types",[]):
            selected.append({
                "playbook_id":   pb_id,
                "playbook_name": pb["name"],
                "result":        pb["result"],
                "executed_at":   ts,
                "automated":     risk_level in ["HIGH","CRITICAL"],
            })

    mttc = 73 if risk_level=="CRITICAL" else 120 if risk_level=="HIGH" else 300
    result = {
        "playbooks_executed":     selected[:3],
        "actions_count":          len(selected[:3]),
        "automated":              risk_level in ["HIGH","CRITICAL"],
        "mttc_seconds":           mttc,
        "human_review_required":  risk_level == "CRITICAL",
        "executed_at":            ts,
    }

    log.append(f"[Response] {len(selected[:3])} playbooks | MTTC: {mttc}s")
    return {**state, "response_actions": result, "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# AGENT 6 — Reporting
# ─────────────────────────────────────────────────────────────────────────────
def reporting_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return {**state, "final_report": "No escalation — event classified normal."}

    log    = state["pipeline_log"].copy()
    alert  = state.get("identity_alert") or {}
    threat = state.get("threat_intel") or {}
    corr   = state.get("correlation") or {}
    resp   = state.get("response_actions") or {}
    event  = state["current_event"]
    log.append("[Reporting] Generating incident report...")

    try:
        m = llm("llama3.1")
        actions = ", ".join(p.get("playbook_name","?") for p in resp.get("playbooks_executed",[]) if p)
        prompt = (
            f"Generate a structured security incident report for a financial SOC.\n\n"
            f"INCIDENT: Identity={alert.get('identity_id','?')} | Risk={state.get('risk_level','?')} "
            f"| Score={alert.get('adjusted_risk_score','?')}/100\n"
            f"ANOMALIES: {', '.join(alert.get('anomalies_detected',[]))}\n"
            f"MITRE: {threat.get('primary_technique','?')} — {threat.get('primary_technique_name','?')}\n"
            f"THREAT: {threat.get('threat_assessment','N/A')}\n"
            f"NARRATIVE: {corr.get('attack_narrative','N/A')}\n"
            f"RESPONSE: {actions}\n"
            f"MTTC: {resp.get('mttc_seconds','?')}s\n\n"
            "Write report with sections:\n"
            "## EXECUTIVE SUMMARY\n## TECHNICAL DETAILS\n"
            "## IMPACT ASSESSMENT\n## ACTIONS TAKEN\n"
            "## RECOMMENDATIONS\n## COMPLIANCE NOTES (PCI-DSS/SOX)"
        )
        report = m.invoke(prompt).strip()
    except Exception as e:
        pci = threat.get("primary_pci_mapping","PCI DSS 8.x")
        report = (
            f"## EXECUTIVE SUMMARY\n"
            f"A {state.get('risk_level','?')} severity IAM/NHI threat auto-contained for "
            f"{alert.get('identity_id','?')} in {resp.get('mttc_seconds','?')} seconds.\n\n"
            f"## TECHNICAL DETAILS\n"
            f"- Identity: {alert.get('identity_id','?')} ({alert.get('identity_type','?')})\n"
            f"- Risk Score: {alert.get('adjusted_risk_score','?')}/100\n"
            f"- Anomalies: {'; '.join(alert.get('anomalies_detected',[]))}\n"
            f"- MITRE: {threat.get('primary_technique','?')} — {threat.get('primary_technique_name','?')}\n\n"
            f"## IMPACT ASSESSMENT\n"
            f"Blast radius: {corr.get('blast_radius_score','?')}/100 | "
            f"Identities: {len(corr.get('affected_identities',[]))} | "
            f"Endpoints: {len(corr.get('affected_endpoints',[]))}\n\n"
            f"## ACTIONS TAKEN\n" +
            "\n".join(f"- {p.get('playbook_name','?')}: {p.get('result','?')}"
                      for p in resp.get("playbooks_executed",[]) if p) +
            f"\n\n## COMPLIANCE NOTES\n{pci}\n"
            f"Incident auto-logged for PCI-DSS audit. MTTC: {resp.get('mttc_seconds','?')}s."
        )

    log.append("[Reporting] Report generated")
    return {**state, "final_report": report, "pipeline_log": log}

# ─────────────────────────────────────────────────────────────────────────────
# Build Pipeline
# ─────────────────────────────────────────────────────────────────────────────
def build_pipeline():
    g = StateGraph(SOCState)
    g.add_node("identity_monitor",   identity_monitor_agent)
    g.add_node("behavior_analyzer",  behavior_analyzer_agent)
    g.add_node("threat_intel",       threat_intel_agent)
    g.add_node("correlation",        correlation_agent)
    g.add_node("response",           response_agent)
    g.add_node("reporting",          reporting_agent)
    g.set_entry_point("identity_monitor")
    g.add_edge("identity_monitor",  "behavior_analyzer")
    g.add_edge("behavior_analyzer", "threat_intel")
    g.add_edge("threat_intel",      "correlation")
    g.add_edge("correlation",       "response")
    g.add_edge("response",          "reporting")
    g.add_edge("reporting",         END)
    return g.compile()

def run_on_event(event: Dict, all_events: List[Dict], case_id: str = None) -> Dict:
    import uuid as _uuid
    pipeline = build_pipeline()
    state: SOCState = {
        "raw_events": all_events, "current_event": event,
        "identity_alert": None, "behavior_score": None,
        "threat_intel": None, "correlation": None,
        "response_actions": None, "final_report": None,
        "risk_level": "LOW", "should_escalate": False,
        "case_id": case_id or f"DEMO-{str(_uuid.uuid4())[:8].upper()}",
        "pipeline_log": [],
    }
    return pipeline.invoke(state)

if __name__ == "__main__":
    import argparse, uuid as _uuid
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-file", default="../data/synthetic_logs.json")
    ap.add_argument("--kafka", action="store_true")
    args = ap.parse_args()

    if args.kafka:
        from kafka.kafka_consumer import run_consumer
        run_consumer()
    else:
        with open(args.log_file) as f:
            logs = json.load(f)
        anomalous = [e for e in logs if e.get("is_anomaly")][:5]
        results = []
        for i, ev in enumerate(anomalous):
            print(f"\n{'='*60}\n[{i+1}/{len(anomalous)}] Processing {ev.get('event_id','?')[:12]}...")
            r = run_on_event(ev, logs, f"DEMO-{str(_uuid.uuid4())[:8].upper()}")
            if r.get("should_escalate"):
                print(f"ALERT {r['risk_level']} | {r['identity_alert']['adjusted_risk_score']:.0f}/100")
                for line in r["pipeline_log"]: print(f"  {line}")
                print(f"\n{r['final_report'][:400]}...")
            results.append(r)
        with open("pipeline_results.json","w") as f:
            json.dump([{"event_id":r["current_event"].get("event_id"),
                        "risk_level":r["risk_level"],"escalated":r["should_escalate"],
                        "report":r["final_report"]} for r in results], f, indent=2)
        print(f"\nDone. Escalated: {sum(1 for r in results if r.get('should_escalate'))}/{len(results)}")