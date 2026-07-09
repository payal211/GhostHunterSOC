"""
AutonomSOC — FastAPI Backend
REST API exposing agent pipeline, Neo4j graph queries, and SOC stats.

Run:    uvicorn api.api:app --reload --port 8000
Docs:   http://localhost:8000/docs
"""

import json, os, uuid, sys
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import StreamingResponse
from io import BytesIO
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

app = FastAPI(title="AutonomSOC API", version="2.0.0",
              description="Agentic AI-Powered Autonomous SOC for IAM & NHI Threats")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── In-memory stores (replace with DB in prod) ────────────────────────────────
CASES:   Dict[str, Dict] = {}
WS_CLIENTS: List[WebSocket] = []


def _build_demo_graph_payload() -> Dict[str, Any]:
    return {
        "nodes_and_edges": [
            {
                "source": "svc_ci_cd_runner_331",
                "source_type": "service_account",
                "source_risk": 96,
                "target": "/api/internal/admin",
                "target_label": "Resource",
                "relationship": "ACCESSED",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
            {
                "source": "svc_ci_cd_runner_331",
                "source_type": "service_account",
                "source_risk": 96,
                "target": "91.108.4.136",
                "target_label": "IP",
                "relationship": "USED_IP",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
            {
                "source": "oauth_connector_219",
                "source_type": "oauth_token",
                "source_risk": 78,
                "target": "svc_reporting_bot_447",
                "target_label": "Identity",
                "relationship": "MOVED_LATERALLY",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
            {
                "source": "svc_reporting_bot_447",
                "source_type": "service_account",
                "source_risk": 91,
                "target": "185.220.101.55",
                "target_label": "IP",
                "relationship": "USED_IP",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
        ],
        "count": 4,
        "demo_mode": True,
    }


def _build_demo_stats_payload() -> Dict[str, Any]:
    return {
        "identities": 4,
        "resources": 3,
        "incidents": 2,
        "high_risk": 3,
        "demo_mode": True,
    }


# ── Models ────────────────────────────────────────────────────────────────────
class SecurityEvent(BaseModel):
    event_id:            Optional[str]  = None
    time:                Optional[str]  = None
    identity_id:         Optional[str]  = None
    identity_type:       Optional[str]  = "service_account"
    user:                Optional[str]  = None
    src_ip:              Optional[str]  = None
    geo:                 Optional[str]  = None
    event_type:          Optional[str]  = None
    action:              Optional[str]  = None
    endpoint:            Optional[str]  = None
    risk_score:          Optional[float]= 0.0
    bytes_out:           Optional[int]  = 0
    mfa_used:            Optional[bool] = True
    days_since_last_active: Optional[int] = 0
    total_scopes:        Optional[int]  = 0
    context:             Optional[str]  = None
    attack_type:         Optional[str]  = None
    is_anomaly:          Optional[bool] = False

class AnalyzeRequest(BaseModel):
    events:              List[SecurityEvent]
    historical_context:  Optional[List[SecurityEvent]] = []

# ── Helpers ───────────────────────────────────────────────────────────────────
async def _broadcast(msg: dict):
    dead = []
    for ws in WS_CLIENTS:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        WS_CLIENTS.remove(ws)

def _run_pipeline(event_dict: dict, all_events: list, case_id: str) -> dict:
    from agents.agent_pipeline import run_on_event
    return run_on_event(event_dict, all_events, case_id)


def store_case_result(result: dict, event: dict, case_id: str) -> dict:
    alert = result.get("identity_alert") or {}
    threat = result.get("threat_intel") or {}
    resp = result.get("response_actions") or {}

    case = {
        "case_id": case_id,
        "status": "CONTAINED" if result.get("should_escalate") else "CLEARED",
        "risk_level": result.get("risk_level", "LOW"),
        "escalated": bool(result.get("should_escalate")),
        "identity_id": alert.get("identity_id"),
        "identity_type": alert.get("identity_type"),
        "anomalies": alert.get("anomalies_detected", []),
        "identity_explanation": alert.get("llm_explanation", ""),
        "risk_score": alert.get("adjusted_risk_score", 0),
        "mitre_technique": threat.get("primary_technique"),
        "mitre_technique_name": threat.get("primary_technique_name"),
        "mitre_tactic": threat.get("primary_tactic"),
        "threat_assessment": threat.get("threat_assessment", ""),
        "relevant_techniques": [t.get("technique_id") for t in threat.get("relevant_techniques", [])],
        "blast_radius": result.get("correlation", {}).get("blast_radius_score", 0),
        "related_event_count": result.get("correlation", {}).get("related_event_count", 0),
        "attack_narrative": result.get("correlation", {}).get("attack_narrative", ""),
        "correlation": result.get("correlation", {}),
        "affected_identities": result.get("correlation", {}).get("affected_identities", []),
        "response_actions": [p["playbook_name"] for p in resp.get("playbooks_executed", [])],
        "mttc_seconds": resp.get("mttc_seconds", 0),
        "report": result.get("final_report", ""),
        "pipeline_log": result.get("pipeline_log", []),
        "behavior_score": result.get("behavior_score", {}),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "raw_event": event,
    }
    CASES[case_id] = case
    return case

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "AutonomSOC API",
        "version": "2.0.0",
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/health"
    }

@app.get("/health")
def health():
    return {"status": "operational", "version": "2.0.0",
            "timestamp": datetime.utcnow().isoformat()+"Z",
            "components": {"kafka":"configured","neo4j":"configured",
                           "ollama":"configured","chroma":"configured"}}

@app.post("/analyze")
async def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    all_events = [e.model_dump() for e in req.historical_context + req.events]

    for e in all_events:
        if not e.get("event_id"): e["event_id"] = str(uuid.uuid4())
        if not e.get("time"):     e["time"] = datetime.utcnow().isoformat()+"Z"

    target = all_events[-len(req.events):] if req.events else []

    results = []
    for event in target:
        case_id = f"DEMO-SOC-{str(uuid.uuid4())[:8].upper()}"
        try:
            result = _run_pipeline(event, all_events, case_id)
        except Exception as e:
            import traceback
            error_detail = f"{str(e)}\n\n{traceback.format_exc()}"
            print(f"[ERROR] Pipeline failed: {error_detail}")
            raise HTTPException(500, f"Pipeline error: {str(e)}")

        if result is None:
            print(f"[ERROR] Pipeline returned None for case_id={case_id} event={event.get('event_id')}")
            raise HTTPException(500, detail="Pipeline error: result is None")

        alert  = result.get("identity_alert") or {}
        threat = result.get("threat_intel")   or {}
        resp   = result.get("response_actions") or {}

        case = store_case_result(result, event, case_id)
        results.append(case)

        # WebSocket broadcast
        if result["should_escalate"]:
            background_tasks.add_task(_broadcast, {
                "type": "NEW_INCIDENT",
                "case_id": case_id,
                "risk_level": result["risk_level"],
                "identity_id": alert.get("identity_id"),
                "mitre": threat.get("primary_technique"),
                "timestamp": datetime.utcnow().isoformat()+"Z",
            })

    return results

@app.get("/cases")
def list_cases(limit: int = 50, risk_level: Optional[str] = None, escalated: Optional[bool] = None):
    cases = list(CASES.values())
    if risk_level:
        cases = [c for c in cases if c["risk_level"] == risk_level.upper()]
    if escalated is not None:
        cases = [c for c in cases if c["escalated"] == escalated]
    cases.sort(key=lambda c: c["created_at"], reverse=True)
    return {"total": len(CASES), "filtered": len(cases), "cases": cases[:limit]}

@app.get("/cases/{case_id}")
def get_case(case_id: str):
    if case_id not in CASES:
        raise HTTPException(404, f"Case {case_id} not found")
    return CASES[case_id]

@app.get("/cases/{case_id}/report")
def get_report(case_id: str):
    if case_id not in CASES:
        raise HTTPException(404, "Case not found")
    return {"case_id": case_id, "report": CASES[case_id].get("report","")}


@app.get("/cases/{case_id}/export/pdf")
def export_case_pdf(case_id: str):
    """Export full incident report as PDF."""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    try:
        from backend.api.pdf_generator import generate_incident_report_pdf
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generator import error: {e}")

    case = CASES[case_id]
    try:
        pdf_buffer = generate_incident_report_pdf(case)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[ERROR] PDF generation failed for {case_id}: {e}\n{tb}")
        raise HTTPException(status_code=500, detail=f"PDF generation error: {e}")

    pdf_buffer.seek(0)
    filename = f"AutonomSOC-Report-{case_id}.pdf"
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/cases/{case_id}/export/trace")
def export_case_trace_pdf(case_id: str):
    """Export pipeline execution trace as PDF."""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    try:
        from backend.api.pdf_generator import generate_pipeline_trace_pdf
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generator import error: {e}")

    case = CASES[case_id]
    try:
        pdf_buffer = generate_pipeline_trace_pdf(case)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[ERROR] Trace PDF generation failed for {case_id}: {e}\n{tb}")
        raise HTTPException(status_code=500, detail=f"Trace PDF generation error: {e}")

    pdf_buffer.seek(0)
    filename = f"AutonomSOC-Trace-{case_id}.pdf"
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.get("/stats")
def get_stats():
    escalated  = [c for c in CASES.values() if c["escalated"]]
    risk_dist  = {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
    tech_count: Dict[str,int] = {}
    attack_count: Dict[str,int] = {}
    total_mttc = 0

    for c in CASES.values():
        rl = c.get("risk_level","LOW")
        risk_dist[rl] = risk_dist.get(rl,0)+1
    for c in escalated:
        t = c.get("mitre_technique","UNKNOWN")
        tech_count[t] = tech_count.get(t,0)+1
        a = c.get("raw_event",{}).get("attack_type","unknown")
        attack_count[a] = attack_count.get(a,0)+1
        total_mttc += c.get("mttc_seconds",0)

    avg_mttc = total_mttc // max(len(escalated),1)
    total_actions = sum(len(c.get("response_actions",[])) for c in escalated)

    return {
        "total_events_processed": len(CASES),
        "total_escalated":  len(escalated),
        "escalation_rate":  f"{len(escalated)/max(len(CASES),1)*100:.1f}%",
        "risk_breakdown":   risk_dist,
        "top_techniques":   dict(sorted(tech_count.items(),key=lambda x:x[1],reverse=True)[:5]),
        "attack_types":     attack_count,
        "avg_mttc_seconds": avg_mttc,
        "playbooks_executed": total_actions,
        "neo4j_browser":    "http://localhost:7474",
        "kafka_ui":         "http://localhost:8090",
    }

@app.get("/graph/attack")
def get_attack_graph():
    try:
        from attack_graph.neo4j_graph import AttackGraphDB
        db = AttackGraphDB()
        data = db.get_attack_graph(limit=100)
        db.close()
        if data:
            return {"nodes_and_edges": data, "count": len(data)}
    except Exception as e:
        print(f"[Graph] Falling back to demo graph: {e}")

    return _build_demo_graph_payload()

@app.get("/graph/stats")
def get_graph_stats():
    try:
        from attack_graph.neo4j_graph import AttackGraphDB
        db = AttackGraphDB()
        stats = db.get_graph_stats()
        hi = db.get_high_risk_identities(min_risk=70)
        db.close()
        if stats:
            return {**stats, "high_risk_identities": hi[:10]}
    except Exception as e:
        print(f"[Graph] Falling back to demo stats: {e}")

    return _build_demo_stats_payload()

@app.post("/graph/demo")
def load_demo_graph():
    try:
        from attack_graph.neo4j_graph import AttackGraphDB
        db = AttackGraphDB()
        db.load_demo_scenario()
        db.close()
    except Exception as e:
        print(f"[Graph] Demo load skipped: {e}")

    return {"status": "loaded", **_build_demo_graph_payload(), **_build_demo_stats_payload()}

@app.get("/graph/blast-radius/{identity_id}")
def get_blast_radius(identity_id: str):
    try:
        from attack_graph.neo4j_graph import AttackGraphDB
        db = AttackGraphDB()
        result = db.get_blast_radius(identity_id)
        db.close()
        return result
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/mitre/techniques")
def list_mitre():
    from mitre.mitre_engine import MITREEngine
    return MITREEngine().get_all_techniques()

@app.post("/cases/ingest")
def ingest_case(payload: Dict[str, Any]):
    result = payload.get("result", {})
    event = payload.get("event", {})
    case_id = payload.get("case_id") or f"DEMO-{str(uuid.uuid4())[:8].upper()}"
    case = store_case_result(result, event, case_id)
    if case.get("escalated"):
        background_tasks = None
    return {"status": "ingested", "case_id": case_id, "risk_level": case.get("risk_level"), "escalated": case.get("escalated")}

@app.delete("/cases/reset")
def reset():
    CASES.clear()
    return {"status": "cleared", "timestamp": datetime.utcnow().isoformat()+"Z"}

# ── WebSocket for live dashboard ──────────────────────────────────────────────
@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    WS_CLIENTS.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive
    except WebSocketDisconnect:
        WS_CLIENTS.remove(ws)
