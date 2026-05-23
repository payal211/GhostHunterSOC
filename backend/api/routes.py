"""FastAPI Backend — REST API exposing the multi-agent pipeline."""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import uuid
from datetime import datetime

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.graph import build_pipeline
from agents.state import SOCState
from api.pdf_generator import generate_incident_report_pdf, generate_pipeline_trace_pdf

app = FastAPI(
    title="AutonomSOC API",
    description="Agentic AI-Powered Autonomous Security Operations Center",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8501", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

CASES: Dict[str, Dict] = {}
WS_CLIENTS: List[WebSocket] = []
pipeline = build_pipeline()


class SecurityEvent(BaseModel):
    event_id: Optional[str] = None
    time: Optional[str] = None
    identity_id: Optional[str] = None
    identity_type: Optional[str] = "service_account"
    user: Optional[str] = None
    src_ip: Optional[str] = None
    geo: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    endpoint: Optional[str] = None
    risk_score: Optional[float] = 0.0
    bytes_out: Optional[int] = 0
    mfa_used: Optional[bool] = True
    days_since_last_active: Optional[int] = 0
    attack_type: Optional[str] = None
    is_anomaly: Optional[bool] = False
    additional_context: Optional[Dict[str, Any]] = {}


class AnalyzeRequest(BaseModel):
    events: List[SecurityEvent]
    historical_context: Optional[List[SecurityEvent]] = []


class CaseResponse(BaseModel):
    case_id: str
    status: str
    risk_level: str
    escalated: bool
    identity_id: Optional[str]
    anomalies: List[str]
    mitre_technique: Optional[str]
    response_actions: List[str]
    created_at: str


@app.get("/health")
async def health_check():
    return {
        "status": "operational",
        "service": "AutonomSOC",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agents": [
            "IdentityMonitor", "BehaviorAnalyzer", "ThreatIntelRAG",
            "CorrelationAgent", "ResponseAgent", "ReportingAgent",
        ],
    }


@app.post("/analyze", response_model=List[CaseResponse])
async def analyze_events(request: AnalyzeRequest):
    all_events = [e.model_dump() for e in request.historical_context + request.events]
    target_events = [e.model_dump() for e in request.events]

    for e in all_events:
        if not e.get("event_id"):
            e["event_id"] = str(uuid.uuid4())
        if not e.get("time"):
            e["time"] = datetime.utcnow().isoformat() + "Z"

    cases = []
    for event in target_events:
        case_id = f"DEMO-SOC-{str(uuid.uuid4())[:8].upper()}"
        initial_state: SOCState = {
            "raw_events": all_events,
            "current_event": event,
            "identity_alert": None,
            "behavior_score": None,
            "threat_intel": None,
            "correlation": None,
            "response_actions": None,
            "final_report": None,
            "risk_level": "LOW",
            "should_escalate": False,
            "case_id": case_id,
            "pipeline_log": [],
        }

        try:
            result = pipeline.invoke(initial_state)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

        alert = result.get("identity_alert") or {}
        threat = result.get("threat_intel") or {}
        response = result.get("response_actions") or {}

        case = {
            "case_id": case_id,
            "status": "CONTAINED" if result["should_escalate"] else "CLEARED",
            "risk_level": result["risk_level"],
            "escalated": result["should_escalate"],
            "identity_id": alert.get("identity_id"),
            "anomalies": alert.get("anomalies_detected", []),
            "mitre_technique": threat.get("primary_technique"),
            "response_actions": [p["playbook_name"] for p in response.get("playbooks_executed", [])],
            "report": result.get("final_report", ""),
            "pipeline_log": result.get("pipeline_log", []),
            "behavior_score": result.get("behavior_score", {}),
            "correlation": result.get("correlation", {}),
            "created_at": datetime.utcnow().isoformat() + "Z",
        }

        CASES[case["case_id"]] = case
        cases.append(CaseResponse(**{k: v for k, v in case.items() if k in CaseResponse.model_fields}))

    return cases


@app.get("/cases")
async def list_cases(limit: int = 50):
    return {"total": len(CASES), "cases": list(CASES.values())[-limit:]}


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return CASES[case_id]


@app.get("/cases/{case_id}/report")
async def get_report(case_id: str):
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "report": CASES[case_id].get("report", "No report available")}


@app.get("/stats")
async def get_stats():
    escalated = [c for c in CASES.values() if c["escalated"]]
    risk_breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for c in CASES.values():
        risk_breakdown[c["risk_level"]] = risk_breakdown.get(c["risk_level"], 0) + 1

    technique_counts = {}
    for c in escalated:
        t = c.get("mitre_technique", "UNKNOWN")
        technique_counts[t] = technique_counts.get(t, 0) + 1

    return {
        "total_events_processed": len(CASES),
        "total_escalated": len(escalated),
        "escalation_rate": f"{len(escalated)/max(len(CASES),1)*100:.1f}%",
        "risk_breakdown": risk_breakdown,
        "top_techniques": technique_counts,
        "avg_mttc_seconds": 90,
        "playbooks_executed": sum(len(c.get("response_actions", [])) for c in escalated),
    }


@app.delete("/cases/reset")
async def reset_cases():
    CASES.clear()
    return {"status": "cleared"}


# ── PDF Export Endpoints ──────────────────────────────────────────────────────
@app.get("/cases/{case_id}/export/pdf")
async def export_case_pdf(case_id: str):
    """Export full incident report as PDF."""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    
    case = CASES[case_id]
    pdf_buffer = generate_incident_report_pdf(case)
    pdf_buffer.seek(0)
    
    filename = f"AutonomSOC-Report-{case_id}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/cases/{case_id}/export/trace")
async def export_case_trace_pdf(case_id: str):
    """Export pipeline execution trace as PDF."""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    
    case = CASES[case_id]
    pdf_buffer = generate_pipeline_trace_pdf(case)
    pdf_buffer.seek(0)
    
    filename = f"AutonomSOC-Trace-{case_id}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


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