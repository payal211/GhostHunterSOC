"""Agent 6: Reporting Agent — Generates structured incident reports."""

from .state import SOCState
from .llm_config import get_llm


def reporting_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return {**state, "final_report": "No escalation required — event classified as normal activity."}

    log = state["pipeline_log"].copy()
    log.append("[Reporting] Generating incident report...")

    alert = state.get("identity_alert", {})
    behavior = state.get("behavior_score", {})
    threat_intel = state.get("threat_intel", {})
    correlation = state.get("correlation", {})
    response = state.get("response_actions", {})
    event = state["current_event"]

    try:
        llm = get_llm("llama3.1", temperature=0.1)
        prompt = f"""Generate a structured security incident report for a financial services SOC.

INCIDENT SUMMARY:
- Identity: {alert.get('identity_id')}
- Risk Level: {state.get('risk_level')}
- Risk Score: {alert.get('adjusted_risk_score', 'N/A')}/100
- Anomalies: {', '.join(alert.get('anomalies_detected', []))}
- MITRE Technique: {threat_intel.get('primary_technique', 'Unknown')}

THREAT CONTEXT:
{threat_intel.get('threat_assessment', 'N/A')}

ATTACK NARRATIVE:
{correlation.get('attack_narrative', 'N/A')}

RESPONSE TAKEN:
{', '.join([p['playbook_name'] for p in response.get('playbooks_executed', [])])}

Generate a concise incident report with these sections:
## EXECUTIVE SUMMARY (2 sentences for CISO)
## TECHNICAL DETAILS (key IOCs and TTPs)
## IMPACT ASSESSMENT (business risk to Organization)
## ACTIONS TAKEN (what was automated)
## RECOMMENDATIONS (next steps for SOC team)
## COMPLIANCE NOTES (PCI-DSS/SOX implications)"""

        report = llm.invoke(prompt)
        final_report = report.strip()
    except Exception as e:
        final_report = f"""
## EXECUTIVE SUMMARY
A {state.get('risk_level')} severity IAM/NHI threat was detected and automatically contained
for identity {alert.get('identity_id')}. Incident contained in {response.get('mttc_seconds', 90)} seconds.

## TECHNICAL DETAILS
- Event ID: {event.get('event_id')}
- Identity: {alert.get('identity_id')} ({alert.get('identity_type', 'unknown')})
- Risk Score: {alert.get('adjusted_risk_score', 'N/A')}/100
- Anomalies: {'; '.join(alert.get('anomalies_detected', []))}
- MITRE Technique: {threat_intel.get('primary_technique', 'Unknown')}
- Related Events: {correlation.get('related_event_count', 0)}

## IMPACT ASSESSMENT
Blast radius: {correlation.get('blast_radius_score', 0)}/100
Affected identities: {len(correlation.get('affected_identities', []))}
Affected endpoints: {len(correlation.get('affected_endpoints', []))}

## ACTIONS TAKEN
{chr(10).join([f"- {p['playbook_name']}: {p['result']}" for p in response.get('playbooks_executed', [])])}

## COMPLIANCE NOTES
This incident has been auto-logged for PCI-DSS Section 8 (Identity Management) audit requirements.
"""

    log.append("[Reporting] Incident report generated.")
    return {**state, "final_report": final_report, "pipeline_log": log}