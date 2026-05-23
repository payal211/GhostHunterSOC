"""Agent 5: Response Agent — Selects and simulates SOAR playbook execution."""

from datetime import datetime
from .state import SOCState


def response_agent(state: SOCState) -> SOCState:
    if not state.get("should_escalate"):
        return state

    event = state["current_event"]
    risk_level = state.get("risk_level", "MEDIUM")
    log = state["pipeline_log"].copy()
    log.append("[Response] Selecting automated playbook...")

    identity_id = event.get("identity_id") or event.get("user")
    identity_type = event.get("identity_type", "unknown")
    attack_type = event.get("attack_type")

    PLAYBOOKS = {
        "rotate_credential": {
            "name": "Credential Rotation",
            "action": f"EXECUTED: Rotated credential for {identity_id}. New credential issued. Old token invalidated.",
            "severity": ["HIGH", "CRITICAL"],
            "applicable_to": ["api_key", "service_account", "oauth_token"],
        },
        "disable_account": {
            "name": "Account Suspension",
            "action": f"EXECUTED: Suspended account {identity_id} pending investigation.",
            "severity": ["CRITICAL"],
            "applicable_to": ["service_account", "human"],
        },
        "revoke_oauth_scopes": {
            "name": "OAuth Scope Revocation",
            "action": f"EXECUTED: Revoked excess OAuth scopes for {identity_id}. Reset to minimum required.",
            "severity": ["MEDIUM", "HIGH", "CRITICAL"],
            "applicable_to": ["oauth_token"],
        },
        "block_ip": {
            "name": "IP Block",
            "action": f"EXECUTED: Blocked source IP {event.get('src_ip')} at perimeter firewall.",
            "severity": ["HIGH", "CRITICAL"],
            "applicable_to": ["api_key", "service_account", "oauth_token", "human"],
        },
        "force_mfa": {
            "name": "Force MFA Re-Authentication",
            "action": f"EXECUTED: Forced MFA re-authentication for {identity_id}. Session invalidated.",
            "severity": ["MEDIUM", "HIGH", "CRITICAL"],
            "applicable_to": ["human", "service_account"],
        },
        "alert_owner": {
            "name": "Notify Identity Owner",
            "action": f"EXECUTED: Notified owner of {identity_id} via Slack + Email. Ticket created in ServiceNow.",
            "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "applicable_to": ["api_key", "service_account", "oauth_token", "human"],
        },
        "quarantine_network": {
            "name": "Network Quarantine",
            "action": f"EXECUTED: Quarantined network segment associated with {identity_id}.",
            "severity": ["CRITICAL"],
            "applicable_to": ["service_account"],
        },
    }

    selected = []
    for pb_id, pb in PLAYBOOKS.items():
        if risk_level in pb["severity"] and identity_type in pb["applicable_to"]:
            selected.append({
                "playbook_id": pb_id,
                "playbook_name": pb["name"],
                "result": pb["action"],
                "executed_at": datetime.utcnow().isoformat() + "Z",
                "automated": risk_level in ["HIGH", "CRITICAL"],
            })

    if attack_type == "dormant_nhi_reactivation":
        selected = [p for p in selected if p["playbook_id"] in ["rotate_credential", "disable_account", "alert_owner"]]
    elif attack_type == "oauth_scope_creep":
        selected = [p for p in selected if p["playbook_id"] in ["revoke_oauth_scopes", "alert_owner"]]
    elif attack_type == "api_key_exfiltration":
        selected = [p for p in selected if p["playbook_id"] in ["rotate_credential", "block_ip", "alert_owner"]]

    selected = selected[:3]

    response_summary = {
        "playbooks_executed": selected,
        "actions_count": len(selected),
        "automated": risk_level in ["HIGH", "CRITICAL"],
        "mttc_seconds": 90 if risk_level == "CRITICAL" else 180,
        "human_review_required": risk_level == "CRITICAL",
    }

    log.append(f"[Response] Executed {len(selected)} playbooks | MTTC: {response_summary['mttc_seconds']}s")
    return {**state, "response_actions": response_summary, "pipeline_log": log}