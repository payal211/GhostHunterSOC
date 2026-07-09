from api.api import CASES, store_case_result


def test_store_case_result_persists_escalated_incident():
    CASES.clear()

    event = {
        "identity_id": "svc-test-001",
        "attack_type": "test_attack",
    }
    result = {
        "should_escalate": True,
        "risk_level": "HIGH",
        "identity_alert": {
            "identity_id": "svc-test-001",
            "identity_type": "service_account",
            "anomalies_detected": ["suspicious_login"],
            "adjusted_risk_score": 82,
            "llm_explanation": "Suspicious service account pattern",
        },
        "threat_intel": {
            "primary_technique": "T1078",
            "primary_technique_name": "Valid Accounts",
            "primary_tactic": "TA0001",
            "threat_assessment": "elevated",
            "relevant_techniques": [{"technique_id": "T1078"}],
        },
        "response_actions": {
            "playbooks_executed": [{"playbook_name": "Isolate Host"}],
            "mttc_seconds": 45,
        },
        "correlation": {
            "blast_radius_score": 3,
            "related_event_count": 2,
            "attack_narrative": "Lateral movement detected",
            "affected_identities": ["svc-test-001"],
        },
        "final_report": "Test incident report",
        "pipeline_log": ["step one"],
        "behavior_score": {},
    }

    case = store_case_result(result, event, "TEST-CASE-1")

    assert case["case_id"] == "TEST-CASE-1"
    assert CASES["TEST-CASE-1"]["risk_level"] == "HIGH"
    assert CASES["TEST-CASE-1"]["escalated"] is True
    assert CASES["TEST-CASE-1"]["response_actions"] == ["Isolate Host"]
