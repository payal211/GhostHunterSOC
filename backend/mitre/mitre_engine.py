"""
AutonomSOC — LLM-Based MITRE ATT&CK Mapping Engine
UPGRADED from rule-based to full LLM reasoning.

The original mitre_engine.py used hardcoded dictionaries like:
    "attack_types": ["dormant_nhi_reactivation"]
to map events to techniques. This is a rule, not reasoning.

This version sends the raw event to the Ollama LLM with full MITRE
context and asks it to reason from first principles — no hardcoded maps.

Backends supported: Ollama (default), Anthropic, OpenAI
"""

import json
import os
import re
import time
import requests
from typing import Dict, List, Optional, Any


# ── LLM Configuration ────────────────────────────────────────────────────────
OLLAMA_HOST  = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")

ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_KEY    = os.getenv("OPENAI_API_KEY",    "")

# ── MITRE Knowledge Base injected as LLM context ─────────────────────────────
MITRE_CONTEXT = """
You are an expert in MITRE ATT&CK for IAM and Non-Human Identity (NHI) security
at financial institutions. You know these techniques deeply:

T1078.004 — Valid Accounts: Cloud Accounts
  Tactic: Initial Access, Defense Evasion, Persistence, Privilege Escalation | Severity: HIGH
  Indicators: dormant NHI (90+ days), unusual geo (RU/CN/KP/IR/NG/BR), MFA bypass,
  off-hours access, service accounts hitting payment APIs.
  PCI-DSS: 8.2, 8.3

T1558.001 — Golden Ticket (Kerberos Forging)
  Tactic: Credential Access | Severity: CRITICAL
  Indicators: LDAP SPN enumeration targeting krbtgt, service account auth from external IP at night,
  forged TGT long-lifetime, east-west lateral movement.
  PCI-DSS: 10.2

T1098.001 — Account Manipulation: Additional Cloud Credentials
  Tactic: Persistence, Privilege Escalation | Severity: HIGH
  Indicators: OAuth token scope expansion over multiple days, admin-level scope grants
  (admin:config, admin:users), total_scopes > 3.
  PCI-DSS: 7.1

T1552.001 — Unsecured Credentials: Credentials In Files
  Tactic: Credential Access | Severity: CRITICAL
  Indicators: CI/CD pipeline API key in context=unknown_external, same key used from
  both internal pipeline IP and external IP, large bytes_out.
  PCI-DSS: 6.3

T1550.003 — Pass the Ticket (Lateral Movement)
  Tactic: Lateral Movement, Defense Evasion | Severity: CRITICAL
  Indicators: service account accessing internal admin resources it never accessed before,
  east-west pivot, auth without corresponding LDAP bind.
  PCI-DSS: 10.2

T1110.003 — Brute Force: Password Spraying
  Tactic: Credential Access | Severity: MEDIUM
  Indicators: multiple auth failures across many accounts, low rate per account.
  PCI-DSS: 8.3

T1528 — Steal Application Access Token
  Tactic: Credential Access | Severity: HIGH
  Indicators: OAuth bearer token from unexpected geo, token reuse across IPs.
  PCI-DSS: 8.3

NHI-DORMANT — Dormant NHI Reactivation (Financial Custom)
  Tactic: Initial Access | Severity: HIGH
  Indicators: identity inactive 90+ days, external IP, no MFA, payment API access.
  PCI-DSS: 8.2.6

NHI-EXFIL — API Key Exfiltration (Financial Custom)
  Tactic: Collection, Exfiltration | Severity: CRITICAL
  Indicators: CI/CD key in unknown_external context, same key from internal+external simultaneously.
  PCI-DSS: 6.4

Always respond with VALID JSON ONLY. No markdown fences."""

RESPONSE_SCHEMA = """{
  "primary_technique":      "T1078.004",
  "primary_technique_name": "Valid Accounts: Cloud Accounts",
  "primary_tactic":         "Initial Access",
  "primary_severity":       "HIGH",
  "primary_confidence":     0.95,
  "primary_reasoning":      "2-3 sentences WHY this technique matches these specific indicators",
  "primary_remediation":    "Specific actionable steps for this exact event",
  "primary_pci_mapping":    "PCI-DSS 8.2, 8.3",
  "secondary_techniques": [
    {"technique_id": "T1550.003", "technique_name": "Pass the Ticket", "confidence": 0.60}
  ],
  "threat_narrative":      "3-4 sentence threat assessment for the SOC",
  "urgency":               "CRITICAL",
  "false_positive_risk":   "LOW"
}"""


# ── LLM Clients ──────────────────────────────────────────────────────────────

def _call_ollama(prompt: str, system: str, max_tokens: int = 1000) -> str:
    """Calls Ollama /api/chat endpoint."""
    r = requests.post(
        f"{OLLAMA_HOST}/api/chat",
        json={
            "model":   OLLAMA_MODEL,
            "stream":  False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            "options": {"temperature": 0.1, "num_predict": max_tokens},
        },
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["message"]["content"].strip()


def _call_anthropic(prompt: str, system: str, max_tokens: int = 1000) -> str:
    """Calls Anthropic claude-sonnet-4-20250514."""
    if not ANTHROPIC_KEY:
        raise ValueError("ANTHROPIC_API_KEY not set")
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"},
        json={"model": "claude-sonnet-4-20250514", "max_tokens": max_tokens,
              "system": system, "messages": [{"role": "user", "content": prompt}]},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["content"][0]["text"].strip()


def _call_openai(prompt: str, system: str, max_tokens: int = 1000) -> str:
    """Calls OpenAI gpt-4o."""
    if not OPENAI_KEY:
        raise ValueError("OPENAI_API_KEY not set")
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"},
        json={"model": "gpt-4o", "max_tokens": max_tokens, "temperature": 0.1,
              "response_format": {"type": "json_object"},
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": prompt}]},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def _parse_json(raw: str) -> Dict:
    """Strips markdown fences and parses JSON."""
    clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', clean, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {"parse_error": True, "raw": raw[:300]}


def _call_llm(prompt: str, backend: str = "ollama") -> str:
    """Routes to correct LLM backend."""
    if backend == "anthropic":
        return _call_anthropic(prompt, MITRE_CONTEXT)
    elif backend == "openai":
        return _call_openai(prompt, MITRE_CONTEXT)
    else:
        return _call_ollama(prompt, MITRE_CONTEXT)


# ── Public API ────────────────────────────────────────────────────────────────

class MITREMapper:
    """
    LLM-powered MITRE ATT&CK mapper.
    Zero hardcoded rules — LLM reasons from event indicators.
    """

    def __init__(self, backend: str = "ollama"):
        self.backend = backend
        print(f"[MITREMapper] Backend: {backend} | Model: {OLLAMA_MODEL if backend=='ollama' else backend}")

    def map_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a security event to MITRE techniques via LLM reasoning."""
        prompt = (
            f"Analyse this security event from American Express and map to MITRE ATT&CK.\n\n"
            f"EVENT:\n{json.dumps(event, indent=2)}\n\n"
            f"Respond with ONLY this JSON schema:\n{RESPONSE_SCHEMA}"
        )
        t0  = time.time()
        raw = _call_llm(prompt, self.backend)
        result = _parse_json(raw)
        result["_latency_sec"] = round(time.time() - t0, 2)
        result["_model"]       = OLLAMA_MODEL if self.backend == "ollama" else self.backend
        return result

    def quick_triage(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Fast single-call pre-filter. Returns is_attack + primary_technique only."""
        prompt = f"""Quick triage: Is this a security attack or normal activity?

Event summary:
- identity_type: {event.get('identity_type','?')}
- geo: {event.get('geo','?')}
- risk_score: {event.get('risk_score',0)}
- bytes_out: {event.get('bytes_out',0)}
- mfa_used: {event.get('mfa_used','?')}
- days_dormant: {event.get('days_since_last_active',0)}
- context: {event.get('context','normal')}

Respond with ONLY this JSON:
{{"is_attack": true, "risk_level": "HIGH", "primary_technique": "T1078.004", "confidence": 0.92, "reason": "one sentence"}}"""
        raw = _call_llm(prompt, self.backend)
        return _parse_json(raw)

    def get_kill_chain(self, events: List[Dict]) -> List[Dict]:
        """Maps a sequence of events to their MITRE techniques (kill chain)."""
        chain = []
        for ev in events:
            result = self.map_event(ev)
            if not result.get("parse_error"):
                chain.append({
                    "event_id":  ev.get("event_id"),
                    "timestamp": ev.get("time"),
                    "technique": result.get("primary_technique"),
                    "tactic":    result.get("primary_tactic"),
                    "severity":  result.get("primary_severity"),
                })
        return sorted(chain, key=lambda x: x.get("timestamp") or "")

    def get_tactic_coverage(self, events: List[Dict]) -> Dict[str, int]:
        """Returns count of events per MITRE tactic across a set of events."""
        counts: Dict[str, int] = {}
        for ev in events:
            result = self.map_event(ev)
            tactic = result.get("primary_tactic", "Unknown")
            counts[tactic] = counts.get(tactic, 0) + 1
        return counts
