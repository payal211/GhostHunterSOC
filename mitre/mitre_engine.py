"""
AutonomSOC — MITRE ATT&CK Mapping Engine + ChromaDB RAG
Maps security events to MITRE techniques using semantic search + rule-based matching.

Sources:
  - Embedded IAM/NHI-specific technique library (always available)
  - ChromaDB vector store (runtime semantic search)
  - Optional: Live MITRE STIX feed from attack.mitre.org

Usage:
    from mitre.mitre_engine import MITREEngine
    engine = MITREEngine()
    result = engine.map_event(event_dict)
"""

import os, json, re
from typing import Dict, List, Optional, Tuple
import chromadb
from chromadb.config import Settings

CHROMA_HOST = os.getenv("CHROMA_HOST", "http://localhost:8001")
CHROMA_LOCAL = "./chroma_db"

# ── Full IAM/NHI MITRE ATT&CK Knowledge Base ─────────────────────────────────
MITRE_KNOWLEDGE_BASE = [
    {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation",
        "severity": "HIGH",
        "text": (
            "Adversaries obtain and abuse credentials of existing cloud accounts. "
            "Service accounts and NHIs are primary targets. "
            "Key indicators: logins from unusual geographies, access outside business hours, "
            "dormant accounts becoming active after 90+ days, privilege escalation attempts, "
            "MFA bypass, impossible travel between geolocations."
        ),
        "remediation": "Disable dormant accounts. Enforce MFA. Rotate all credentials for affected identities.",
        "pci_dss": "PCI DSS 8.2, 8.3 - Identity management and MFA requirements",
        "keywords": ["dormant","inactive","reactivation","unusual geo","off-hours","service account","mfa bypass"],
    },
    {
        "id": "T1558.001",
        "name": "Steal or Forge Kerberos Tickets: Golden Ticket",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "text": (
            "Adversaries with domain admin forge Kerberos TGTs using the KRBTGT account hash. "
            "Signs: TGT tickets with unusually long lifetime, SPN enumeration via LDAP, "
            "authentication from service accounts to sensitive systems, "
            "lateral movement using forged tickets."
        ),
        "remediation": "Reset KRBTGT password twice. Audit all service account SPNs. Force re-authentication.",
        "pci_dss": "PCI DSS 10.2 - Audit trail for privileged access",
        "keywords": ["kerberos","golden ticket","krbtgt","spn","ldap","tgt","ticket","forged"],
    },
    {
        "id": "T1098.001",
        "name": "Account Manipulation: Additional Cloud Credentials",
        "tactic": "Persistence, Privilege Escalation",
        "severity": "HIGH",
        "text": (
            "Adversaries add credentials to cloud accounts for persistence. "
            "OAuth token scope expansion over time is a key indicator. "
            "Monitor for permission grants to service accounts and OAuth applications, "
            "especially admin-level scope additions."
        ),
        "remediation": "Revoke excess OAuth scopes. Enforce least-privilege. Audit all scope grants.",
        "pci_dss": "PCI DSS 7.1 - Least privilege access control",
        "keywords": ["oauth","scope","permission","admin scope","scope creep","privilege","token grant"],
    },
    {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "text": (
            "Adversaries search for credentials stored insecurely in CI/CD pipelines, "
            "code repositories, and configuration files. "
            "API keys exposed in CI/CD pipelines or source code are primary targets. "
            "Indicators: same API key used from multiple external IPs, key appearing in unexpected contexts."
        ),
        "remediation": "Rotate all exposed credentials immediately. Scan repos for secrets. Use secrets management.",
        "pci_dss": "PCI DSS 6.3 - Security of internal application components",
        "keywords": ["api key","ci/cd","pipeline","external","exfil","exposed credential","secret","github"],
    },
    {
        "id": "T1550.003",
        "name": "Use Alternate Authentication Material: Pass the Ticket",
        "tactic": "Lateral Movement, Defense Evasion",
        "severity": "CRITICAL",
        "text": (
            "Adversaries use stolen Kerberos tickets to move laterally without needing passwords. "
            "Indicators: service accounts accessing resources they do not normally access, "
            "authentication events with forged ticket properties, unusual east-west traffic."
        ),
        "remediation": "Force Kerberos ticket expiry. Enable PAC validation. Monitor east-west identity flows.",
        "pci_dss": "PCI DSS 10.2 - Audit privileged access",
        "keywords": ["lateral movement","pass the ticket","kerberos","east-west","pivot","cross-system"],
    },
    {
        "id": "T1136.003",
        "name": "Create Account: Cloud Account",
        "tactic": "Persistence",
        "severity": "HIGH",
        "text": (
            "Adversaries create new cloud accounts to maintain persistent access. "
            "In NHI context: creation of new service accounts, OAuth applications, "
            "or API keys that were not authorized through change management."
        ),
        "remediation": "Audit all identity creation events. Enforce approval workflows for NHI provisioning.",
        "pci_dss": "PCI DSS 8.1 - Identity management processes",
        "keywords": ["new account","create account","new identity","new service account","new api key","provisioning"],
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "severity": "MEDIUM",
        "text": (
            "Adversaries use a single common password against many accounts to avoid lockout. "
            "Indicators: multiple failed authentications across many identities, "
            "low volume per account but high volume overall, common password patterns."
        ),
        "remediation": "Enable account lockout. Enforce MFA. Monitor failed auth patterns.",
        "pci_dss": "PCI DSS 8.3 - Strong authentication requirements",
        "keywords": ["brute force","spray","failed login","authentication failure","lockout","multiple accounts"],
    },
    {
        "id": "T1528",
        "name": "Steal Application Access Token",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "text": (
            "Adversaries steal application access tokens like OAuth tokens to bypass authentication. "
            "These tokens grant access to cloud services without requiring passwords. "
            "Indicators: tokens used from unexpected IPs, token reuse across geolocations."
        ),
        "remediation": "Revoke compromised tokens. Implement token binding. Monitor token usage anomalies.",
        "pci_dss": "PCI DSS 8.3 - Token-based authentication security",
        "keywords": ["token theft","oauth token","access token","bearer token","jwt","token reuse"],
    },
    {
        "id": "NHI-DORMANT",
        "name": "NHI: Dormant Identity Reactivation (Custom)",
        "tactic": "Initial Access, Persistence",
        "severity": "HIGH",
        "text": (
            "Non-Human Identity inactive for 90+ days suddenly becomes active. "
            "Attackers identify dormant accounts with valid, unrotated credentials as low-detection entry points. "
            "Key controls: periodic NHI hygiene reviews, automatic credential rotation after 90 days, "
            "activity-based access reviews."
        ),
        "remediation": "Disable identity. Rotate credentials. Investigate prior 72 hours of activity.",
        "pci_dss": "PCI DSS 8.2.6 - Inactive account management",
        "keywords": ["dormant","inactive","180 days","90 days","forgotten","unmonitored","no baseline"],
    },
    {
        "id": "NHI-EXFIL",
        "name": "NHI: API Key Exfiltration (Custom)",
        "tactic": "Collection, Exfiltration",
        "severity": "CRITICAL",
        "text": (
            "CI/CD pipeline or application API key appears in external traffic context. "
            "Indicates supply chain compromise, insider threat, or secrets leaked via code repository. "
            "Same credential appearing from both internal pipeline context and external IPs is a definitive indicator."
        ),
        "remediation": "Revoke key immediately. Rotate all keys in affected pipeline. Scan all repos for secrets.",
        "pci_dss": "PCI DSS 6.4 - Protection of web-facing applications",
        "keywords": ["api key external","ci/cd external","unknown_external","supply chain","exfiltration","pipeline key"],
    },
]

# ── Rule-Based Fast Mapping ───────────────────────────────────────────────────
EVENT_TYPE_MAP = {
    "ldap_query":         ["T1558.001"],
    "oauth_scope_grant":  ["T1098.001"],
    "api_call":           ["T1552.001", "T1078.004"],
    "authentication":     ["T1078.004", "T1110.003"],
}

ATTACK_TYPE_MAP = {
    "golden_ticket":             "T1558.001",
    "dormant_nhi_reactivation":  "T1078.004",
    "oauth_scope_creep":         "T1098.001",
    "api_key_exfiltration":      "T1552.001",
}

class MITREEngine:

    def __init__(self, use_remote_chroma: bool = False):
        self._kb = {t["id"]: t for t in MITRE_KNOWLEDGE_BASE}
        self._collection = None
        self._init_chroma(use_remote_chroma)

    def _init_chroma(self, use_remote: bool):
        try:
            if use_remote:
                client = chromadb.HttpClient(host=CHROMA_HOST.replace("http://","").split(":")[0],
                                              port=int(CHROMA_HOST.split(":")[-1]))
            else:
                client = chromadb.PersistentClient(path=CHROMA_LOCAL)

            try:
                self._collection = client.get_collection("mitre_threat_intel")
                print(f"[MITRE] Loaded existing ChromaDB collection ({self._collection.count()} docs)")
            except Exception:
                try:
                    self._collection = client.create_collection("mitre_threat_intel")
                    self._seed_collection()
                    print(f"[MITRE] Seeded ChromaDB with {len(MITRE_KNOWLEDGE_BASE)} techniques")
                except Exception as e:
                    # Try to recover if the collection exists but get_collection failed.
                    try:
                        self._collection = client.get_collection("mitre_threat_intel")
                        print(f"[MITRE] Recovered existing ChromaDB collection after create conflict")
                    except Exception:
                        raise
        except Exception as e:
            print(f"[MITRE] ChromaDB unavailable: {e} — using keyword matching only")

    def _seed_collection(self):
        self._collection.add(
            documents=[t["text"] for t in MITRE_KNOWLEDGE_BASE],
            ids=[t["id"] for t in MITRE_KNOWLEDGE_BASE],
            metadatas=[{"tactic": t["tactic"], "severity": t["severity"],
                        "name": t["name"], "pci": t["pci_dss"]}
                       for t in MITRE_KNOWLEDGE_BASE],
        )

    # ── Core Mapping ──────────────────────────────────────────────────────────
    def map_event(self, event: Dict) -> Dict:
        """
        Full mapping pipeline:
        1. Direct attack_type lookup (fastest, most accurate)
        2. Keyword rule matching
        3. ChromaDB semantic search (most flexible)
        Returns ranked list of matching techniques.
        """
        candidates: List[Tuple[str, float]] = []  # (technique_id, confidence)

        # 1. Direct attack type mapping
        attack_type = event.get("attack_type")
        if attack_type and attack_type in ATTACK_TYPE_MAP:
            tid = ATTACK_TYPE_MAP[attack_type]
            candidates.append((tid, 0.99))

        # 2. Event type rule mapping
        event_type = event.get("event_type", "")
        for tid in EVENT_TYPE_MAP.get(event_type, []):
            if not any(c[0]==tid for c in candidates):
                candidates.append((tid, 0.75))

        # 3. Keyword matching against anomalies
        anomaly_text = " ".join(event.get("anomalies_detected", []) +
                                 [str(event.get("alert_name",""))])
        for tech in MITRE_KNOWLEDGE_BASE:
            score = sum(1 for kw in tech["keywords"] if kw.lower() in anomaly_text.lower())
            if score > 0:
                conf = min(0.95, 0.5 + score * 0.12)
                if not any(c[0]==tech["id"] for c in candidates):
                    candidates.append((tech["id"], conf))

        # 4. ChromaDB semantic search
        if self._collection and anomaly_text.strip():
            try:
                query = self._build_rag_query(event)
                results = self._collection.query(query_texts=[query], n_results=3)
                for i, tid in enumerate(results["ids"][0]):
                    conf = max(0.0, 1.0 - results["distances"][0][i]) if results.get("distances") else 0.6
                    if not any(c[0]==tid for c in candidates):
                        candidates.append((tid, conf))
            except Exception as e:
                print(f"[MITRE] ChromaDB query failed: {e}")

        # Sort by confidence, deduplicate, enrich
        candidates.sort(key=lambda x: x[1], reverse=True)
        return self._enrich_results(candidates[:5], event)

    def _build_rag_query(self, event: Dict) -> str:
        parts = []
        if event.get("identity_type"):
            parts.append(f"Identity type: {event['identity_type']}")
        if event.get("event_type"):
            parts.append(f"Event type: {event['event_type']}")
        if event.get("attack_type"):
            parts.append(f"Attack pattern: {event['attack_type']}")
        if event.get("geo") in ["RU","CN","KP","IR","BR"]:
            parts.append("Anomalous geography access")
        if event.get("days_since_last_active", 0) > 90:
            parts.append("Dormant identity reactivation")
        if event.get("context") == "unknown_external":
            parts.append("API key used from external unknown context")
        if event.get("total_scopes", 0) > 2:
            parts.append("OAuth permission scope escalation")
        return ". ".join(parts) if parts else "IAM anomaly detected"

    def _enrich_results(self, candidates: List[Tuple[str,float]], event: Dict) -> Dict:
        techniques = []
        for tid, conf in candidates:
            tech = self._kb.get(tid, {"id": tid, "name": tid, "tactic": "Unknown",
                                       "severity": "MEDIUM", "text": "", "remediation": "",
                                       "pci_dss": "", "keywords": []})
            techniques.append({
                "technique_id": tid,
                "technique_name": tech.get("name", tid),
                "tactic": tech.get("tactic", "Unknown"),
                "severity": tech.get("severity", "MEDIUM"),
                "confidence": round(conf, 3),
                "description": tech.get("text", ""),
                "remediation": tech.get("remediation", ""),
                "pci_dss": tech.get("pci_dss", ""),
                "mitre_url": f"https://attack.mitre.org/techniques/{tid.replace('.','/')}",
            })

        primary = techniques[0] if techniques else {
            "technique_id": "UNKNOWN", "technique_name": "Unknown",
            "tactic": "Unknown", "severity": "LOW", "confidence": 0.0
        }

        return {
            "primary_technique": primary["technique_id"],
            "primary_technique_name": primary["technique_name"],
            "primary_tactic": primary["tactic"],
            "primary_severity": primary["severity"],
            "primary_confidence": primary["confidence"],
            "primary_remediation": primary.get("remediation",""),
            "primary_pci_mapping": primary.get("pci_dss",""),
            "all_techniques": techniques,
            "technique_count": len(techniques),
        }

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        return self._kb.get(technique_id)

    def get_all_techniques(self) -> List[Dict]:
        return list(self._kb.values())