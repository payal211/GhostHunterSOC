"""ChromaDB + LlamaIndex RAG — Threat intelligence vector store and query engine."""

import chromadb
from chromadb.config import Settings


def setup_chroma(persist_dir: str = "./chroma_db") -> chromadb.Collection:
    """Sets up ChromaDB with MITRE ATT&CK threat intel."""
    client = chromadb.PersistentClient(path=persist_dir)

    try:
        collection = client.get_collection("mitre_threat_intel")
        print("[ChromaDB] Loaded existing threat intel collection.")
    except Exception:
        collection = client.create_collection("mitre_threat_intel")
        _seed_threat_intel(collection)
        print("[ChromaDB] Seeded new threat intel collection.")

    return collection


def _seed_threat_intel(collection: chromadb.Collection):
    """Seeds ChromaDB with MITRE ATT&CK IAM/NHI relevant techniques."""
    intel_docs = [
        {
            "id": "T1078.004",
            "text": (
                "Valid Accounts: Cloud Accounts (T1078.004). Adversaries obtain credentials for cloud accounts "
                "and use them to access cloud services. Service accounts and NHIs are primary targets. "
                "Indicators: logins from unusual geographies, access outside business hours, "
                "dormant accounts becoming active, privilege escalation attempts."
            ),
            "tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation",
        },
        {
            "id": "T1558.001",
            "text": (
                "Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001). Adversaries with domain admin "
                "forge Kerberos TGTs using the KRBTGT account hash. Signs: TGT tickets with unusually long "
                "lifetime, SPN enumeration via LDAP, authentication from service accounts to sensitive systems."
            ),
            "tactic": "Credential Access",
        },
        {
            "id": "T1098.001",
            "text": (
                "Account Manipulation: Additional Cloud Credentials (T1098.001). Adversaries add credentials "
                "to cloud accounts for persistence. OAuth token scope expansion over time is a key indicator. "
                "Monitor for permission grants to service accounts and OAuth applications."
            ),
            "tactic": "Persistence, Privilege Escalation",
        },
        {
            "id": "T1552.001",
            "text": (
                "Unsecured Credentials: Credentials In Files (T1552.001). Adversaries search for credentials "
                "in file systems and repositories. API keys exposed in CI/CD pipelines or code repositories "
                "are primary targets. Indicators: same API key used from multiple external IPs."
            ),
            "tactic": "Credential Access",
        },
        {
            "id": "T1550.003",
            "text": (
                "Use Alternate Authentication Material: Pass the Ticket (T1550.003). Adversaries use stolen "
                "Kerberos tickets to move laterally. Indicators: service accounts accessing resources they "
                "do not normally access, authentication events with forged ticket properties."
            ),
            "tactic": "Lateral Movement, Defense Evasion",
        },
        {
            "id": "NHI-001",
            "text": (
                "Non-Human Identity Abuse Pattern: Dormant service accounts reactivated after 90+ days indicate "
                "potential compromise. Attackers identify dormant accounts with valid credentials to avoid "
                "detection. Key controls: periodic NHI hygiene, automatic credential rotation, access reviews."
            ),
            "tactic": "Initial Access, Persistence",
        },
        {
            "id": "NHI-002",
            "text": (
                "API Key Exfiltration Pattern: CI/CD pipeline API keys appearing in external traffic indicates "
                "supply chain compromise or insider threat. Monitor for same credential used from internal "
                "pipeline context and external IP addresses simultaneously."
            ),
            "tactic": "Collection, Exfiltration",
        },
        {
            "id": "PCI-IAM-001",
            "text": (
                "PCI DSS 8.x Identity Management Requirements: All service accounts must be inventoried, "
                "MFA enforced where technically feasible, privileged access reviewed quarterly. "
                "NHI credentials must be rotated at least annually. Inactive accounts disabled after 90 days."
            ),
            "tactic": "Compliance",
        },
    ]

    collection.add(
        documents=[d["text"] for d in intel_docs],
        ids=[d["id"] for d in intel_docs],
        metadatas=[{"tactic": d["tactic"], "id": d["id"]} for d in intel_docs],
    )
    print(f"[ChromaDB] Seeded {len(intel_docs)} threat intel documents.")


def query_threat_intel(collection: chromadb.Collection, query: str, n_results: int = 3):
    """Query the threat intel collection."""
    results = collection.query(query_texts=[query], n_results=n_results)
    docs = []
    for i, doc in enumerate(results["documents"][0]):
        docs.append({
            "technique_id": results["ids"][0][i],
            "content": doc,
            "tactic": results["metadatas"][0][i].get("tactic", "Unknown"),
        })
    return docs