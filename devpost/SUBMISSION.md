# AutonomSOC — Devpost Submission Package
# TCS-Amex GenAI (Agentic AI) Hackathon 2026

## PROJECT NAME
AutonomSOC — Ghost Identity Hunter

## TAGLINE
Agentic AI-Powered Autonomous Security Operations Center for IAM & Non-Human Identity Threats

## ONE-LINE PITCH
AutonomSOC is an AI-powered autonomous SOC platform for detecting and responding to
compromised Non-Human Identities using real-time streaming, graph intelligence, and
multi-agent AI — reducing mean-time-to-investigate from hours to 90 seconds.

---

## WHAT IT DOES

AutonomSOC is a next-generation autonomous Security Operations Center platform built
specifically for detecting and responding to Identity and Non-Human Identity (NHI) threats
in a financial services environment like American Express.

Modern enterprises manage thousands of NHIs — service accounts, API keys, OAuth tokens,
CI/CD bots, and cloud identities — that are routinely overprivileged, forgotten, and
completely unmonitored. When these identities are compromised, attackers can move laterally
for days before detection.

AutonomSOC deploys six specialized AI agents that autonomously:
1. Monitor every IAM and NHI event in real time via Kafka streaming
2. Build behavioral baselines and score deviations per identity
3. Enrich alerts with MITRE ATT&CK context using ChromaDB RAG
4. Correlate isolated events into complete attack narratives
5. Execute SOAR playbooks (rotate tokens, block IPs, suspend accounts)
6. Generate PCI-DSS/SOX-compliant incident reports

The platform includes a Neo4j attack graph that visualizes identity relationships and
blast radius, enabling analysts to understand attacker movement instantly.

---

## HOW WE BUILT IT

### Architecture
```
Data Sources → Apache Kafka → 6 AI Agents (LangGraph) → Neo4j Graph → Response Engine → React Dashboard
```

### AI Layer
- **LangGraph**: Stateful multi-agent orchestration with typed state passing between agents
- **Ollama (On-Prem)**: LLaMA 3.1 8B, Mixtral 8x7B, Mistral 7B — zero cloud dependency
- **ChromaDB RAG**: MITRE ATT&CK STIX data indexed for semantic threat intel retrieval
- **LlamaIndex**: Document ingestion pipeline for threat intelligence knowledge base

### Security Stack
- **Apache Kafka**: Real-time event streaming from multiple SIEM sources
- **Neo4j**: Attack graph database with APOC and GDS plugins for path analysis
- **MITRE ATT&CK**: Full IAM/NHI technique mapping engine
- **FastAPI**: REST API with WebSocket support for live dashboard updates

### SOC Tool Integrations
- **Wazuh**: Open-source SIEM/XDR for real alert ingestion
- **MISP**: Threat intelligence platform IOC enrichment
- **TheHive**: Incident response case management integration
- **Shuffle SOAR**: Workflow automation for playbook execution

### Frontend
- **React + Zustand**: Live SOC dashboard with real-time WebSocket alerts
- **Canvas force-layout**: Custom attack graph visualization (no external library)
- **5 pages**: Dashboard, Incidents, Attack Graph, Analysis, MITRE Map

### Dataset Support
- **Synthetic**: Custom Splunk CIM-format generator with 4 attack scenarios
- **BOTS v3**: Splunk Boss of the SOC dataset adapter
- **Microsoft MSTIC GUIDE**: Incident prediction dataset adapter
- **Wazuh / MISP**: Live threat feed adapters

### Infrastructure
- **Docker Compose**: Full enterprise stack (Kafka, Neo4j, Ollama, ChromaDB, Wazuh, MISP, TheHive)
- **Kubernetes**: Production-grade manifests with HPA and Ingress
- **GitHub Actions**: Full CI/CD pipeline with security scanning

---

## CHALLENGES I RAN INTO

1. **LangGraph state typing**: Getting TypedDict to work cleanly across 6 agents with
   optional fields required careful design of the SOCState schema.

2. **Neo4j blast radius queries**: The APOC subgraph traversal needed tuning to avoid
   full graph scans on large identity datasets.

3. **Ollama latency**: Running Mixtral 8x7B on CPU is slow — we implemented model routing
   so fast agents use Mistral 7B and only correlation uses the larger model.

4. **Real dataset normalization**: BOTS v3 and MSTIC datasets have completely different
   schemas — the adapter pattern solved this cleanly without touching the pipeline.

---

## ACCOMPLISHMENTS

- Full 6-agent LangGraph pipeline running end-to-end
- 100% on-premise LLM stack — no API keys, no cloud cost
- Neo4j attack graph with real relationship traversal
- 4 complete attack scenarios with realistic detection and response
- MITRE ATT&CK mapping with ChromaDB semantic search
- React SOC dashboard with live WebSocket alerts
- Docker Compose stack bringing up 12 services with one command
- TheHive integration for real incident case creation
- PCI-DSS/SOX auto-compliance documentation per incident

---

## WHAT WE LEARNED

- NHI security is genuinely underserved — most SIEM tools treat machine identities
  as second-class citizens
- LangGraph's stateful graph model is significantly better than linear chains
  for complex multi-agent pipelines where agents need context from prior agents
- Neo4j's APOC path traversal is uniquely suited for blast radius calculation —
  no other database handles this as naturally
- On-premise LLMs are production-viable for classification tasks; the speed
  penalty is acceptable when data sovereignty is non-negotiable

---

## WHAT'S NEXT

- Real-time Wazuh agent deployment for live alert ingestion
- LLM fine-tuning on BOTS v3 dataset for higher-precision IAM triage
- OAuth flow for multi-tenant SOC team access
- Scheduled NHI hygiene reports (dormant account cleanup automation)
- Integration with CyberArk / HashiCorp Vault for automated secrets rotation
- SOC co-pilot mode: human-in-the-loop for CRITICAL risk incidents

---

## BUILT WITH
langchain · langgraph · ollama · llama3.1 · mixtral · chromadb · llamaindex ·
neo4j · apache-kafka · fastapi · react · zustand · docker · kubernetes ·
wazuh · misp · thehive · shuffle · python · javascript · mitre-attck

---

## TEAM
- Tech Lead + Architect (9yr Cybersecurity + AI/LLM + Agentic AI)
- AI / ML Engineer
- Security Analyst
- Full Stack Developer

---

## VIDEO DEMO SCRIPT (2 minutes)

0:00 — Problem: Show the NHI sprawl stat (10K+ vs 1K humans)
0:20 — Architecture overview: Logs → Kafka → 6 Agents → Neo4j → Dashboard
0:40 — Demo Scenario 1: Dormant NHI — show the 90-second containment
1:00 — Demo Scenario 2: API Key Exfiltration — show attack graph in Neo4j
1:20 — Show React dashboard: live incidents, risk distribution, MITRE map
1:40 — Show the auto-generated PCI-DSS incident report
1:55 — Closing: "From reactive monitoring to autonomous response"

---

## LINKS
- GitHub: https://github.com/your-org/autonomsoc
- Demo Video: [YouTube link]
- Live Demo: [Render/Vercel deployment link]
- API Docs: [Swagger UI link]
