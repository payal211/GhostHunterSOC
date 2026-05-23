# 🛡️  GhostHunterSOC: Autonomous NHI Threat Detection and Response
## Agentic AI-Powered Autonomous Security Operations Center
### TCS-Amex GenAI Hackathon 2026 · Cybersecurity Track

---

## ❓ Synthetic Data vs Real Datasets — Which Should You Use?

| Dataset | Pros | Cons | Best For |
|---|---|---|---|
| **Synthetic (default)** | Instant, controllable attack scenarios, CIM-format | Not real attack patterns | Demos, fast iteration |
| **Splunk BOTS v3** | Real APT28 attacks, realistic multi-stage | Requires Splunk BOTS environment to export | Production-like testing |
| **Microsoft MSTIC GUIDE** | Labeled TP/FP/BP incidents, MITRE mapped | Enterprise Azure focus, no NHI-specific | ML triage model training |
| **Awesome-Security-Datasets** | Variety of PCAPs, logs, malware samples | Needs normalization, no IAM focus | Research/exploration |
| **Graylog Open** | Real syslog/audit format | Not IAM-specific | Infrastructure log testing |
| **Wazuh Live** | Real alerts from your own endpoints | Requires deployed Wazuh agents | True production use |
| **MISP Live** | Real IOC feeds (CIRCL, Abuse.ch) | Requires MISP deployment | Threat intel enrichment |

### 🎯 Recommendation for Hackathon:
- **Demo day**: Use **synthetic** — full control, no setup, guaranteed attack scenarios
- **Judges ask about data**: Run **BOTS v3 adapter** — shows real APT pattern knowledge
- **Production POC**: Use **Wazuh + MISP live** — real enterprise integration

---

## 🏗️ Full Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  DATA SOURCES                                                       │
│  Splunk BOTS · Wazuh · MISP · MSTIC · Synthetic Generator           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    Apache Kafka
              (autonomsoc.iam / .nhi / .wazuh)
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│  LANGGRAPH ORCHESTRATOR                                             │
│                                                                     │
│  [Identity Monitor] → [Behavior Analyzer] → [Threat Intel RAG]      │
│                    → [Correlation Agent]  → [Response Agent]        │
│                    → [Reporting Agent]                              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
          ┌────────────────┴────────────────┐
          │                                 │
    Neo4j Graph DB                    TheHive / Shuffle
    (Attack Graph)                    (Incident Response)
          │
    FastAPI REST + WebSocket
          │
    React SOC Dashboard
```

---

## 🚀 Quick Start (One Command)

```bash
# Clone and start everything
git clone https://github.com/your-org/GhostHunterSOC
cd GhostHunterSOC

# 1. Pull Ollama models (one time)
set OLLAMA_HOST="https://localhost:11434"
ollama pull llama3.1
ollama pull mistral
ollama serve
```

Use one startup path. Docker Compose already starts the API and dashboard, so do not also run `uvicorn` and `npm start` on ports 8000/3000 at the same time.

# 2A. Start full Docker Compose stack
```bash
docker-compose -f docker/docker-compose.yml build
docker-compose -f docker/docker-compose.yml up -d
```

# 2B. Or run local API and dashboard instead of Docker Compose
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python data/synthetic_generator.py --events 500 --attack all
python -c "from mitre.mitre_engine import MITREEngine; MITREEngine()"
```

# 4. In another terminal — start API
```bash
uvicorn api.api:app --port 8000
```
or 
```bash
python -m uvicorn api.api:app --port 8000
```

# 5. Start React dashboard
```bash
cd react-dashboard && npm install && npm start
```

# Agent Architecture

![Agent Architecture](diagrams/agent_architecture.png)

### Services after startup:
| Service | URL |
|---|---|
| React Dashboard | http://localhost:3000 |
| API + Swagger | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 |
| Kafka UI | http://localhost:8090 |
| TheHive | http://localhost:9000 |
| ChromaDB | http://localhost:8001 |

---

## 📁 Project Structure

```
GhostHunterSOC/
├── agents/
│   └── agent_pipeline.py              # Root LangGraph 6-agent pipeline used by api/api.py
├── api/
│   └── api.py                         # Root FastAPI REST + WebSocket API
├── attack_graph/
│   └── neo4j_graph.py                 # Root Neo4j attack graph engine
├── backend/
│   ├── api/
│   │   ├── routes.py                  # Alternate backend FastAPI routes
│   │   └── pdf_generator.py           # Incident and trace PDF exports
│   ├── agents/                        # Modular backend agent implementation
│   ├── kafka/                         # Backend Kafka helpers
│   ├── mitre/                         # LLM-based MITRE mapper
│   ├── neo4j/                         # Backend Neo4j graph builder and queries
│   ├── orchestrator/                  # Backend LangGraph orchestration
│   ├── rag/                           # Backend ChromaDB/RAG helpers
│   ├── Dockerfile
│   └── requirements.txt
├── data/
│   └── synthetic_generator.py         # Splunk CIM IAM/NHI log generator
├── docker/
│   ├── docker-compose.yml             # Full local enterprise stack
│   ├── Dockerfile.agents              # Root Python agents + API image
│   ├── Dockerfile.dashboard           # React + Nginx image
│   └── nginx.conf
├── kafka/
│   ├── kafka_producer.py              # Multi-source event producer
│   └── kafka_consumer.py              # Pipeline consumer + TheHive integration
├── k8s/
│   ├── full-stack.yaml
│   └── manifests.yaml                 # Kubernetes deployment manifests
├── mitre/
│   └── mitre_engine.py                # Rule/RAG MITRE ATT&CK mapping engine
├── react-dashboard/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx                    # Router + sidebar + WebSocket
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx          # Live SOC overview
│   │   │   ├── Incidents.jsx          # Incident list + filter
│   │   │   ├── IncidentDetail.jsx     # Full case view + report export
│   │   │   ├── AttackGraph.jsx        # Canvas attack graph visualization
│   │   │   ├── Analysis.jsx           # Run events through pipeline
│   │   │   └── MITREMap.jsx           # MITRE technique browser
│   │   └── store/
│   │       └── alertStore.js          # Zustand live alert store
│   ├── package.json
│   └── package-lock.json
├── .github/
│   └── workflows/
│       └── ci-cd.yml                  # GitHub Actions workflow
├── diagrams/                          # Architecture diagrams
├── .env.example
├── .gitignore
├── quickstart.sh
├── render.yaml                        # Render deployment config
├── requirements.txt                   # Root API/agents dependencies
├── vercel.json                        # Vercel CRA dashboard config
└── README.md
```

---
