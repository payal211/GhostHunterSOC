# Sample for Swagger UI (http://127.0.0.1:8000/docs#/default/analyze_analyze_post)

1. Request Body
```
{
  "events": [
    {
      "identity_id": "svc_reporting_bot_447",
      "identity_type": "service_account",
      "src_ip": "185.220.101.55",
      "geo": "RU",
      "event_type": "api_call",
      "endpoint": "/api/v2/transactions",
      "risk_score": 88,
      "bytes_out": 485000,
      "mfa_used": false,
      "days_since_last_active": 243,
      "is_anomaly": true,
      "attack_type": "dormant_nhi_reactivation"
    }
  ],
  "historical_context": []
}
```

{
  "events": [
    {
      "identity_id": "svc_reporting_bot_447",
      "identity_type": "service_account",
      "src_ip": "185.220.101.55",
      "geo": "RU",
      "event_type": "api_call",
      "endpoint": "/api/v2/transactions",
      "risk_score": 66,
      "bytes_out": 180000,
      "mfa_used": false,
      "days_since_last_active": 42,
      "is_anomaly": true,
      "attack_type": "unusual_access_pattern"
    }
  ],
  "historical_context": []
}
```
This is a medium-severity example: the account is suspicious, but the activity is not yet a full exfiltration or privilege escalation.


2. Example Response:
```
[
  {
    "case_id": "DEMO-SOC-XXXXXXXX",
    "status": "CONTAINED",
    "risk_level": "CRITICAL",
    "escalated": true,
    "identity_id": "svc_reporting_bot_447",
    "identity_type": "service_account",
    "anomalies": [
      "ANOMALOUS_GEO: RU is high-risk country",
      "DORMANT_IDENTITY: 243 days inactive",
      "LARGE_TRANSFER: 485,000 bytes exfiltrated"
    ],
    "risk_score": 100,
    "mitre_technique": "T1078.004",
    "mitre_technique_name": "Valid Accounts: Cloud Accounts",
    "mitre_tactic": "Initial Access, Defense Evasion, Persistence, Privilege Escalation",
    "blast_radius": 0,
    "affected_identities": [],
    "response_actions": [
      "Credential Rotation",
      "Account Suspension",
      "Notify Identity Owner"
    ],
    "mttc_seconds": 73,
    "report": "## EXECUTIVE SUMMARY\nA CRITICAL severity IAM/NHI threat auto-contained for svc_reporting_bot_447 in 73 seconds.\n...",
    "pipeline_log": [
      "[IdentityMonitor] Processing: ...",
      "[IdentityMonitor] ALERT CRITICAL (100.0) | 3 anomalies",
      "[BehaviorAnalyzer] Building behavioral profile...",
      "[ThreatIntel] Querying MITRE ATT&CK knowledge base...",
      "[Correlation] Building attack chain...",
      "[Response] 3 playbooks | MTTC: 73s",
      "[Reporting] Report generated"
    ]
  }
]
```

# Sample for Dashboard analyze page (http://localhost:3000/analyze)
1. Event JSON to paste into the textarea
```
{
  "identity_id": "svc_reporting_bot_447",
  "identity_type": "service_account",
  "src_ip": "185.220.101.55",
  "geo": "RU",
  "event_type": "api_call",
  "endpoint": "/api/v2/transactions",
  "risk_score": 88,
  "bytes_out": 485000,
  "mfa_used": false,
  "days_since_last_active": 243,
  "is_anomaly": true,
  "attack_type": "dormant_nhi_reactivation"
}
```
2. OAuth Scope Creep
```
{
  "identity_id": "oauth_connector_219",
  "identity_type": "oauth_token",
  "src_ip": "10.12.45.67",
  "geo": "US-NY",
  "event_type": "oauth_scope_grant",
  "scope_added": "admin:config",
  "total_scopes": 5,
  "risk_score": 78,
  "is_anomaly": true,
  "attack_type": "oauth_scope_creep"
}
```
3. API Key Exfiltration
```
{
  "identity_id": "api_key_ci_cd_runner_331",
  "identity_type": "api_key",
  "src_ip": "91.108.4.136",
  "geo": "CN",
  "event_type": "api_call",
  "endpoint": "/api/v2/accounts",
  "context": "unknown_external",
  "risk_score": 94,
  "bytes_out": 890000,
  "is_anomaly": true,
  "attack_type": "api_key_exfiltration"
}
```
4. Golden Ticket Attack
```
{
  "identity_id": "svc_payment_processor_123",
  "identity_type": "service_account",
  "src_ip": "45.33.32.156",
  "geo": "RU",
  "event_type": "ldap_query",
  "query_type": "SPN_enumeration",
  "target": "krbtgt",
  "risk_score": 85,
  "is_anomaly": true,
  "attack_type": "golden_ticket"
}
```



# 🛡️ AutonomSOC — Ghost Identity Hunter
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
git clone https://github.com/your-org/autonomsoc
cd autonomsoc

# 1. Pull Ollama models (one time)
set OLLAMA_HOST=127.0.0.1:11435
ollama pull llama3.1
ollama pull mistral
ollama serve 
```



> If Ollama is already installed and running on your host machine at port `11434`, do not start the Docker `ollama` service. Instead, use `OLLAMA_HOST=http://localhost:11434` for local backend runs, or `OLLAMA_HOST=http://host.docker.internal:11434` when calling from within Docker.

```bash
# 2. Start full enterprise stack
docker-compose -f docker/docker-compose.yml build
docker-compose -f docker/docker-compose.yml up -d
```



```bash
# 3. Generate synthetic data and seed ChromaDB
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python data/synthetic_generator.py --events 500 --attack all
python -c "from mitre.mitre_engine import MITREEngine; MITREEngine()"
```



```bash



**What it does:**
The Kafka producer continuously generates synthetic security events (IAM logs, API calls, endpoint activities) 
that simulate real attacks. Each event includes identity information (user ID, service account), behaviors 
(login from unusual location, mass file access), and contextual metadata (timestamp, IP geo, MFA status, bytes transferred).

**Why it requires continuous running state:**
- **Event sequencing**: Attacks are multi-stage (e.g., reconnaissance → lateral movement → data exfiltration). 
  The producer maintains temporal ordering and patterns across events to create realistic attack chains.
- **Kafka streaming**: Events are published to Kafka topics continuously. Stopping the producer halts the event stream, 
  so the consumer/pipeline won't receive new data to analyze.
- **Real-time anomaly detection**: The pipeline uses a sliding window of recent events as baseline for comparison. 
  Continuous stream enables behavior analysis (e.g., "user accessed 10GB in 1 minute when baseline is 100MB").
- **Kafka broker state**: Event ordering and partitioning are maintained by Kafka across multiple producers/consumers. 
  Stopping production doesn't affect Kafka durability but stops new content flowing through the system.

# 5. In another terminal — run agent consumer
python kafka/kafka_consumer.py



# 6. In another terminal — start API
uvicorn api.api:app --port 8000
# or
python -m uvicorn api.api:app --port 8000


# 7. Start React dashboard
cd react-dashboard && npm install && npm start



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

## � Understanding Continuous Running State

AutonomSOC is a **real-time streaming system**. Each component maintains state and depends on others:

```
[Kafka Producer] ──→ [Kafka Broker] ──→ [Kafka Consumer] ──→ [LangGraph 6-Agent Pipeline]
      ↓                    ↓                     ↓                        ↓
   Events               Topic Partition      Message Queue          Neo4j + TheHive
   (streaming)          (durable)            (ACK tracking)         (persistent)
                                                 ↓
                                            [API /analyze]
                                                 ↓
                                            [WebSocket /ws/alerts]
                                                 ↓
                                            [React Dashboard]
```

### Why Each Component Must Keep Running:

| Component | Runs Continuously | State Maintained | If Stopped |
|---|---|---|---|
| **Kafka Broker** | ✅ Yes | Messages in topics, partitions, offsets, consumer group lag | Entire pipeline halts; messages queue up in producer until restart |
| **Kafka Producer** | ✅ Yes | Event sequence, attack chain context, timing patterns | No new events → consumer idle → no pipeline executions |
| **Kafka Consumer** | ✅ Yes | Sliding window of user events, correlation state, baseline profiles | Unprocessed messages stay in queue; restarted consumer re-processes them from last offset |
| **LangGraph Pipeline** (within consumer) | ✅ Per-event | Historical context, behavior baselines, RAG embeddings (ChromaDB) | Current event analysis pauses; new events queue in Kafka |
| **Neo4j Graph DB** | ✅ Yes | Attack graph nodes/edges, blast radius paths, entity relationships | Already-written data persists; new relationships can't be written |
| **ChromaDB** | ✅ Yes | MITRE technique embeddings, historical incident RAG context | Already-embedded data available; new queries still work (readonly) |
| **TheHive** | ✅ Yes | Case database, analyst workflows, evidence collection | Already-created cases persist; new escalations can't be created |
| **Ollama LLM** | ✅ Yes | Loaded model in VRAM, context windows | Model unloads; next request reloads (slower) |
| **FastAPI** | ✅ Yes | In-memory case cache (CASES dict) | HTTP requests fail; WebSocket clients disconnect |
| **React Dashboard** | ✅ Yes | WebSocket connection, live state | Page stales out; manual refresh shows outdated data |

### Key Insight: Stateful Architecture

```python
# Each pipeline invocation builds on history:
initial_state: SOCState = {
    "raw_events": [prev_week_of_events],  # Baseline for anomaly detection
    "current_event": new_security_event,  # What we're analyzing NOW
    "identity_alert": agent_1_output,     # Passed to agent 2
    "behavior_score": agent_2_output,     # Passed to agent 3
    ...  # Each agent outputs → input for next agent
    "pipeline_log": [audit_trail],        # Visible in UI "Agent Reasoning" tab
}

result = pipeline.invoke(initial_state)  # If Kafka consumer stops, this never runs
```

If the **consumer stops**, the pipeline never executes again until restarted, even if the producer keeps sending events.

---

## �🔧 SOC Tool Integration Guide

### Wazuh (Open Source SIEM/XDR)
```bash
# Deploy Wazuh Manager
docker run -d --name wazuh wazuh/wazuh-manager:4.7.3 -p 55000:55000

# Feed Wazuh alerts into AutonomSOC
python kafka/kafka_producer.py --mode wazuh \
  --wazuh-url http://localhost:55000 \
  --wazuh-user wazuh --wazuh-pass wazuh
```
**What it adds**: Real endpoint alerts, file integrity monitoring, vulnerability detection

### MISP (Threat Intelligence)
```bash
# Deploy MISP
docker-compose up misp

# Feed IOCs into ChromaDB + Kafka
python kafka/kafka_producer.py --mode misp \
  --misp-url https://localhost:8443 \
  --misp-key YOUR_API_KEY
```
**What it adds**: Real IOC enrichment from CIRCL, Abuse.ch, and custom feeds

### TheHive (Incident Response)
```bash
# Set API key in .env
THEHIVE_KEY=your-key-here

# Cases auto-created for CRITICAL/HIGH incidents
# View at http://localhost:9000
```
**What it adds**: Case management, analyst assignment, evidence collection

### Shuffle SOAR (Workflow Automation)
```bash
# Access Shuffle UI at http://localhost:5001
# Import AutonomSOC playbooks from shuffle-apps/
```
**What it adds**: Visual playbook editor, 3rd-party integrations (Slack, Jira, PagerDuty)

---

## 📊 Using Real Datasets

### Option 1: Splunk BOTS v3
```bash
# Download from: https://github.com/splunk/botsv3
# Export from Splunk: index=botsv3 | outputcsv bots.json
python kafka/kafka_producer.py --mode bots --dataset /path/to/bots.json
```

### Option 2: Microsoft MSTIC GUIDE
```bash
# Download from: https://github.com/microsoft/mstic
# File: GUIDE_Train.csv
python kafka/kafka_producer.py --mode mstic --dataset /path/to/GUIDE_Train.csv
```

### Option 3: Awesome-Security-Datasets
```bash
# Browse: https://github.com/shramos/Awesome-Cybersecurity-Datasets
# Many are PCAP — use tshark to convert to JSON, then use raw adapter
python kafka/kafka_producer.py --mode simulate  # default while normalizing
```

---

## 📁 Project Structure

```
autonomsoc/
├── data/
│   └── synthetic_generator.py     # Splunk CIM IAM/NHI log generator
├── agents/
│   └── agent_pipeline.py          # LangGraph 6-agent pipeline
├── kafka/
│   ├── kafka_producer.py          # Multi-source event producer
│   └── kafka_consumer.py          # Pipeline consumer + TheHive integration
├── neo4j/
│   └── neo4j_graph.py             # Attack graph engine
├── mitre/
│   └── mitre_engine.py            # MITRE ATT&CK mapping + ChromaDB RAG
├── api/
│   └── api.py                     # FastAPI REST + WebSocket
├── react-dashboard/
│   ├── src/
│   │   ├── App.jsx                # Router + sidebar + WebSocket
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Live SOC overview
│   │   │   ├── Incidents.jsx      # Incident list + filter
│   │   │   ├── IncidentDetail.jsx # Full case view + report
│   │   │   ├── AttackGraph.jsx    # Neo4j force-layout visualization
│   │   │   ├── Analysis.jsx       # Run events through pipeline
│   │   │   └── MITREMap.jsx       # MITRE technique browser
│   │   └── store/
│   │       └── alertStore.js      # Zustand live alert store
│   └── package.json
├── docker/
│   ├── docker-compose.yml         # Full 12-service enterprise stack
│   ├── Dockerfile.agents          # Python agents + API
│   ├── Dockerfile.dashboard       # React + Nginx
│   └── nginx.conf
├── k8s/
│   └── manifests.yaml             # Full K8s deployment + HPA + Ingress
├── .github/
│   └── workflows/
│       └── ci-cd.yml              # GitHub Actions CI/CD
├── devpost/
│   └── SUBMISSION.md              # Full Devpost submission text
├── requirements.txt
├── .env.example
└── README.md
```

---

## 👥 Team Roles

| Role | Owner | Key Deliverables |
|---|---|---|
| Tech Lead + Architect | You (9yr Security + AI) | Agent design, MITRE mapping, attack scenarios, LLM prompts |
| AI / ML Engineer | ML person | LangGraph orchestration, Ollama, ChromaDB RAG |
| Security Analyst | Security person | Synthetic data realism, playbook logic, MITRE accuracy |
| Full Stack Dev | Both-skills person | React dashboard, FastAPI, Neo4j, Docker, demo polish |

---

## 🏆 Hackathon Submission Checklist

- [x] Problem statement defined (IAM/NHI blind spot)
- [x] Business use case (Financial organization Amex-specific: NHI sprawl, payment API protection)
- [x] POC built (all 6 agents functional)
- [x] Demo scenarios ready (3 attack scenarios, <90s containment each)
- [x] MITRE ATT&CK mapped (ChromaDB RAG + rules engine)
- [x] Neo4j attack graph (blast radius visualization)
- [x] React dashboard (5 pages, live WebSocket alerts)
- [x] On-prem LLMs (Ollama — no cloud cost, full data sovereignty)
- [x] SOC tool integrations (Wazuh, MISP, TheHive, Shuffle)
- [x] Docker Compose (12 services, one-command startup)
- [x] Kubernetes manifests (production-ready)
- [x] GitHub Actions CI/CD (build, test, security scan, deploy)
- [x] Devpost submission package
- [x] PowerPoint presentation (14 slides, storytelling flow)
- [x] README complete

---

*Built for TCS-Amex GenAI Hackathon 2026 | Cybersecurity Track | Best POC + Best Design*
