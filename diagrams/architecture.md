# AutonomSOC — Architecture Diagram

## Full System Architecture (Mermaid)

```mermaid
flowchart TD
    subgraph SOURCES["Data Sources"]
        SYN[Synthetic Generator]
        WAZ[Wazuh SIEM]
        MISP[MISP Threat Intel]
        BOTS[Splunk BOTS v3]
    end

    subgraph KAFKA["Apache Kafka"]
        T1[autonomsoc.raw-events]
        T2[autonomsoc.alerts]
        T3[autonomsoc.responses]
    end

    subgraph AGENTS["LangGraph Multi-Agent Pipeline"]
        direction TB
        A1["🔍 Agent 1\nIdentity Monitor\nModel: mistral"]
        A2["📊 Agent 2\nBehavior Analyzer\nModel: mistral"]
        A3["🧠 Agent 3\nThreat Intel RAG\nModel: llama3.1"]
        A4["🔗 Agent 4\nCorrelation\nModel: llama3.1"]
        A5["⚡ Agent 5\nResponse\nModel: mistral"]
        A6["📋 Agent 6\nReporting\nModel: llama3.1"]
        A1 -->|should_escalate=true| A2
        A1 -->|should_escalate=false| END_A([END])
        A2 --> A3
        A3 --> A4
        A4 --> A5
        A5 --> A6
    end

    subgraph STORAGE["Storage Layer"]
        NEO4J[(Neo4j\nAttack Graph)]
        CHROMA[(ChromaDB\nMITRE RAG)]
        OLLAMA[Ollama\nOn-Prem LLM]
    end

    subgraph OUTPUT["Output Layer"]
        API[FastAPI\nREST + WebSocket]
        HIVE[TheHive\nIncident Cases]
        DASH[Next.js\nSOC Dashboard]
    end

    SOURCES --> T1
    T1 --> CONSUMER[Kafka Consumer]
    CONSUMER --> AGENTS
    A3 <-->|vector search| CHROMA
    A4 -->|write graph| NEO4J
    A1 & A2 & A3 & A4 & A6 <-->|LLM calls| OLLAMA
    A5 -->|create case| HIVE
    A6 --> T2
    T2 --> API
    NEO4J --> API
    CHROMA --> API
    API -->|WebSocket| DASH

    style SOURCES fill:#0D1F3C,stroke:#1A3A6B,color:#CBD5E1
    style KAFKA   fill:#0D1F3C,stroke:#FFB400,color:#FFB400
    style AGENTS  fill:#071828,stroke:#00D4FF,color:#CBD5E1
    style STORAGE fill:#0D1F3C,stroke:#9B5DE5,color:#CBD5E1
    style OUTPUT  fill:#0D1F3C,stroke:#00FF9C,color:#CBD5E1
```

---

## Agent State Flow

```mermaid
stateDiagram-v2
    [*] --> IdentityMonitor : raw event
    IdentityMonitor --> END : is_anomaly=false
    IdentityMonitor --> BehaviorAnalyzer : risk_score > 40
    BehaviorAnalyzer --> ThreatIntelRAG
    ThreatIntelRAG --> Correlation
    Correlation --> Response
    Response --> Reporting
    Reporting --> [*] : incident report + Neo4j graph
```

---

## Data Flow: Columns & Features

| Column | Type | Source | Used By |
|---|---|---|---|
| event_id | UUID | Generator | All agents |
| identity_id | string | IAM/NHI logs | Agents 1,2,4 |
| identity_type | enum | IAM logs | Agents 1,5 |
| src_ip | string | Network | Agent 1,2 |
| geo | string | GeoIP | Agent 1 |
| risk_score | float 0-100 | Rule+LLM | Agent 1 |
| bytes_out | int | API logs | Agent 1 |
| mfa_used | bool | Okta | Agent 1 |
| days_since_last_active | int | IAM DB | Agent 1 |
| attack_type | enum | Label | Agents 3,4,5 |
| is_anomaly | bool | Label | Consumer filter |
| mitre_technique | string | LLM/ChromaDB | Agent 3 |
| adjusted_risk_score | float | Agent 1 output | Agents 2-6 |
| behavior_score | float | Agent 2 output | Agent 4 |
| blast_radius | int 0-100 | Agent 4 output | Agent 5,6 |
| attack_narrative | string | Agent 4 LLM | Agent 6 |
| playbooks_executed | list | Agent 5 | Agent 6 |
| final_report | markdown | Agent 6 LLM | API/Dashboard |

---

## Risk Score Calculation (0–100)

```
base_score       = event.risk_score (0-15 normal, 55-96 attack)

anomaly_boost    = count(anomalies_detected) × 12
  Each fires if:
  ANOMALOUS_GEO      → geo in [RU,CN,KP,IR,NG,BR]       → +12
  DORMANT_IDENTITY   → days_inactive > 90                 → +12
  MFA_BYPASS         → mfa_used=False on auth             → +12
  OFF_HOURS_ACCESS   → hour < 6 or hour > 22 UTC          → +12
  LARGE_TRANSFER     → bytes_out > 100,000                → +12
  API_KEY_EXTERNAL   → context=unknown_external           → +12
  SCOPE_CREEP        → total_scopes > 2                   → +12

adjusted_score   = min(base_score + anomaly_boost, 100)
llm_score        = Behavior Analyzer LLM rating (0-100)
final_score      = max(adjusted_score, llm_score)

CRITICAL → score > 80   AUTO-RESPOND
HIGH     → score > 60   AUTO-RESPOND
MEDIUM   → score > 40   HUMAN REVIEW
LOW      → score ≤ 40   LOG ONLY
```
