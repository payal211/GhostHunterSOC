"""
AutonomSOC — Kafka Producer
Streams security events from multiple sources into Kafka topics.

Supports:
  - Synthetic simulation (default)
  - Splunk Boss of the SOC (BOTS) dataset
  - Wazuh SIEM live alerts
  - MISP threat intel feeds
  - Microsoft MSTIC incident dataset
  - Awesome-Security-Datasets (GitHub)

Topics produced:
  - autonomsoc.iam.events      → IAM logins, MFA, privilege changes
  - autonomsoc.nhi.events      → Service accounts, API keys, OAuth tokens
  - autonomsoc.threat.intel    → MISP IOCs, threat feeds
  - autonomsoc.wazuh.alerts    → Wazuh SIEM alerts (if connected)

Run:
  python kafka_producer.py --mode simulate --attack all
  python kafka_producer.py --mode bots --dataset /data/BOTS_v3.json
  python kafka_producer.py --mode wazuh --wazuh-url http://localhost:55000
"""

import json
import time
import random
import argparse
import os
import sys
import requests
import uuid
from datetime import datetime, timedelta
from typing import Generator, Dict, Any, List

# Ensure project root is on sys.path when running this module directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from confluent_kafka import Producer, KafkaError
from faker import Faker
import sys
# Ensure project root is on sys.path when running script directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

fake = Faker()

# ── Kafka Config ──────────────────────────────────────────────────────────────
KAFKA_CONFIG = {
    "bootstrap.servers": os.getenv("KAFKA_BOOTSTRAP", "localhost:9092"),
    "client.id": "autonomsoc-producer",
    "acks": "all",
    "retries": 3,
    "batch.size": 16384,
    "linger.ms": 10,
}

TOPICS = {
    "iam":     "autonomsoc.iam.events",
    "nhi":     "autonomsoc.nhi.events",
    "threat":  "autonomsoc.threat.intel",
    "wazuh":   "autonomsoc.wazuh.alerts",
    "misp":    "autonomsoc.misp.iocs",
    "raw":     "autonomsoc.raw.logs",
}

# ── Delivery callback ─────────────────────────────────────────────────────────
def delivery_report(err, msg):
    if err:
        print(f"❌ Delivery failed: {err}")
    else:
        pass  # Silent on success for throughput


# ── Dataset Adapters ─────────────────────────────────────────────────────────

class BOTSAdapter:
    """
    Splunk Boss of the SOC (BOTS) Dataset Adapter.
    Dataset: https://github.com/splunk/botsv3
    Download: index=botsv3 | outputcsv bots.csv (from Splunk BOTS environment)
    
    BOTS contains real attack data including:
    - APT28 (Fancy Bear) TTPs
    - Ransomware campaigns
    - Web application attacks
    - Credential harvesting
    Maps to CIM format compatible with AutonomSOC.
    """
    
    FIELD_MAP = {
        # BOTS field → AutonomSOC field
        "_time": "time",
        "src_ip": "src_ip",
        "dest_ip": "dest_ip",
        "user": "user",
        "action": "action",
        "signature": "alert_name",
        "category": "event_category",
        "severity": "risk_score_raw",
    }
    
    SEVERITY_MAP = {"critical": 95, "high": 75, "medium": 50, "low": 20, "informational": 5}
    
    def __init__(self, dataset_path: str):
        self.path = dataset_path
    
    def stream(self) -> Generator[Dict, None, None]:
        """Streams BOTS events, normalizing to AutonomSOC CIM format."""
        try:
            with open(self.path) as f:
                events = json.load(f) if self.path.endswith(".json") else []
        except FileNotFoundError:
            print(f"⚠️  BOTS dataset not found at {self.path} — using sample simulation")
            yield from self._sample_bots_events()
            return
        
        for raw in events:
            yield self._normalize(raw)
    
    def _normalize(self, raw: Dict) -> Dict:
        normalized = {
            "event_id": str(uuid.uuid4()),
            "source": "bots_v3",
            "time": raw.get("_time", datetime.utcnow().isoformat() + "Z"),
            "user": raw.get("user", raw.get("src_user", "unknown")),
            "src_ip": raw.get("src_ip", raw.get("src", "")),
            "dest_ip": raw.get("dest_ip", raw.get("dest", "")),
            "action": raw.get("action", "unknown"),
            "event_type": raw.get("sourcetype", "unknown"),
            "risk_score": self.SEVERITY_MAP.get(raw.get("severity", "low"), 20),
            "alert_name": raw.get("signature", raw.get("rule_name", "")),
            "is_anomaly": raw.get("severity", "low") in ["high", "critical"],
        }
        return normalized
    
    def _sample_bots_events(self):
        """Sample events mimicking BOTS structure for demo."""
        samples = [
            {"user": "amber.turing", "src_ip": "10.0.0.14", "action": "allowed",
             "severity": "high", "signature": "ET POLICY PE EXE or DLL Windows file download",
             "sourcetype": "suricata"},
            {"user": "service_account_dc01", "src_ip": "192.168.9.25", "action": "success",
             "severity": "critical", "signature": "Kerberoasting: SPN Enumeration Detected",
             "sourcetype": "wineventlog"},
        ]
        for s in samples:
            yield self._normalize(s)


class MicrosoftMSTICAdapter:
    """
    Microsoft Security Operations Incident Prediction Dataset.
    Source: https://github.com/microsoft/MSTIC-Security-Datasets
    
    Contains labeled security incidents with:
    - Triage grade (TP, BP, FP)
    - MITRE technique mappings
    - Entity enrichment (devices, users, IPs)
    
    Great for training ML-based triage models.
    """
    
    def __init__(self, dataset_path: str = None):
        self.path = dataset_path
    
    def stream(self) -> Generator[Dict, None, None]:
        """Streams MSTIC incidents normalized to AutonomSOC format."""
        if not self.path or not os.path.exists(self.path):
            print("⚠️  MSTIC dataset not found — generating sample events")
            yield from self._sample_mstic_events()
            return
        
        with open(self.path) as f:
            for line in f:
                raw = json.loads(line)
                yield self._normalize(raw)
    
    def _normalize(self, raw: Dict) -> Dict:
        """Normalize MSTIC GUIDE schema to AutonomSOC format."""
        grade_risk = {"TP": 90, "BP": 40, "FP": 5}
        return {
            "event_id": raw.get("IncidentId", str(uuid.uuid4())),
            "source": "mstic_guide",
            "time": raw.get("Timestamp", datetime.utcnow().isoformat() + "Z"),
            "user": raw.get("AccountUpn", raw.get("AccountName", "unknown")),
            "identity_id": raw.get("AccountObjectId"),
            "identity_type": "user",
            "src_ip": raw.get("IPAddress", ""),
            "event_type": raw.get("Category", "incident"),
            "action": raw.get("ActionType", "unknown"),
            "risk_score": grade_risk.get(raw.get("TriageGrade", "BP"), 40),
            "mitre_technique": raw.get("MitreTechniques", ""),
            "alert_name": raw.get("Title", ""),
            "is_anomaly": raw.get("TriageGrade") == "TP",
            "device_id": raw.get("DeviceId"),
            "osm_entity_type": raw.get("OrgId"),
        }
    
    def _sample_mstic_events(self):
        samples = [
            {"IncidentId": "INC-001", "AccountUpn": "svc_payment@demo.com",
             "Category": "MaliciousCredentialTheft", "TriageGrade": "TP",
             "MitreTechniques": "T1558.001", "Title": "Golden Ticket Attack Detected",
             "IPAddress": "185.220.101.55"},
        ]
        for s in samples:
            yield self._normalize(s)


class WazuhAdapter:
    """
    Wazuh SIEM Live Alert Adapter.
    Connects to Wazuh Manager API and streams real alerts.
    
    Setup:
    1. Deploy Wazuh: docker run -d --name wazuh wazuh/wazuh-manager
    2. Configure agents on endpoints
    3. Point this adapter at the Wazuh API
    
    Wazuh provides:
    - File integrity monitoring (FIM)
    - Vulnerability detection
    - Log analysis (Syslog, Windows Event Log, etc.)
    - Active response triggers
    """
    
    def __init__(self, base_url: str, username: str = "wazuh", password: str = "wazuh"):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.token = None
    
    def authenticate(self) -> bool:
        try:
            resp = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=self.auth, verify=False, timeout=10
            )
            self.token = resp.json()["data"]["token"]
            return True
        except Exception as e:
            print(f"❌ Wazuh auth failed: {e}")
            return False
    
    def stream_alerts(self, limit: int = 100) -> Generator[Dict, None, None]:
        """Streams Wazuh alerts from API."""
        if not self.authenticate():
            return
        
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"limit": limit, "sort": "-timestamp", "select": "full"}
        
        try:
            resp = requests.get(
                f"{self.base_url}/alerts",
                headers=headers, params=params, verify=False, timeout=30
            )
            alerts = resp.json().get("data", {}).get("items", [])
        except Exception as e:
            print(f"❌ Wazuh alerts fetch failed: {e}")
            return
        
        for alert in alerts:
            yield {
                "event_id": str(alert.get("id", uuid.uuid4())),
                "source": "wazuh",
                "time": alert.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "identity_id": alert.get("data", {}).get("win", {}).get("system", {}).get("subjectUserName"),
                "identity_type": "service_account",
                "src_ip": alert.get("data", {}).get("srcip", ""),
                "event_type": "wazuh_alert",
                "alert_name": alert.get("rule", {}).get("description", ""),
                "risk_score": int(alert.get("rule", {}).get("level", 0)) * 6,
                "mitre_technique": alert.get("rule", {}).get("mitre", {}).get("id", [""])[0],
                "is_anomaly": int(alert.get("rule", {}).get("level", 0)) >= 10,
                "wazuh_rule_id": alert.get("rule", {}).get("id"),
                "wazuh_groups": alert.get("rule", {}).get("groups", []),
            }


class MISPAdapter:
    """
    MISP (Malware Information Sharing Platform) Threat Intel Adapter.
    
    Pulls IOCs and threat events from MISP and feeds into:
    - ChromaDB RAG for threat context enrichment
    - Kafka threat.intel topic for real-time correlation
    
    Setup:
    1. Deploy MISP: https://misp-project.org/download/
    2. Get API key from MISP UI
    3. Configure feeds (CIRCL, Abuse.ch, etc.)
    """
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    
    def stream_iocs(self, days_back: int = 7) -> Generator[Dict, None, None]:
        """Streams recent IOCs from MISP."""
        try:
            payload = {
                "request": {
                    "returnFormat": "json",
                    "type": ["ip-src", "ip-dst", "domain", "url", "md5", "sha256"],
                    "last": f"{days_back}d",
                    "to_ids": True,
                }
            }
            resp = requests.post(
                f"{self.base_url}/attributes/restSearch",
                json=payload, headers=self.headers, verify=False, timeout=30
            )
            attributes = resp.json().get("response", {}).get("Attribute", [])
        except Exception as e:
            print(f"❌ MISP fetch failed: {e} — using sample IOCs")
            yield from self._sample_iocs()
            return
        
        for attr in attributes:
            yield {
                "event_id": str(uuid.uuid4()),
                "source": "misp",
                "time": datetime.utcfromtimestamp(int(attr.get("timestamp", 0))).isoformat() + "Z",
                "ioc_type": attr.get("type"),
                "ioc_value": attr.get("value"),
                "misp_event_id": attr.get("event_id"),
                "tags": [t["name"] for t in attr.get("Tag", [])],
                "threat_level": attr.get("Event", {}).get("threat_level_id", "2"),
                "comment": attr.get("comment", ""),
            }
    
    def _sample_iocs(self):
        yield {
            "event_id": str(uuid.uuid4()),
            "source": "misp_sample",
            "time": datetime.utcnow().isoformat() + "Z",
            "ioc_type": "ip-src",
            "ioc_value": "185.220.101.55",
            "tags": ["tlp:white", "misp-galaxy:threat-actor=APT28"],
            "threat_level": "1",
            "comment": "Known Tor exit node used in credential attacks",
        }


# ── Simulation Mode (Default) ─────────────────────────────────────────────────
class SimulationProducer:
    """
    Generates synthetic events mimicking enterprise IAM/NHI traffic.
    Injects attack scenarios at configurable intervals.
    
    Use this when:
    - No real dataset available
    - Want to test specific attack scenarios
    - Demo/hackathon environment
    
    Upgrade to real dataset by swapping adapter only — pipeline is the same.
    """
    
    ATTACK_SCENARIOS = ["golden_ticket", "dormant_nhi", "oauth_scope_creep", "api_key_exfiltration"]
    
    def __init__(self, attack_scenarios: List[str] = None, events_per_second: int = 5):
        self.attacks = attack_scenarios or ["all"]
        self.eps = events_per_second
        self.event_count = 0
        self.attack_inject_interval = 50  # inject attack every N normal events
    
    def stream(self) -> Generator[Dict, None, None]:
        """Infinite stream of events with embedded attacks."""
        from data.synthetic_generator import generate_logs
        
        # Pre-generate a pool of events
        attack_list = self.ATTACK_SCENARIOS if "all" in self.attacks else self.attacks
        events = generate_logs(num_events=200, attacks=attack_list)
        
        idx = 0
        while True:
            event = events[idx % len(events)]
            event["event_id"] = str(uuid.uuid4())  # Fresh ID each loop
            event["time"] = datetime.utcnow().isoformat() + "Z"
            yield event
            idx += 1
            time.sleep(1.0 / self.eps)


# ── Main Producer ─────────────────────────────────────────────────────────────
def run_producer(mode: str = "simulate", **kwargs):
    producer = Producer(KAFKA_CONFIG)
    
    print(f"""
╔══════════════════════════════════════════╗
║   AutonomSOC Kafka Producer              ║
║   Mode: {mode:<32} ║
║   Bootstrap: {KAFKA_CONFIG['bootstrap.servers']:<28} ║
╚══════════════════════════════════════════╝
    """)
    
    # Select adapter
    if mode == "simulate":
        adapter = SimulationProducer(
            attack_scenarios=kwargs.get("attacks", ["all"]),
            events_per_second=kwargs.get("eps", 3)
        )
        event_stream = adapter.stream()
    
    elif mode == "bots":
        adapter = BOTSAdapter(kwargs.get("dataset", "data/bots_v3.json"))
        event_stream = adapter.stream()
    
    elif mode == "mstic":
        adapter = MicrosoftMSTICAdapter(kwargs.get("dataset", "data/mstic_incidents.json"))
        event_stream = adapter.stream()
    
    elif mode == "wazuh":
        adapter = WazuhAdapter(
            kwargs.get("wazuh_url", os.getenv("WAZUH_API", "http://localhost:55000")),
            kwargs.get("wazuh_user", "wazuh"),
            kwargs.get("wazuh_pass", "wazuh")
        )
        event_stream = adapter.stream_alerts()
    
    elif mode == "misp":
        adapter = MISPAdapter(
            kwargs.get("misp_url", os.getenv("MISP_URL", "http://localhost:443")),
            kwargs.get("misp_key", os.getenv("MISP_KEY", ""))
        )
        event_stream = adapter.stream_iocs()
    
    else:
        raise ValueError(f"Unknown mode: {mode}")
    
    # Topic routing by event type
    def route_topic(event: Dict) -> str:
        identity_type = event.get("identity_type", "")
        source = event.get("source", "")
        if source == "misp":
            return TOPICS["threat"]
        elif source == "wazuh":
            return TOPICS["wazuh"]
        elif identity_type in ["api_key", "oauth_token", "service_account", "certificate"]:
            return TOPICS["nhi"]
        elif event.get("event_type") in ["authentication", "ldap_query", "oauth_scope_grant"]:
            return TOPICS["iam"]
        return TOPICS["raw"]
    
    # Stream events
    total_sent = 0
    try:
        for event in event_stream:
            topic = route_topic(event)
            producer.produce(
                topic=topic,
                key=event.get("identity_id") or event.get("user") or "unknown",
                value=json.dumps(event).encode("utf-8"),
                callback=delivery_report,
            )
            producer.poll(0)
            total_sent += 1
            
            if total_sent % 10 == 0:
                anomaly = "🚨 ATTACK" if event.get("is_anomaly") else "✅ normal"
                print(f"[{total_sent:05d}] {anomaly} → topic:{topic.split('.')[-1]:8} | id:{str(event.get('identity_id','?'))[:30]}")
    
    except KeyboardInterrupt:
        print(f"\n⏹  Stopped. Total events sent: {total_sent}")
    finally:
        producer.flush(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutonomSOC Kafka Producer")
    parser.add_argument("--mode", choices=["simulate", "bots", "mstic", "wazuh", "misp"], default="simulate")
    parser.add_argument("--dataset", help="Path to dataset file (bots/mstic modes)")
    parser.add_argument("--attack", nargs="+", default=["all"], help="Attack scenarios to inject")
    parser.add_argument("--eps", type=int, default=3, help="Events per second (simulate mode)")
    parser.add_argument("--wazuh-url", default=os.getenv("WAZUH_API", "http://localhost:55000"))
    parser.add_argument("--misp-url", default=os.getenv("MISP_URL", "http://localhost:443"))
    parser.add_argument("--misp-key", default=os.getenv("MISP_KEY", ""))
    args = parser.parse_args()
    
    run_producer(
        mode=args.mode,
        attacks=args.attack,
        eps=args.eps,
        dataset=args.dataset,
        wazuh_url=args.wazuh_url,
        misp_url=args.misp_url,
        misp_key=args.misp_key,
    )