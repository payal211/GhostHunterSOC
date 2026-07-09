"""
AutonomSOC — Kafka Consumer
Consumes security events from Kafka topics and feeds into the 6-agent pipeline.

Topics consumed:
  - autonomsoc.iam.events
  - autonomsoc.nhi.events
  - autonomsoc.wazuh.alerts
  - autonomsoc.raw.logs

Run:  python kafka_consumer.py
"""

import json, os, sys, uuid, time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from confluent_kafka import Consumer, KafkaError

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
GROUP_ID        = "autonomsoc-agents"

TOPICS = [
    "autonomsoc.iam.events",
    "autonomsoc.nhi.events",
    "autonomsoc.wazuh.alerts",
    "autonomsoc.raw.logs",
]

CONSUMER_CONFIG = {
    "bootstrap.servers":  KAFKA_BOOTSTRAP,
    "group.id":           GROUP_ID,
    "auto.offset.reset":  "latest",
    "enable.auto.commit": True,
    "session.timeout.ms": 30000,
    "max.poll.interval.ms": 300000,
}

# Sliding window of recent events for behavior analysis
EVENT_WINDOW: list = []
MAX_WINDOW = 2000

def run_consumer():
    from agents.agent_pipeline import run_on_event

    consumer = Consumer(CONSUMER_CONFIG)
    consumer.subscribe(TOPICS)

    print(f"""
╔══════════════════════════════════════════╗
║   AutonomSOC Kafka Consumer              ║
║   Group: {GROUP_ID:<32} ║
║   Topics: {len(TOPICS):<32} ║
╚══════════════════════════════════════════╝
    """)

    stats = {"total": 0, "escalated": 0, "errors": 0}
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"❌ Kafka error: {msg.error()}")
                stats["errors"] += 1
                continue

            try:
                event = json.loads(msg.value().decode("utf-8"))
            except Exception as e:
                print(f"❌ Parse error: {e}")
                continue

            # Maintain sliding window
            EVENT_WINDOW.append(event)
            if len(EVENT_WINDOW) > MAX_WINDOW:
                EVENT_WINDOW.pop(0)

            stats["total"] += 1
            case_id = f"DEMO-{str(uuid.uuid4())[:8].upper()}"

            # Only run full pipeline on potentially anomalous events
            # (pre-filter: risk_score > 30 or flagged)
            if event.get("risk_score", 0) > 30 or event.get("is_anomaly"):
                try:
                    result = run_on_event(event, EVENT_WINDOW.copy(), case_id)

                    if result.get("should_escalate"):
                        stats["escalated"] += 1
                        _handle_escalation(result, case_id, event)
                    else:
                        print(f"[{stats['total']:05d}] ✅ CLEARED → {event.get('identity_id','?')[:30]}")
                except Exception as e:
                    print(f"❌ Pipeline error: {e}")
                    stats["errors"] += 1
            else:
                if stats["total"] % 50 == 0:
                    print(f"[{stats['total']:05d}] 📊 Stats: escalated={stats['escalated']} errors={stats['errors']}")

    except KeyboardInterrupt:
        print(f"\n⏹  Consumer stopped.")
        print(f"📊 Final: total={stats['total']} escalated={stats['escalated']} errors={stats['errors']}")
    finally:
        consumer.close()


def _push_to_api(result: dict, case_id: str, event: dict):
    api_url = os.getenv("AUTONOMSOC_API_URL", "http://127.0.0.1:8000")
    payload = {
        "event": event,
        "result": result,
        "case_id": case_id,
    }
    req = Request(
        f"{api_url}/cases/ingest",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            print(f"  [API] ✅ ingested incident: {body}")
    except Exception as exc:
        print(f"  [API] ⚠️ ingest failed: {exc}")


def _handle_escalation(result: dict, case_id: str, event: dict):
    """Handles an escalated incident: log, TheHive, Kafka response topic."""
    alert  = result.get("identity_alert") or {}
    threat = result.get("threat_intel") or {}
    resp   = result.get("response_actions") or {}

    print(f"\n🚨 INCIDENT {case_id} | {result['risk_level']} | "
          f"Score={alert.get('adjusted_risk_score','?'):.0f} | "
          f"MITRE={threat.get('primary_technique','?')} | "
          f"MTTC={resp.get('mttc_seconds','?')}s")

    for line in result.get("pipeline_log", []):
        print(f"  {line}")

    # Push to TheHive if configured
    if os.getenv("THEHIVE_KEY"):
        _create_thehive_alert(result, case_id)

    # Push into API-backed dashboard store
    _push_to_api(result, case_id, event)

    # Save incident locally
    try:
        incidents_file = "incidents.jsonl"
        with open(incidents_file, "a") as f:
            f.write(json.dumps({
                "case_id":     case_id,
                "timestamp":   datetime.utcnow().isoformat()+"Z",
                "risk_level":  result["risk_level"],
                "identity_id": alert.get("identity_id"),
                "mitre":       threat.get("primary_technique"),
                "report":      result.get("final_report","")[:500],
                "actions":     [p["playbook_name"] for p in resp.get("playbooks_executed",[])],
            }) + "\n")
    except Exception:
        pass


def _create_thehive_alert(result: dict, case_id: str):
    """Creates a case in TheHive 5 via REST API."""
    import requests
    alert  = result.get("identity_alert") or {}
    threat = result.get("threat_intel") or {}

    payload = {
        "title":       f"[AutonomSOC] {result['risk_level']} — {alert.get('identity_id','?')}",
        "description": result.get("final_report","")[:2000],
        "severity":    {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(result["risk_level"],2),
        "source":      "AutonomSOC",
        "sourceRef":   case_id,
        "type":        "alert",
        "tags":        [
            f"mitre:{threat.get('primary_technique','UNKNOWN')}",
            f"identity:{alert.get('identity_type','unknown')}",
            "autonomsoc", "iam-nhi",
        ],
        "customFields": {
            "risk_score":  {"integer": int(alert.get("adjusted_risk_score",0))},
            "attack_type": {"string": result["current_event"].get("attack_type","unknown")},
        },
    }
    try:
        r = requests.post(
            f"{os.getenv('THEHIVE_URL','http://localhost:9000')}/api/v1/alert",
            json=payload,
            headers={"Authorization": f"Bearer {os.getenv('THEHIVE_KEY','')}",
                     "Content-Type": "application/json"},
            timeout=15,
        )
        if r.status_code in [200, 201]:
            print(f"  [TheHive] ✅ Alert created: {r.json().get('_id','?')}")
        else:
            print(f"  [TheHive] ⚠️  {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"  [TheHive] ❌ {e}")


if __name__ == "__main__":
    run_consumer()