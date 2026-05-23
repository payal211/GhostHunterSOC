"""
Kafka Consumer — Consumes security events and feeds the agent pipeline.

BUG FIXED: The original had `from kafka.producer import ...`
Python resolved `kafka` to the LOCAL kafka/ folder, which shadows
confluent_kafka internals AND works fine — BUT only if consumer.py
is inside the backend/ folder. The sys.path manipulation was also
duplicated (import sys, os appeared twice). Both fixed below.

Run:
    cd backend/
    python -m kafka.consumer
"""

import json
import os
import sys

# Ensure backend/ root is on the path so all absolute imports resolve
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from confluent_kafka import Consumer, KafkaError

from orchestrator.graph import build_pipeline
from agents.state import SOCState

# Import from our local kafka package (not confluent_kafka)
from kafka.producer import create_producer, publish_alert, flush

KAFKA_BROKER    = os.getenv("KAFKA_BROKER", "localhost:9092")
TOPIC_RAW       = "autonomsoc.raw-events"
MAX_WINDOW_SIZE = 500  # keep last N events for behavioral baseline


def create_consumer(group_id: str = "autonomsoc-pipeline") -> Consumer:
    return Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id":          group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
        "session.timeout.ms": 30000,
    })


def process_message(
    pipeline,
    producer,
    msg_value: str,
    event_window: list,
) -> dict | None:
    """
    Deserialises one Kafka message and runs it through the 6-agent pipeline.
    Returns the pipeline result dict, or None if pre-filtered as normal.
    """
    event = json.loads(msg_value)
    event_window.append(event)

    # Pre-filter: skip obvious normal events to save LLM compute
    if not event.get("is_anomaly") and event.get("risk_score", 0) <= 30:
        return None

    initial_state: SOCState = {
        "raw_events":       event_window[-MAX_WINDOW_SIZE:],
        "current_event":    event,
        "identity_alert":   None,
        "behavior_score":   None,
        "threat_intel":     None,
        "correlation":      None,
        "response_actions": None,
        "final_report":     None,
        "risk_level":       "LOW",
        "should_escalate":  False,
        "case_id":          None,
        "pipeline_log":     [],
    }

    result = pipeline.invoke(initial_state)

    if result.get("should_escalate"):
        alert_msg = {
            "case_id":    event.get("event_id"),
            "risk_level": result["risk_level"],
            "identity_id": result.get("identity_alert", {}).get("identity_id"),
            "mitre":       result.get("threat_intel", {}).get("primary_technique"),
            "report":      result.get("final_report", ""),
        }
        publish_alert(producer, alert_msg)
        print(
            f"[Consumer] 🚨 ESCALATED {result['risk_level']} "
            f"— {event.get('identity_id','?')} "
            f"— {result.get('threat_intel',{}).get('primary_technique','?')}"
        )
    else:
        print(f"[Consumer] ✅ CLEARED — {event.get('event_id','?')[:12]}")

    return result


def run_consumer():
    """Main consumer loop — blocks indefinitely."""
    consumer = create_consumer()
    consumer.subscribe([TOPIC_RAW])
    pipeline     = build_pipeline()
    producer     = create_producer()
    event_window = []

    print(f"[Consumer] 🚀 Listening on {TOPIC_RAW} | broker: {KAFKA_BROKER}")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"[Consumer] ❌ Kafka error: {msg.error()}")
                break

            try:
                process_message(pipeline, producer, msg.value().decode("utf-8"), event_window)
                flush(producer)
            except Exception as e:
                print(f"[Consumer] ❌ Processing error: {e}")

    except KeyboardInterrupt:
        print("[Consumer] ⏹ Shutting down...")
    finally:
        consumer.close()
        print("[Consumer] Closed.")


if __name__ == "__main__":
    run_consumer()
