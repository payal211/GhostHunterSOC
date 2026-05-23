"""Kafka Producer — Publishes security events to Kafka topics."""

import json
import os
from confluent_kafka import Producer


KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
TOPIC_RAW_EVENTS = "autonomsoc.raw-events"
TOPIC_ALERTS = "autonomsoc.alerts"
TOPIC_RESPONSES = "autonomsoc.responses"


def _delivery_report(err, msg):
    if err:
        print(f"[Kafka Producer] Delivery failed: {err}")
    else:
        print(f"[Kafka Producer] Delivered to {msg.topic()} [{msg.partition()}]")


def create_producer() -> Producer:
    return Producer({
        "bootstrap.servers": KAFKA_BROKER,
        "client.id": "autonomsoc-producer",
    })


def publish_event(producer: Producer, topic: str, event: dict, key: str = None):
    producer.produce(
        topic,
        key=key or event.get("event_id", ""),
        value=json.dumps(event),
        callback=_delivery_report,
    )
    producer.poll(0)


def publish_raw_event(producer: Producer, event: dict):
    publish_event(producer, TOPIC_RAW_EVENTS, event, key=event.get("event_id"))


def publish_alert(producer: Producer, alert: dict):
    publish_event(producer, TOPIC_ALERTS, alert, key=alert.get("case_id"))


def publish_response(producer: Producer, response: dict):
    publish_event(producer, TOPIC_RESPONSES, response, key=response.get("case_id"))


def flush(producer: Producer):
    producer.flush()


if __name__ == "__main__":
    import sys
    p = create_producer()
    sample = {
        "event_id": "test-kafka-001",
        "identity_id": "svc_test_123",
        "event_type": "api_call",
        "risk_score": 85.0,
    }
    publish_raw_event(p, sample)
    flush(p)
    print("Test event published.")