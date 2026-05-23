"""Neo4j Attack Graph Builder — Creates identity relationship and attack graphs."""

import os
from neo4j import GraphDatabase
from typing import Dict, Any, List


NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


class AttackGraphBuilder:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def close(self):
        self.driver.close()

    def create_identity_node(self, identity: Dict[str, Any]):
        with self.driver.session() as session:
            session.run(
                """
                MERGE (i:Identity {identity_id: $identity_id})
                SET i.type = $type,
                    i.risk_score = $risk_score,
                    i.status = $status,
                    i.last_seen = $last_seen
                """,
                identity_id=identity.get("identity_id"),
                type=identity.get("identity_type", "unknown"),
                risk_score=identity.get("risk_score", 0),
                status=identity.get("status", "active"),
                last_seen=identity.get("time", ""),
            )

    def create_event_node(self, event: Dict[str, Any]):
        with self.driver.session() as session:
            session.run(
                """
                CREATE (e:SecurityEvent {
                    event_id: $event_id,
                    event_type: $event_type,
                    timestamp: $timestamp,
                    src_ip: $src_ip,
                    geo: $geo,
                    risk_score: $risk_score,
                    attack_type: $attack_type
                })
                """,
                event_id=event.get("event_id"),
                event_type=event.get("event_type"),
                timestamp=event.get("time"),
                src_ip=event.get("src_ip"),
                geo=event.get("geo"),
                risk_score=event.get("risk_score", 0),
                attack_type=event.get("attack_type"),
            )

    def link_identity_to_event(self, identity_id: str, event_id: str, relationship: str = "PERFORMED"):
        with self.driver.session() as session:
            session.run(
                f"""
                MATCH (i:Identity {{identity_id: $identity_id}})
                MATCH (e:SecurityEvent {{event_id: $event_id}})
                MERGE (i)-[:{relationship}]->(e)
                """,
                identity_id=identity_id,
                event_id=event_id,
            )

    def create_attack_chain(self, events: List[Dict[str, Any]]):
        """Links sequential events into an attack chain."""
        for i in range(len(events) - 1):
            with self.driver.session() as session:
                session.run(
                    """
                    MATCH (e1:SecurityEvent {event_id: $event_id_1})
                    MATCH (e2:SecurityEvent {event_id: $event_id_2})
                    MERGE (e1)-[:LEADS_TO {step: $step}]->(e2)
                    """,
                    event_id_1=events[i].get("event_id"),
                    event_id_2=events[i + 1].get("event_id"),
                    step=i + 1,
                )

    def link_to_mitre(self, event_id: str, technique_id: str, tactic: str):
        with self.driver.session() as session:
            session.run(
                """
                MERGE (t:MITRETechnique {technique_id: $technique_id})
                SET t.tactic = $tactic
                WITH t
                MATCH (e:SecurityEvent {event_id: $event_id})
                MERGE (e)-[:MAPS_TO]->(t)
                """,
                technique_id=technique_id,
                tactic=tactic,
                event_id=event_id,
            )

    def create_endpoint_node(self, endpoint: str):
        with self.driver.session() as session:
            session.run(
                "MERGE (ep:Endpoint {path: $path})",
                path=endpoint,
            )

    def link_event_to_endpoint(self, event_id: str, endpoint: str):
        with self.driver.session() as session:
            session.run(
                """
                MATCH (e:SecurityEvent {event_id: $event_id})
                MATCH (ep:Endpoint {path: $endpoint})
                MERGE (e)-[:ACCESSED]->(ep)
                """,
                event_id=event_id,
                endpoint=endpoint,
            )

    def ingest_pipeline_result(self, result: Dict[str, Any]):
        """Ingests a full pipeline result into the attack graph."""
        event = result.get("current_event", {})
        alert = result.get("identity_alert", {})
        correlation = result.get("correlation", {})
        threat_intel = result.get("threat_intel", {})

        identity_id = event.get("identity_id") or event.get("user")
        event_id = event.get("event_id")

        if not identity_id or not event_id:
            return

        self.create_identity_node({
            "identity_id": identity_id,
            "identity_type": event.get("identity_type"),
            "risk_score": alert.get("adjusted_risk_score", 0),
            "status": "compromised" if result.get("should_escalate") else "active",
            "time": event.get("time"),
        })

        self.create_event_node(event)
        self.link_identity_to_event(identity_id, event_id)

        if event.get("endpoint"):
            self.create_endpoint_node(event["endpoint"])
            self.link_event_to_endpoint(event_id, event["endpoint"])

        primary_technique = threat_intel.get("primary_technique")
        if primary_technique and primary_technique != "UNKNOWN":
            techniques = threat_intel.get("all_techniques", [])
            tactic = techniques[0].get("tactic", "Unknown") if techniques else "Unknown"
            self.link_to_mitre(event_id, primary_technique, tactic)

    def get_blast_radius(self, identity_id: str) -> Dict[str, Any]:
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (i:Identity {identity_id: $identity_id})-[:PERFORMED]->(e:SecurityEvent)
                OPTIONAL MATCH (e)-[:ACCESSED]->(ep:Endpoint)
                OPTIONAL MATCH (e)-[:MAPS_TO]->(t:MITRETechnique)
                OPTIONAL MATCH (e)-[:LEADS_TO*]->(chain:SecurityEvent)
                RETURN i, collect(DISTINCT e) as events,
                       collect(DISTINCT ep.path) as endpoints,
                       collect(DISTINCT t.technique_id) as techniques,
                       collect(DISTINCT chain) as chain_events
                """,
                identity_id=identity_id,
            )
            record = result.single()
            if not record:
                return {"identity_id": identity_id, "found": False}

            return {
                "identity_id": identity_id,
                "found": True,
                "event_count": len(record["events"]),
                "endpoints": [ep for ep in record["endpoints"] if ep],
                "mitre_techniques": [t for t in record["techniques"] if t],
                "chain_length": len(record["chain_events"]),
            }

    def clear_graph(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")