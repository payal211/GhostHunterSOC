"""
AutonomSOC — Neo4j Attack Graph Engine
Builds identity relationship graphs and attack chain visualizations.

Node types:  Identity, Resource, IP, GeoLocation, MITRETechnique, Incident
Edge types:  ACCESSED, ESCALATED_TO, MOVED_LATERALLY, CREATED, COMPROMISED, LINKED_TO

Run standalone:
    python neo4j_graph.py --demo
"""

import os, sys, json
from datetime import datetime
from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase, exceptions as neo4j_exc

# Dynamically add the root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

NEO4J_URI  = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "autonomsoc2026")

# ── Schema / Constraints ──────────────────────────────────────────────────────
SCHEMA_QUERIES = [
    "CREATE CONSTRAINT identity_id IF NOT EXISTS FOR (i:Identity) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (inc:Incident) REQUIRE inc.id IS UNIQUE",
    "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (ip:IP) REQUIRE ip.address IS UNIQUE",
    "CREATE CONSTRAINT mitre_id IF NOT EXISTS FOR (m:MITRETechnique) REQUIRE m.technique_id IS UNIQUE",
    "CREATE INDEX identity_type IF NOT EXISTS FOR (i:Identity) ON (i.type)",
    "CREATE INDEX identity_risk IF NOT EXISTS FOR (i:Identity) ON (i.risk_score)",
]

class AttackGraphDB:

    def __init__(self, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            print(f"[Neo4j] ✅ Connected → {uri}")
            self._apply_schema()
        except Exception as e:
            print(f"[Neo4j] ⚠️  Connection failed: {e} — graph features disabled")
            self.driver = None

    def _apply_schema(self):
        with self.driver.session() as s:
            for q in SCHEMA_QUERIES:
                try:
                    s.run(q)
                except Exception:
                    pass

    def close(self):
        if self.driver:
            self.driver.close()

    # ── Node Upserts ──────────────────────────────────────────────────────────
    def upsert_identity(self, identity_id: str, identity_type: str,
                        risk_score: float = 0, **props):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MERGE (i:Identity {id: $id})
                SET i.type = $type,
                    i.risk_score = $risk,
                    i.last_seen = $ts,
                    i += $props
            """, id=identity_id, type=identity_type, risk=risk_score,
                 ts=datetime.utcnow().isoformat(), props=props)

    def upsert_resource(self, resource_id: str, resource_type: str, **props):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MERGE (r:Resource {id: $id})
                SET r.type = $type, r.last_accessed = $ts, r += $props
            """, id=resource_id, type=resource_type,
                 ts=datetime.utcnow().isoformat(), props=props)

    def upsert_ip(self, address: str, geo: str = None, is_malicious: bool = False):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MERGE (ip:IP {address: $addr})
                SET ip.geo = $geo, ip.is_malicious = $mal, ip.last_seen = $ts
            """, addr=address, geo=geo or "UNKNOWN",
                 mal=is_malicious, ts=datetime.utcnow().isoformat())

    def upsert_mitre_technique(self, technique_id: str, name: str,
                                tactic: str, description: str = ""):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MERGE (m:MITRETechnique {technique_id: $tid})
                SET m.name = $name, m.tactic = $tactic, m.description = $desc
            """, tid=technique_id, name=name, tactic=tactic, desc=description)

    def upsert_incident(self, incident_id: str, risk_level: str,
                        attack_type: str, narrative: str = ""):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MERGE (inc:Incident {id: $id})
                SET inc.risk_level = $rl, inc.attack_type = $at,
                    inc.narrative = $narr, inc.created_at = $ts
            """, id=incident_id, rl=risk_level, at=attack_type,
                 narr=narrative, ts=datetime.utcnow().isoformat())

    # ── Relationship Writers ──────────────────────────────────────────────────
    def link_identity_accessed_resource(self, identity_id: str, resource_id: str,
                                         timestamp: str, is_anomalous: bool = False):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MATCH (i:Identity {id: $iid}), (r:Resource {id: $rid})
                MERGE (i)-[rel:ACCESSED]->(r)
                SET rel.last_access = $ts,
                    rel.is_anomalous = $anom,
                    rel.count = coalesce(rel.count, 0) + 1
            """, iid=identity_id, rid=resource_id, ts=timestamp, anom=is_anomalous)

    def link_identity_used_ip(self, identity_id: str, ip_address: str,
                               timestamp: str, is_anomalous: bool = False):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MATCH (i:Identity {id: $iid}), (ip:IP {address: $addr})
                MERGE (i)-[rel:USED_IP]->(ip)
                SET rel.last_seen = $ts, rel.is_anomalous = $anom
            """, iid=identity_id, addr=ip_address, ts=timestamp, anom=is_anomalous)

    def link_lateral_movement(self, from_id: str, to_id: str,
                               method: str, timestamp: str):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MATCH (a:Identity {id: $from}), (b:Identity {id: $to})
                MERGE (a)-[rel:MOVED_LATERALLY]->(b)
                SET rel.method = $method, rel.timestamp = $ts
            """, **{"from": from_id}, to=to_id, method=method, ts=timestamp)

    def link_privilege_escalation(self, identity_id: str, from_role: str,
                                   to_role: str, timestamp: str):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MATCH (i:Identity {id: $iid})
                MERGE (r1:Resource {id: $from_role})
                MERGE (r2:Resource {id: $to_role})
                SET r1.type = 'role', r2.type = 'role'
                MERGE (i)-[:HAD_ROLE {timestamp: $ts}]->(r1)
                MERGE (i)-[rel:ESCALATED_TO {timestamp: $ts}]->(r2)
            """, iid=identity_id, from_role=from_role,
                 to_role=to_role, ts=timestamp)

    def link_incident_to_identity(self, incident_id: str, identity_id: str,
                                   mitre_technique: str = None):
        if not self.driver: return
        with self.driver.session() as s:
            s.run("""
                MATCH (inc:Incident {id: $iid}), (i:Identity {id: $aid})
                MERGE (inc)-[rel:INVOLVES]->(i)
                SET rel.mitre_technique = $mit
            """, iid=incident_id, aid=identity_id, mit=mitre_technique or "UNKNOWN")

    # ── Ingest Pipeline Event ─────────────────────────────────────────────────
    def ingest_pipeline_result(self, result: Dict):
        """
        Master method: takes a full pipeline result dict and writes
        all relevant nodes and edges into the graph.
        """
        if not self.driver: return

        event     = result.get("current_event", {})
        alert     = result.get("identity_alert") or {}
        corr      = result.get("correlation") or {}
        threat    = result.get("threat_intel") or {}
        incident_id = result.get("case_id", f"INC-{event.get('event_id','?')[:8]}")

        identity_id   = event.get("identity_id") or event.get("user", "unknown")
        identity_type = event.get("identity_type", "unknown")
        risk_score    = alert.get("adjusted_risk_score", event.get("risk_score", 0))
        src_ip        = event.get("src_ip")
        geo           = event.get("geo")
        endpoint      = event.get("endpoint")
        timestamp     = event.get("time", datetime.utcnow().isoformat()+"Z")
        mitre         = threat.get("primary_technique", "UNKNOWN")
        attack_type   = event.get("attack_type", "unknown")
        is_anomalous  = event.get("is_anomaly", False)

        # Upsert core nodes
        self.upsert_identity(identity_id, identity_type, risk_score=risk_score,
                              last_seen=timestamp, attack_type=attack_type)

        if src_ip:
            self.upsert_ip(src_ip, geo=geo, is_malicious=is_anomalous)
            self.link_identity_used_ip(identity_id, src_ip, timestamp, is_anomalous)

        if endpoint:
            self.upsert_resource(endpoint, "api_endpoint", path=endpoint)
            self.link_identity_accessed_resource(identity_id, endpoint, timestamp, is_anomalous)

        # Incident node
        if result.get("should_escalate"):
            self.upsert_incident(
                incident_id, result.get("risk_level","UNKNOWN"),
                attack_type, corr.get("attack_narrative","")
            )
            self.link_incident_to_identity(incident_id, identity_id, mitre)

        # MITRE technique node
        if mitre and mitre != "UNKNOWN":
            techniques = threat.get("all_techniques", [])
            for t in techniques:
                self.upsert_mitre_technique(
                    t["technique_id"], t["technique_id"],
                    t.get("tactic","Unknown"), t.get("content","")[:200]
                )

        # Lateral movement from correlation
        for related_id in corr.get("affected_identities", []):
            if related_id and related_id != identity_id:
                self.upsert_identity(related_id, "service_account", risk_score=50)
                self.link_lateral_movement(identity_id, related_id, attack_type, timestamp)

        print(f"[Neo4j] Ingested → {identity_id} | risk:{risk_score:.0f} | mitre:{mitre}")

    # ── Queries ───────────────────────────────────────────────────────────────
    def get_attack_graph(self, limit: int = 50) -> List[Dict]:
        """Returns full attack graph for dashboard visualization."""
        if not self.driver: return []
        with self.driver.session() as s:
            result = s.run("""
                MATCH path = (i:Identity)-[r]->(n)
                WHERE r.is_anomalous = true OR type(r) IN ['MOVED_LATERALLY','ESCALATED_TO']
                WITH i, r, n, type(r) as rel_type
                RETURN i.id as source, i.type as source_type, i.risk_score as source_risk,
                       n.id as target, labels(n)[0] as target_label,
                       rel_type as relationship, r.timestamp as timestamp
                ORDER BY i.risk_score DESC LIMIT $limit
            """, limit=limit)
            return [dict(r) for r in result]

    def get_blast_radius(self, identity_id: str) -> Dict:
        """Calculates the full blast radius from a compromised identity."""
        if not self.driver: return {}
        with self.driver.session() as s:
            result = s.run("""
                MATCH (start:Identity {id: $id})
                CALL apoc.path.subgraphAll(start, {
                    relationshipFilter: 'ACCESSED|MOVED_LATERALLY|ESCALATED_TO|CREATED',
                    maxLevel: 4
                })
                YIELD nodes, relationships
                RETURN
                    size([n in nodes WHERE n:Identity]) as affected_identities,
                    size([n in nodes WHERE n:Resource]) as affected_resources,
                    size([n in nodes WHERE n:IP]) as affected_ips,
                    size(relationships) as total_edges,
                    [n in nodes | {id: n.id, labels: labels(n), risk: n.risk_score}] as all_nodes
            """, id=identity_id)
            row = result.single()
            return dict(row) if row else {}

    def get_high_risk_identities(self, min_risk: float = 70) -> List[Dict]:
        """Returns all identities above a risk threshold."""
        if not self.driver: return []
        with self.driver.session() as s:
            result = s.run("""
                MATCH (i:Identity)
                WHERE i.risk_score >= $min
                OPTIONAL MATCH (i)-[:MOVED_LATERALLY]->(lateral:Identity)
                RETURN i.id as identity_id, i.type as type,
                       i.risk_score as risk_score, i.attack_type as attack_type,
                       i.last_seen as last_seen,
                       collect(lateral.id) as lateral_targets
                ORDER BY i.risk_score DESC
            """, min=min_risk)
            return [dict(r) for r in result]

    def get_incident_timeline(self, incident_id: str) -> List[Dict]:
        """Returns chronological event timeline for an incident."""
        if not self.driver: return []
        with self.driver.session() as s:
            result = s.run("""
                MATCH (inc:Incident {id: $id})-[:INVOLVES]->(i:Identity)
                OPTIONAL MATCH (i)-[r]->(n)
                RETURN inc.id as incident_id, inc.risk_level as risk_level,
                       i.id as identity_id, type(r) as action,
                       n.id as target, r.last_access as timestamp
                ORDER BY timestamp
            """, id=incident_id)
            return [dict(r) for r in result]

    def get_graph_stats(self) -> Dict:
        """Dashboard stats query."""
        if not self.driver:
            return {"identities":0,"resources":0,"incidents":0,"high_risk":0}
        with self.driver.session() as s:
            r = s.run("""
                MATCH (i:Identity) WITH count(i) as identities
                MATCH (r:Resource) WITH identities, count(r) as resources
                MATCH (inc:Incident) WITH identities, resources, count(inc) as incidents
                MATCH (hr:Identity) WHERE hr.risk_score >= 70
                RETURN identities, resources, incidents, count(hr) as high_risk
            """).single()
            return dict(r) if r else {}

    # ── Demo Loader ───────────────────────────────────────────────────────────
    def load_demo_scenario(self):
        """Loads a pre-built demo attack scenario into the graph."""
        print("[Neo4j] Loading demo attack scenario...")

        # Identities
        self.upsert_identity("svc_ci_cd_runner_331","api_key",risk_score=96,
                              attack_type="api_key_exfiltration")
        self.upsert_identity("oauth_connector_219","oauth_token",risk_score=78,
                              attack_type="oauth_scope_creep")
        self.upsert_identity("svc_reporting_bot_447","service_account",risk_score=91,
                              attack_type="dormant_nhi_reactivation")
        self.upsert_identity("svc_payment_processor_123","service_account",risk_score=45)
        self.upsert_identity("demo\\fraud.analyst","human",risk_score=10)

        # IPs
        self.upsert_ip("91.108.4.136","CN",is_malicious=True)
        self.upsert_ip("185.220.101.55","RU",is_malicious=True)
        self.upsert_ip("10.12.45.67","US-NY",is_malicious=False)

        # Resources
        self.upsert_resource("/api/v2/transactions","api_endpoint")
        self.upsert_resource("/api/v2/accounts","api_endpoint")
        self.upsert_resource("/api/internal/admin","api_endpoint",is_sensitive=True)
        self.upsert_resource("admin:config","oauth_scope",is_sensitive=True)

        # MITRE nodes
        self.upsert_mitre_technique("T1552.001","Credentials In Files","Credential Access")
        self.upsert_mitre_technique("T1078.004","Valid Cloud Accounts","Initial Access")
        self.upsert_mitre_technique("T1098.001","Additional Cloud Credentials","Privilege Escalation")

        # Attack relationships
        ts = datetime.utcnow().isoformat()+"Z"
        self.link_identity_used_ip("svc_ci_cd_runner_331","91.108.4.136",ts,True)
        self.link_identity_accessed_resource("svc_ci_cd_runner_331","/api/v2/accounts",ts,True)
        self.link_identity_accessed_resource("svc_ci_cd_runner_331","/api/internal/admin",ts,True)
        self.link_lateral_movement("svc_ci_cd_runner_331","svc_payment_processor_123","api_key_reuse",ts)
        self.link_lateral_movement("oauth_connector_219","svc_reporting_bot_447","token_abuse",ts)
        self.link_identity_used_ip("svc_reporting_bot_447","185.220.101.55",ts,True)
        self.link_identity_accessed_resource("svc_reporting_bot_447","/api/v2/transactions",ts,True)
        self.link_privilege_escalation("oauth_connector_219","read:basic","admin:config",ts)

        # Incidents
        self.upsert_incident("DEMO-SOC-001","CRITICAL","api_key_exfiltration",
            "CI/CD API key exfiltrated and used externally to access payment APIs.")
        self.upsert_incident("DEMO-SOC-002","HIGH","dormant_nhi_reactivation",
            "Dormant service account reactivated from Russia targeting payment systems.")
        self.link_incident_to_identity("DEMO-SOC-001","svc_ci_cd_runner_331","T1552.001")
        self.link_incident_to_identity("DEMO-SOC-002","svc_reporting_bot_447","T1078.004")

        print("[Neo4j] ✅ Demo scenario loaded. Open http://localhost:7474")
        print("  Query: MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 100")


if __name__=="__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    db = AttackGraphDB()
    if args.demo: db.load_demo_scenario()
    if args.stats: print(json.dumps(db.get_graph_stats(), indent=2))
    db.close()
