"""Neo4j Cypher queries for common attack graph operations."""

QUERIES = {
    "blast_radius": """
        MATCH (i:Identity {identity_id: $identity_id})-[:PERFORMED]->(e:SecurityEvent)
        OPTIONAL MATCH (e)-[:ACCESSED]->(ep:Endpoint)
        OPTIONAL MATCH (e)-[:MAPS_TO]->(t:MITRETechnique)
        RETURN i, collect(DISTINCT e) as events,
               collect(DISTINCT ep.path) as endpoints,
               collect(DISTINCT t.technique_id) as techniques
    """,

    "attack_chain": """
        MATCH path = (start:SecurityEvent)-[:LEADS_TO*]->(end:SecurityEvent)
        WHERE start.attack_type = $attack_type
        RETURN path
        ORDER BY length(path) DESC
        LIMIT 10
    """,

    "compromised_identities": """
        MATCH (i:Identity {status: 'compromised'})
        RETURN i.identity_id as identity_id,
               i.type as type,
               i.risk_score as risk_score,
               i.last_seen as last_seen
        ORDER BY i.risk_score DESC
    """,

    "mitre_coverage": """
        MATCH (e:SecurityEvent)-[:MAPS_TO]->(t:MITRETechnique)
        RETURN t.technique_id as technique,
               t.tactic as tactic,
               count(e) as event_count
        ORDER BY event_count DESC
    """,

    "identity_connections": """
        MATCH (i1:Identity)-[:PERFORMED]->(e1:SecurityEvent)-[:LEADS_TO*0..3]->(e2:SecurityEvent)<-[:PERFORMED]-(i2:Identity)
        WHERE i1.identity_id = $identity_id AND i1 <> i2
        RETURN DISTINCT i2.identity_id as connected_identity,
               i2.type as type,
               i2.status as status
    """,

    "high_risk_paths": """
        MATCH path = (i:Identity)-[:PERFORMED]->(e:SecurityEvent)-[:ACCESSED]->(ep:Endpoint)
        WHERE e.risk_score > 70
        RETURN i.identity_id as identity,
               e.event_id as event,
               ep.path as endpoint,
               e.risk_score as risk_score
        ORDER BY e.risk_score DESC
        LIMIT 20
    """,
}