"""
AutonomSOC — Synthetic Splunk CIM-Format Log Generator
Generates realistic IAM + NHI event data for testing the agent pipeline.

Usage:
    python synthetic_generator.py --events 500 --attack all --output logs.json
    python synthetic_generator.py --events 1000 --attack dormant_nhi
"""

import json, random, argparse, uuid
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()
random.seed(42)

HUMAN_IDENTITIES = [
    {"user": f"demo\\{fake.user_name()}", "dept": dept}
    for dept in ["payments","fraud-ops","identity-eng","data-science","infosec"]
    for _ in range(8)
]

NHI_IDENTITIES = [
    {"id": f"svc_{name}_{random.randint(100,999)}", "type": t,
     "owner": f"demo\\{fake.user_name()}",
     "last_active": (datetime.utcnow()-timedelta(days=random.randint(1,400))).isoformat()}
    for name, t in [
        ("payment_processor","service_account"),("fraud_detector","service_account"),
        ("auth_gateway","api_key"),("reporting_bot","service_account"),
        ("data_pipeline","api_key"),("ci_cd_runner","api_key"),
        ("oauth_connector","oauth_token"),("cert_renewal","certificate"),
        ("monitoring_agent","service_account"),("batch_processor","service_account"),
    ] for _ in range(4)
]

INTERNAL_IPS  = [f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(50)]
EXTERNAL_IPS  = [fake.ipv4_public() for _ in range(20)]
GEOS_NORMAL   = ["US-NY","US-AZ","US-UT","US-FL"]
GEOS_ATTACK   = ["RU","CN","KP","IR","BR"]
PAYMENT_APIS  = ["/api/v2/transactions","/api/v2/accounts","/api/v2/transfers","/api/v1/cards"]
INTERNAL_APIS = ["/api/internal/audit","/api/internal/config","/api/internal/admin"]

def _evt(overrides):
    base = {
        "event_id": str(uuid.uuid4()),
        "time": datetime.utcnow().isoformat()+"Z",
        "is_anomaly": False,
        "attack_type": None,
        "risk_score": random.uniform(0,15),
    }
    base.update(overrides)
    return base

def make_normal_login(ts):
    u = random.choice(HUMAN_IDENTITIES)
    return _evt({"time":ts.isoformat()+"Z","index":"demo_iam","sourcetype":"okta:system:user",
                 "event_type":"authentication","action":"success","user":u["user"],
                 "identity_type":"human","src_ip":random.choice(INTERNAL_IPS),
                 "geo":random.choice(GEOS_NORMAL),"mfa_used":True,
                 "app":random.choice(["Workday","Jira","ServiceNow","Splunk"])})

def make_normal_api_call(ts):
    n = random.choice(NHI_IDENTITIES)
    return _evt({"time":ts.isoformat()+"Z","index":"demo_nhi","sourcetype":"demo:api:access",
                 "event_type":"api_call","action":"success","identity_id":n["id"],
                 "identity_type":n["type"],"src_ip":random.choice(INTERNAL_IPS),
                 "endpoint":random.choice(PAYMENT_APIS),"http_method":"GET",
                 "response_code":200,"bytes_out":random.randint(100,5000)})

# ── Attack Injectors ──────────────────────────────────────────────────────────
def inject_golden_ticket(base_ts):
    nhi = random.choice([n for n in NHI_IDENTITIES if n["type"]=="service_account"])
    evts = []
    for i in range(4):
        evts.append(_evt({"time":(base_ts+timedelta(minutes=i*2)).isoformat()+"Z",
            "index":"demo_iam","sourcetype":"windows:security","event_type":"ldap_query",
            "identity_id":nhi["id"],"identity_type":"service_account",
            "src_ip":random.choice(INTERNAL_IPS),"query_type":"SPN_enumeration","target":"krbtgt",
            "risk_score":55,"is_anomaly":True,"attack_type":"golden_ticket",
            "mitre_tactic":"Credential Access","mitre_technique":"T1558.001"}))
    night = base_ts.replace(hour=3,minute=random.randint(0,59))
    evts.append(_evt({"time":night.isoformat()+"Z","index":"demo_iam","sourcetype":"okta:system:user",
        "event_type":"authentication","action":"success","identity_id":nhi["id"],
        "identity_type":"service_account","src_ip":random.choice(EXTERNAL_IPS),
        "geo":random.choice(GEOS_ATTACK),"mfa_used":False,"risk_score":88,
        "is_anomaly":True,"attack_type":"golden_ticket",
        "mitre_tactic":"Defense Evasion","mitre_technique":"T1078"}))
    for ep in INTERNAL_APIS:
        evts.append(_evt({"time":(night+timedelta(minutes=random.randint(1,15))).isoformat()+"Z",
            "index":"demo_nhi","sourcetype":"demo:api:access","event_type":"api_call",
            "identity_id":nhi["id"],"identity_type":"service_account",
            "src_ip":random.choice(EXTERNAL_IPS),"endpoint":ep,"http_method":"GET",
            "bytes_out":random.randint(50000,500000),"risk_score":92,
            "is_anomaly":True,"attack_type":"golden_ticket",
            "mitre_tactic":"Lateral Movement","mitre_technique":"T1550.003"}))
    return evts

def inject_dormant_nhi(base_ts):
    dormant = [n for n in NHI_IDENTITIES
               if (datetime.utcnow()-datetime.fromisoformat(n["last_active"])).days > 150]
    nhi = random.choice(dormant or NHI_IDENTITIES[:2])
    evts = []
    for i, ep in enumerate(PAYMENT_APIS):
        evts.append(_evt({"time":(base_ts+timedelta(minutes=i*5)).isoformat()+"Z",
            "index":"demo_nhi","sourcetype":"demo:api:access","event_type":"api_call",
            "identity_id":nhi["id"],"identity_type":nhi["type"],
            "src_ip":random.choice(EXTERNAL_IPS),"geo":random.choice(GEOS_ATTACK),
            "endpoint":ep,"http_method":"GET","bytes_out":random.randint(10000,200000),
            "days_since_last_active":random.randint(150,400),"risk_score":91,
            "is_anomaly":True,"attack_type":"dormant_nhi_reactivation",
            "mitre_tactic":"Initial Access","mitre_technique":"T1078.004"}))
    return evts

def inject_oauth_scope_creep(base_ts):
    nhi = random.choice([n for n in NHI_IDENTITIES if n["type"]=="oauth_token"] or NHI_IDENTITIES)
    scopes = ["read:basic","read:accounts","write:transactions","admin:users","admin:config"]
    evts = []
    for day, scope in enumerate(scopes):
        ts = base_ts+timedelta(days=day+1)
        evts.append(_evt({"time":ts.isoformat()+"Z","index":"demo_iam","sourcetype":"okta:system:oauth",
            "event_type":"oauth_scope_grant","identity_id":nhi["id"],"identity_type":"oauth_token",
            "src_ip":random.choice(INTERNAL_IPS),"scope_added":scope,"total_scopes":day+1,
            "granted_by":random.choice(HUMAN_IDENTITIES)["user"],
            "risk_score":20+day*18,"is_anomaly":day>=2,
            "attack_type":"oauth_scope_creep" if day>=2 else None,
            "mitre_tactic":"Privilege Escalation" if day>=2 else None,
            "mitre_technique":"T1098.001" if day>=2 else None}))
    return evts

def inject_api_key_exfiltration(base_ts):
    nhi = random.choice([n for n in NHI_IDENTITIES if n["type"]=="api_key"] or NHI_IDENTITIES)
    evts = []
    for i in range(3):
        evts.append(_evt({"time":(base_ts-timedelta(hours=3)+timedelta(minutes=i*20)).isoformat()+"Z",
            "index":"demo_nhi","sourcetype":"demo:api:access","event_type":"api_call",
            "identity_id":nhi["id"],"identity_type":"api_key",
            "src_ip":random.choice(INTERNAL_IPS),"endpoint":"/api/v2/deploy",
            "context":"ci_cd_pipeline","risk_score":5}))
    for i in range(5):
        evts.append(_evt({"time":(base_ts+timedelta(minutes=i*10)).isoformat()+"Z",
            "index":"demo_nhi","sourcetype":"demo:api:access","event_type":"api_call",
            "identity_id":nhi["id"],"identity_type":"api_key",
            "src_ip":fake.ipv4_public(),"geo":random.choice(GEOS_ATTACK),
            "endpoint":random.choice(PAYMENT_APIS),"http_method":"POST",
            "context":"unknown_external","bytes_out":random.randint(100000,1000000),
            "risk_score":96,"is_anomaly":True,"attack_type":"api_key_exfiltration",
            "mitre_tactic":"Collection","mitre_technique":"T1552.001"}))
    return evts

ATTACK_INJECTORS = {
    "golden_ticket": inject_golden_ticket,
    "dormant_nhi": inject_dormant_nhi,
    "oauth_scope_creep": inject_oauth_scope_creep,
    "api_key_exfiltration": inject_api_key_exfiltration,
}

def generate_logs(num_events=500, attacks=None, output_file=None):
    logs, base_ts = [], datetime.utcnow()-timedelta(hours=24)
    interval = timedelta(hours=24)/num_events
    for i in range(num_events):
        ts = base_ts+interval*i
        logs.append(make_normal_login(ts) if random.random()<0.6 else make_normal_api_call(ts))
    if attacks:
        for atk in attacks:
            targets = list(ATTACK_INJECTORS.keys()) if atk=="all" else [atk]
            for name in targets:
                if name in ATTACK_INJECTORS:
                    inject_ts = base_ts+timedelta(hours=random.randint(2,20))
                    evts = ATTACK_INJECTORS[name](inject_ts)
                    logs.extend(evts)
                    print(f"[+] Injected {len(evts)} events for: {name}")
    logs.sort(key=lambda x: x["time"])
    anomalies = sum(1 for e in logs if e.get("is_anomaly"))
    print(f"\n📊 Total:{len(logs)} | Normal:{len(logs)-anomalies} | Anomalies:{anomalies}")
    if output_file:
        with open(output_file,"w") as f: json.dump(logs,f,indent=2)
        print(f"✅ Saved → {output_file}")
    return logs

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events",type=int,default=500)
    ap.add_argument("--attack",nargs="+",default=["all"])
    ap.add_argument("--output",default="synthetic_logs.json")
    args = ap.parse_args()
    generate_logs(num_events=args.events,attacks=args.attack,output_file=args.output)
