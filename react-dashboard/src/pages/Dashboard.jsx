import React, { useState, useEffect } from "react";
import { AlertTriangle, Shield, Clock, Zap, TrendingUp, Activity } from "lucide-react";

const C = {
  navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
  cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
  red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B",
};

const RISK_COLORS = { CRITICAL:C.red, HIGH:C.amber, MEDIUM:C.cyan, LOW:C.green };

function MetricCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div style={{ background:C.card, border:`1px solid ${color||C.border}`,
                  borderRadius:10, padding:"20px 22px", flex:1, minWidth:160 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <div style={{ fontSize:11, color:C.muted, textTransform:"uppercase",
                        letterSpacing:1, marginBottom:6 }}>{label}</div>
          <div style={{ fontSize:34, fontWeight:900, color:color||C.white, lineHeight:1 }}>{value}</div>
          {sub && <div style={{ fontSize:11, color:C.muted, marginTop:6 }}>{sub}</div>}
        </div>
        {Icon && <Icon size={28} color={color||C.muted} style={{ opacity:0.5 }} />}
      </div>
    </div>
  );
}

function AlertRow({ c }) {
  const clr = RISK_COLORS[c.risk_level] || C.muted;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:14, padding:"12px 16px",
                  borderBottom:`1px solid ${C.border}`, cursor:"pointer",
                  transition:"background 0.15s" }}
         onClick={() => window.location.href=`/incidents/${c.case_id}`}>
      <div style={{ width:8, height:8, borderRadius:"50%", background:clr, flexShrink:0 }} />
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:13, color:"#fff", fontWeight:600, overflow:"hidden",
                      textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
          {c.identity_id || "Unknown Identity"}
        </div>
        <div style={{ fontSize:11, color:C.muted }}>
          {c.mitre_technique || "?"} · {c.identity_type || "?"}
        </div>
      </div>
      <div style={{ textAlign:"right", flexShrink:0 }}>
        <div style={{ fontSize:11, fontWeight:700, color:clr }}>{c.risk_level}</div>
        <div style={{ fontSize:10, color:C.muted }}>{c.mttc_seconds}s MTTC</div>
      </div>
      <div style={{ fontSize:11, padding:"3px 8px", borderRadius:4,
                    background:`${clr}22`, color:clr, fontWeight:700 }}>
        {c.status}
      </div>
    </div>
  );
}

function RiskBar({ label, count, total, color }) {
  const pct = total > 0 ? (count/total*100).toFixed(0) : 0;
  return (
    <div style={{ marginBottom:12 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
        <span style={{ fontSize:12, color:C.silver }}>{label}</span>
        <span style={{ fontSize:12, color, fontWeight:700 }}>{count} ({pct}%)</span>
      </div>
      <div style={{ background:"#0A1628", borderRadius:4, height:6 }}>
        <div style={{ width:`${pct}%`, background:color, borderRadius:4, height:6,
                      transition:"width 0.5s ease" }} />
      </div>
    </div>
  );
}

export default function Dashboard({ api }) {
  const [stats, setStats]       = useState(null);
  const [graphStats, setGraphStats] = useState(null);
  const [cases, setCases]       = useState([]);
  const [loading, setLoading]   = useState(true);

  const load = async () => {
    try {
      const [s, c, g] = await Promise.all([
        fetch(`${api}/stats`).then(r => r.json()),
        fetch(`${api}/cases?limit=20&escalated=true`).then(r => r.json()),
        fetch(`${api}/graph/stats`).then(r => r.json()),
      ]);
      setStats(s);
      setCases(c.cases || []);
      setGraphStats(g);
    } catch (e) {
      console.error("API unreachable:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); const id = setInterval(load,10000); return ()=>clearInterval(id); }, []);

  if (loading) return (
    <div style={{ display:"flex", justifyContent:"center", alignItems:"center", height:"80vh" }}>
      <div style={{ color:C.cyan, fontSize:16 }}>⟳ Connecting to AutonomSOC API...</div>
    </div>
  );

  const rb = stats?.risk_breakdown || {};
  const total = stats?.total_events_processed || 0;
  const techniques = Object.entries(stats?.top_techniques || {});

  return (
    <div style={{ padding:28 }}>

      {/* Header */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:28 }}>
        <div>
          <h1 style={{ margin:0, fontSize:24, fontWeight:800 }}>🛡️ Live SOC Dashboard</h1>
          <div style={{ fontSize:12, color:C.muted, marginTop:4 }}>
            Auto-refreshing · {new Date().toLocaleTimeString()}
            {graphStats?.incidents != null && (
              <span style={{ marginLeft:16 }}>
                Graph incidents: {graphStats.incidents.toLocaleString()} · Neo4j persisted
              </span>
            )}
          </div>
        </div>
        <button onClick={load} style={{ padding:"8px 18px", background:C.card,
                border:`1px solid ${C.border}`, borderRadius:6, color:C.cyan,
                cursor:"pointer", fontSize:13 }}>
          ↺ Refresh
        </button>
      </div>

      {/* Metrics row */}
      <div style={{ display:"flex", gap:16, marginBottom:24, flexWrap:"wrap" }}>
        <MetricCard label="Events Processed" value={total.toLocaleString()}
                    color={C.cyan} icon={Activity} sub="Total ingested" />
        <MetricCard label="Incidents" value={stats?.total_escalated||0}
                    color={C.red} icon={AlertTriangle} sub={stats?.escalation_rate} />
        <MetricCard label="Avg MTTC" value={`${stats?.avg_mttc_seconds||0}s`}
                    color={C.green} icon={Clock} sub="Mean-time-to-contain" />
        <MetricCard label="Playbooks Run" value={stats?.playbooks_executed||0}
                    color={C.amber} icon={Zap} sub="Automated responses" />
        <MetricCard label="Critical" value={rb.CRITICAL||0}
                    color={C.red} icon={Shield} sub="Highest severity" />
        <MetricCard label="Graph Incidents" value={graphStats?.incidents||0}
                    color={C.purple} icon={TrendingUp} sub="Neo4j persisted count" />
      </div>

      {/* Main content split */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, marginBottom:20 }}>

        {/* Risk distribution */}
        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10, padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, marginBottom:18 }}>Risk Distribution</div>
          <RiskBar label="CRITICAL" count={rb.CRITICAL||0} total={total} color={C.red} />
          <RiskBar label="HIGH"     count={rb.HIGH||0}     total={total} color={C.amber} />
          <RiskBar label="MEDIUM"   count={rb.MEDIUM||0}   total={total} color={C.cyan} />
          <RiskBar label="LOW"      count={rb.LOW||0}      total={total} color={C.green} />
        </div>

        {/* Top MITRE techniques */}
        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10, padding:20 }}>
          <div style={{ fontSize:14, fontWeight:700, marginBottom:18 }}>Top MITRE Techniques</div>
          {techniques.length === 0
            ? <div style={{ color:C.muted, fontSize:13 }}>No incidents yet — run an analysis.</div>
            : techniques.slice(0,5).map(([tech, count], i) => (
              <div key={tech} style={{ display:"flex", alignItems:"center", gap:12,
                                       marginBottom:10 }}>
                <div style={{ width:24, height:24, borderRadius:4, background:"#0A1628",
                               display:"flex", alignItems:"center", justifyContent:"center",
                               fontSize:11, color:C.muted, fontWeight:700 }}>{i+1}</div>
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:12, color:C.white, fontWeight:600 }}>{tech}</div>
                </div>
                <div style={{ fontSize:12, fontWeight:700, color:C.cyan }}>{count}</div>
              </div>
            ))
          }
        </div>
      </div>

      {/* Recent incidents table */}
      <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10 }}>
        <div style={{ padding:"16px 20px", borderBottom:`1px solid ${C.border}`,
                      display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div style={{ fontSize:14, fontWeight:700 }}>Recent Incidents</div>
          <a href="/incidents" style={{ fontSize:12, color:C.cyan, textDecoration:"none" }}>
            View all →
          </a>
        </div>
        {cases.length === 0
          ? <div style={{ padding:24, color:C.muted, fontSize:13 }}>
              No incidents yet. Go to Analyze to run a scenario.
            </div>
          : cases.slice(0,10).map(c => <AlertRow key={c.case_id} c={c} />)
        }
      </div>
    </div>
  );
}
