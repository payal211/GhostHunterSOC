import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

const C = { navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
            cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
            red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B" };
const RISK_CLR = { CRITICAL:C.red, HIGH:C.amber, MEDIUM:C.cyan, LOW:C.green };

export default function Incidents({ api }) {
  const [cases,   setCases]   = useState([]);
  const [filter,  setFilter]  = useState("ALL");
  const [search,  setSearch]  = useState("");
  const [loading, setLoading] = useState(true);
  const nav = useNavigate();

  useEffect(() => {
    fetch(`${api}/cases?limit=200`)
      .then(r => r.json())
      .then(d => { setCases(d.cases || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [api]);

  const filtered = cases
    .filter(c => c.escalated)
    .filter(c => filter === "ALL" || c.risk_level === filter)
    .filter(c => !search ||
      (c.identity_id || "").toLowerCase().includes(search.toLowerCase()) ||
      (c.mitre_technique || "").toLowerCase().includes(search.toLowerCase()) ||
      (c.case_id || "").toLowerCase().includes(search.toLowerCase()));

  const btn = (label, val, clr) => (
    <button key={val} onClick={() => setFilter(val)} style={{
      padding:"6px 16px", borderRadius:6, fontSize:12, fontWeight:700, cursor:"pointer",
      background: filter===val ? (clr||C.cyan)+"22" : "transparent",
      border:`1px solid ${filter===val ? (clr||C.cyan) : C.border}`,
      color: filter===val ? (clr||C.cyan) : C.muted }}>
      {label}
    </button>
  );

  return (
    <div style={{ padding:28 }}>
      <h1 style={{ margin:"0 0 6px", fontSize:24, fontWeight:800 }}>🚨 Incident Cases</h1>
      <div style={{ color:C.muted, fontSize:13, marginBottom:24 }}>
        {filtered.length} incidents · all auto-contained by AutonomSOC agents
      </div>

      {/* Controls */}
      <div style={{ display:"flex", gap:10, marginBottom:20, flexWrap:"wrap" }}>
        <input value={search} onChange={e=>setSearch(e.target.value)}
          placeholder="Search identity, MITRE, case ID..."
          style={{ flex:1, minWidth:220, padding:"8px 14px", background:C.card,
                   border:`1px solid ${C.border}`, borderRadius:6, color:"#fff",
                   fontSize:13, outline:"none" }} />
        {btn("All","ALL",C.cyan)}
        {btn("Critical","CRITICAL",C.red)}
        {btn("High","HIGH",C.amber)}
        {btn("Medium","MEDIUM",C.cyan)}
      </div>

      {/* Table */}
      <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden" }}>
        {/* Header */}
        <div style={{ display:"grid", gridTemplateColumns:"140px 1fr 130px 110px 90px 90px 80px",
                      gap:16, padding:"10px 18px", background:"#0A1628",
                      borderBottom:`1px solid ${C.border}`,
                      fontSize:11, color:C.muted, fontWeight:700, letterSpacing:1 }}>
          {["CASE ID","IDENTITY","MITRE","RISK","SCORE","MTTC","STATUS"].map(h=>(
            <span key={h}>{h}</span>
          ))}
        </div>

        {loading
          ? <div style={{ padding:32, color:C.muted, textAlign:"center" }}>Loading incidents...</div>
          : filtered.length === 0
            ? <div style={{ padding:32, color:C.muted, textAlign:"center" }}>
                No incidents found. Run an analysis scenario to generate cases.
              </div>
            : filtered.map(c => {
                const clr = RISK_CLR[c.risk_level] || C.muted;
                return (
                  <div key={c.case_id} onClick={() => nav(`/incidents/${c.case_id}`)}
                    style={{ display:"grid",
                             gridTemplateColumns:"140px 1fr 130px 110px 90px 90px 80px",
                             gap:16, padding:"13px 18px", cursor:"pointer",
                             borderBottom:`1px solid ${C.border}`,
                             transition:"background 0.15s" }}
                    onMouseEnter={e=>e.currentTarget.style.background="#0A1628"}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>

                    <span style={{ fontSize:12, color:C.cyan, fontWeight:700,
                                   fontFamily:"monospace" }}>
                      {c.case_id?.slice(-8)}
                    </span>
                    <span style={{ fontSize:13, color:"#fff", overflow:"hidden",
                                   textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {c.identity_id || "Unknown"}
                    </span>
                    <span style={{ fontSize:11, color:C.silver, fontFamily:"monospace" }}>
                      {c.mitre_technique || "—"}
                    </span>
                    <span style={{ fontSize:12, fontWeight:700, color:clr }}>{c.risk_level}</span>
                    <span style={{ fontSize:12, color:C.silver }}>
                      {typeof c.risk_score === "number" ? c.risk_score.toFixed(0) : "?"}/100
                    </span>
                    <span style={{ fontSize:12, color:C.green }}>{c.mttc_seconds}s</span>
                    <span style={{ fontSize:11, padding:"2px 8px", borderRadius:4,
                                   background:`${clr}22`, color:clr, fontWeight:700,
                                   display:"inline-block", textAlign:"center" }}>
                      {c.status}
                    </span>
                  </div>
                );
              })
        }
      </div>
    </div>
  );
}
