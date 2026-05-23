import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Download } from "lucide-react";

const C = { navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
            cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
            red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B" };
const RISK_CLR = { CRITICAL:C.red, HIGH:C.amber, MEDIUM:C.cyan, LOW:C.green };

function Section({ title, color, children }) {
  return (
    <div style={{ background:C.card, border:`1px solid ${color||C.border}`,
                  borderRadius:10, marginBottom:16, overflow:"hidden" }}>
      <div style={{ padding:"12px 18px", background:`${color||C.border}22`,
                    borderBottom:`1px solid ${color||C.border}`,
                    fontSize:12, fontWeight:700, color:color||C.silver,
                    letterSpacing:0.5, textTransform:"uppercase" }}>
        {title}
      </div>
      <div style={{ padding:"16px 18px" }}>{children}</div>
    </div>
  );
}

function KV({ label, value, mono, color }) {
  return (
    <div style={{ display:"flex", gap:12, marginBottom:8, alignItems:"flex-start" }}>
      <span style={{ fontSize:11, color:C.muted, minWidth:140, flexShrink:0 }}>{label}</span>
      <span style={{ fontSize:13, color:color||C.silver,
                     fontFamily:mono?"monospace":"inherit", wordBreak:"break-all" }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

export default function IncidentDetail({ api }) {
  const { id } = useParams();
  const nav    = useNavigate();
  const [c, setC] = useState(null);
  const [tab, setTab] = useState("overview");

  const handleDownloadPDF = (type) => {
    const endpoint = type === "report" ? `/cases/${id}/export/pdf` : `/cases/${id}/export/trace`;
    window.open(`${api}${endpoint}`, "_blank");
  };

  useEffect(() => {
    fetch(`${api}/cases/${id}`)
      .then(r => r.json())
      .then(setC)
      .catch(console.error);
  }, [api, id]);

  if (!c) return (
    <div style={{ padding:40, color:C.muted, textAlign:"center" }}>Loading case {id}...</div>
  );

  const clr    = RISK_CLR[c.risk_level] || C.muted;
  const tabs   = ["overview","anomalies","mitre","response","report","pipeline"];
  const tabLabel= { overview:"Overview", anomalies:"Anomalies", mitre:"MITRE",
                    response:"Response", report:"Full Report", pipeline:"Agent Log" };

  return (
    <div style={{ padding:28 }}>

      {/* Back + header */}
      <button onClick={()=>nav("/incidents")} style={{ background:"none", border:"none",
        color:C.cyan, cursor:"pointer", fontSize:13, marginBottom:16, padding:0 }}>
        ← Back to Incidents
      </button>

      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between",
                    marginBottom:24, flexWrap:"wrap", gap:16 }}>
        <div>
          <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace",
                        marginBottom:4 }}>{c.case_id}</div>
          <h1 style={{ margin:0, fontSize:22, fontWeight:800 }}>
            {c.identity_id || "Unknown Identity"}
          </h1>
          <div style={{ fontSize:13, color:C.muted, marginTop:4 }}>
            {c.identity_type} · {c.created_at?.slice(0,19).replace("T"," ")} UTC
          </div>
        </div>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          <div style={{ padding:"6px 16px", borderRadius:6, background:`${clr}22`,
                        border:`1px solid ${clr}`, color:clr, fontWeight:800, fontSize:14 }}>
            {c.risk_level}
          </div>
          <div style={{ padding:"6px 16px", borderRadius:6, background:`${C.green}22`,
                        border:`1px solid ${C.green}`, color:C.green, fontWeight:700, fontSize:13 }}>
            {c.status}
          </div>
          <button onClick={() => handleDownloadPDF("report")} 
                  title="Download full incident report as PDF"
                  style={{ background:"none", border:"1px solid "+C.cyan, borderRadius:6,
                           color:C.cyan, cursor:"pointer", padding:"6px 12px", display:"flex",
                           alignItems:"center", gap:6, fontSize:13, fontWeight:600,
                           transition:"all 0.2s", ":hover":{background:C.cyan+"22"} }}>
            <Download size={16} />
            Report
          </button>
          <button onClick={() => handleDownloadPDF("trace")} 
                  title="Download agent pipeline trace as PDF"
                  style={{ background:"none", border:"1px solid "+C.amber, borderRadius:6,
                           color:C.amber, cursor:"pointer", padding:"6px 12px", display:"flex",
                           alignItems:"center", gap:6, fontSize:13, fontWeight:600,
                           transition:"all 0.2s", ":hover":{background:C.amber+"22"} }}>
            <Download size={16} />
            Trace
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display:"flex", gap:14, marginBottom:22, flexWrap:"wrap" }}>
        {[
          { l:"Risk Score", v:`${(c.risk_score||0).toFixed(0)}/100`, clr },
          { l:"MTTC",       v:`${c.mttc_seconds}s`,                  clr:C.green },
          { l:"Blast Radius",v:`${c.blast_radius||0}/100`,            clr:C.amber },
          { l:"Affected IDs",v:c.affected_identities?.length||0,      clr:C.purple },
          { l:"MITRE",       v:c.mitre_technique||"?",                clr:C.cyan },
        ].map(m=>(
          <div key={m.l} style={{ background:C.card, border:`1px solid ${m.clr}`,
                                   borderRadius:8, padding:"14px 18px", flex:1, minWidth:130 }}>
            <div style={{ fontSize:11, color:C.muted, marginBottom:4 }}>{m.l}</div>
            <div style={{ fontSize:22, fontWeight:900, color:m.clr,
                          fontFamily:"monospace" }}>{m.v}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display:"flex", gap:4, marginBottom:18, borderBottom:`1px solid ${C.border}`,
                    paddingBottom:0 }}>
        {tabs.map(t=>(
          <button key={t} onClick={()=>setTab(t)} style={{
            padding:"8px 16px", background:"none", cursor:"pointer",
            border:"none", borderBottom: tab===t ? `2px solid ${C.cyan}` : "2px solid transparent",
            color: tab===t ? C.cyan : C.muted, fontSize:13,
            fontWeight: tab===t ? 700 : 400, marginBottom:-1 }}>
            {tabLabel[t]}
          </button>
        ))}
      </div>

      {/* Tab: Overview */}
      {tab==="overview" && (
        <>
          <Section title="Identity Details" color={C.cyan}>
            <KV label="Identity ID"   value={c.identity_id}   mono />
            <KV label="Identity Type" value={c.identity_type} />
            <KV label="Case ID"       value={c.case_id}       mono />
            <KV label="Created"       value={c.created_at?.slice(0,19).replace("T"," ")+" UTC"} />
          </Section>
          <Section title="Attack Context" color={clr}>
            <KV label="MITRE Technique" value={c.mitre_technique}      color={clr} mono />
            <KV label="Technique Name"  value={c.mitre_technique_name} />
            <KV label="Tactic"          value={c.mitre_tactic}         color={C.amber} />
            <KV label="Blast Radius"    value={`${c.blast_radius||0}/100`} color={C.amber} />
            <KV label="Affected Identities"
                value={(c.affected_identities||[]).join(", ")||"None detected"} />
          </Section>
        </>
      )}

      {/* Tab: Anomalies */}
      {tab==="anomalies" && (
        <Section title="Detected Anomalies" color={C.red}>
          {(c.anomalies||[]).length===0
            ? <div style={{color:C.muted}}>No anomalies recorded.</div>
            : (c.anomalies||[]).map((a,i)=>(
              <div key={i} style={{ display:"flex", gap:12, padding:"10px 0",
                                     borderBottom:`1px solid ${C.border}` }}>
                <span style={{ color:C.red, fontWeight:700, fontSize:13, minWidth:20 }}>!</span>
                <span style={{ fontSize:13, color:C.silver }}>{a}</span>
              </div>
            ))
          }
        </Section>
      )}

      {/* Tab: MITRE */}
      {tab==="mitre" && (
        <Section title="MITRE ATT&CK Mapping" color={C.amber}>
          <KV label="Primary Technique" value={`${c.mitre_technique} — ${c.mitre_technique_name}`}
              color={C.amber} />
          <KV label="Tactic"           value={c.mitre_tactic}   color={C.amber} />
          <div style={{ marginTop:12 }}>
            <a href={`https://attack.mitre.org/techniques/${(c.mitre_technique||"").replace(".","/")}`}
               target="_blank" rel="noreferrer"
               style={{ color:C.cyan, fontSize:13 }}>
              ↗ View on MITRE ATT&CK Navigator
            </a>
          </div>
        </Section>
      )}

      {/* Tab: Response */}
      {tab==="response" && (
        <Section title="Automated Response Actions" color={C.green}>
          {(c.response_actions||[]).length===0
            ? <div style={{color:C.muted}}>No automated actions taken.</div>
            : (c.response_actions||[]).map((a,i)=>(
              <div key={i} style={{ display:"flex", gap:12, padding:"10px 0",
                                     borderBottom:`1px solid ${C.border}` }}>
                <span style={{ color:C.green, fontSize:16 }}>✓</span>
                <span style={{ fontSize:13, color:C.silver }}>{a}</span>
              </div>
            ))
          }
          <KV label="MTTC"      value={`${c.mttc_seconds}s`} color={C.green} />
          <KV label="Automated" value={c.mttc_seconds < 200 ? "Yes" : "Manual review required"} />
        </Section>
      )}

      {/* Tab: Full Report */}
      {tab==="report" && (
        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10,
                      padding:"20px 24px" }}>
          <div style={{ fontSize:11, color:C.muted, marginBottom:16,
                        textTransform:"uppercase", letterSpacing:1 }}>
            LLM-Generated Incident Report
          </div>
          <pre style={{ whiteSpace:"pre-wrap", wordBreak:"break-word",
                        color:C.silver, fontSize:13, lineHeight:1.7, margin:0,
                        fontFamily:"'Segoe UI', sans-serif" }}>
            {c.report || "Report not available."}
          </pre>
        </div>
      )}

      {/* Tab: Pipeline Log */}
      {tab==="pipeline" && (
        <div style={{ background:"#020810", border:`1px solid ${C.border}`, borderRadius:10,
                      padding:"16px 20px", fontFamily:"monospace" }}>
          {(c.pipeline_log||[]).length===0
            ? <div style={{color:C.muted}}>No pipeline log available.</div>
            : (c.pipeline_log||[]).map((line,i)=>{
                const clrLine = line.includes("🚨")||line.includes("CRITICAL") ? C.red
                              : line.includes("✅") ? C.green
                              : line.includes("⚠") ? C.amber : C.silver;
                return (
                  <div key={i} style={{ fontSize:12, color:clrLine,
                                         lineHeight:1.8, borderBottom:`1px solid #0D1F3C`,
                                         padding:"2px 0" }}>
                    <span style={{ color:C.muted, marginRight:12 }}>{String(i+1).padStart(2,"0")}</span>
                    {line}
                  </div>
                );
              })
          }
        </div>
      )}
    </div>
  );
}
