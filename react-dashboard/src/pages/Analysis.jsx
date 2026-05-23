import React, { useState } from "react";

const C = { navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
            cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
            red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B" };
const RISK_CLR = { CRITICAL:C.red, HIGH:C.amber, MEDIUM:C.cyan, LOW:C.green };

const SCENARIOS = {
  "🔴 Dormant NHI Reactivation": {
    identity_id:"svc_reporting_bot_447", identity_type:"service_account",
    src_ip:"185.220.101.55", geo:"RU", event_type:"api_call",
    endpoint:"/api/v2/transactions", risk_score:88.0,
    bytes_out:485000, mfa_used:false, days_since_last_active:243,
    is_anomaly:true, attack_type:"dormant_nhi_reactivation",
  },
  "🟡 OAuth Scope Creep": {
    identity_id:"oauth_connector_219", identity_type:"oauth_token",
    src_ip:"10.12.45.67", geo:"US-NY", event_type:"oauth_scope_grant",
    scope_added:"admin:config", total_scopes:5,
    risk_score:78.0, is_anomaly:true, attack_type:"oauth_scope_creep",
  },
  "🔵 API Key Exfiltration": {
    identity_id:"api_key_ci_cd_runner_331", identity_type:"api_key",
    src_ip:"91.108.4.136", geo:"CN", event_type:"api_call",
    endpoint:"/api/v2/accounts", context:"unknown_external",
    risk_score:94.0, bytes_out:890000,
    is_anomaly:true, attack_type:"api_key_exfiltration",
  },
  "⚫ Golden Ticket Attack": {
    identity_id:"svc_payment_processor_123", identity_type:"service_account",
    src_ip:"45.33.32.156", geo:"RU", event_type:"ldap_query",
    query_type:"SPN_enumeration", target:"krbtgt",
    risk_score:85.0, is_anomaly:true, attack_type:"golden_ticket",
  },
};

const STAGES = [
  "Identity Monitor",
  "Behavior Analyzer",
  "Threat Intel RAG",
  "Correlation Agent",
  "Response Agent",
  "Reporting Agent",
];
const DEFAULT_JSON = JSON.stringify(SCENARIOS["🔴 Dormant NHI Reactivation"], null, 2);

export default function Analysis({ api }) {
  const [eventJson, setEventJson] = useState(DEFAULT_JSON);
  const [result,    setResult]    = useState(null);
  const [running,   setRunning]   = useState(false);
  const [error,     setError]     = useState("");
  const [activeTab, setTab]       = useState("summary");
  const [pipelineLog, setPipelineLog] = useState([]);
  const [activeStage, setActiveStage] = useState(0);

  const buildTraceSections = (r) => {
    if (!r) return [];
    return [
      {
        title: "Identity Monitor",
        rows: [
          { label: "Anomalies", value: (r.anomalies || []).length ? r.anomalies.join(", ") : "No anomalies detected." },
          { label: "LLM Reasoning", value: r.identity_explanation || "No LLM explanation available." },
          { label: "Risk Score", value: r.risk_score != null ? `${r.risk_score}/100` : "—" },
          { label: "Risk Level", value: r.risk_level || "—" },
        ],
      },
      {
        title: "Behavior Analyzer",
        rows: [
          { label: "Behavior Score", value: r.behavior_score?.llm_behavior_score != null ? `${r.behavior_score.llm_behavior_score}/100` : "Not scored" },
          { label: "Behavior Reasoning", value: r.behavior_score?.llm_reasoning || "No reasoning returned." },
          { label: "Historical Events", value: r.behavior_score?.historical_event_count ?? "—" },
          { label: "Deviations", value: (r.behavior_score?.deviations || []).length ? r.behavior_score.deviations.join("; ") : "No deviations listed." },
        ],
      },
      {
        title: "Threat Intel RAG",
        rows: [
          { label: "Primary Technique", value: r.mitre_technique || r.mitre_technique_name || "Unknown" },
          { label: "Tactic", value: r.mitre_tactic || "Unknown" },
          { label: "LLM Assessment", value: r.threat_assessment || "No threat assessment available." },
          { label: "Matched Techniques", value: (r.relevant_techniques || []).length ? r.relevant_techniques.join(", ") : "No techniques matched." },
        ],
      },
      {
        title: "Correlation Agent",
        rows: [
          { label: "Attack Narrative", value: r.attack_narrative || "No attack narrative available." },
          { label: "Related Events", value: r.related_event_count ?? 0 },
          { label: "Blast Radius", value: `${r.blast_radius ?? 0}/100` },
          { label: "Affected Identities", value: (r.affected_identities || []).length ? r.affected_identities.join(", ") : "None" },
        ],
      },
      {
        title: "Response Agent",
        rows: [
          { label: "Playbooks", value: (r.response_actions || []).length ? r.response_actions.join(", ") : "No playbooks executed." },
          { label: "MTTC", value: r.mttc_seconds != null ? `${r.mttc_seconds}s` : "—" },
          { label: "Escalated", value: r.escalated ? "Yes" : "No" },
          { label: "Report Status", value: r.report ? "Report generated" : "No report generated." },
        ],
      },
    ];
  };

  const run = async () => {
    setError(""); setResult(null); setPipelineLog([]); setActiveStage(0); setRunning(true);
    let stageInterval = null;

    try {
      stageInterval = setInterval(() => {
        setActiveStage((prev) => Math.min(prev + 1, STAGES.length - 1));
      }, 500);

      const ev = JSON.parse(eventJson);
      const resp = await fetch(`${api}/analyze`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ events:[ev], historical_context:[] }),
      });
      const data = await resp.json();
      if (Array.isArray(data) && data[0]) {
        setResult(data[0]);
        setPipelineLog(data[0].pipeline_log || []);
      } else {
        setError(JSON.stringify(data));
      }
    } catch(e) {
      setError(e.message);
    } finally {
      if (stageInterval) clearInterval(stageInterval);
      setActiveStage(STAGES.length - 1);
      setRunning(false);
    }
  };

  const clr = result ? (RISK_CLR[result.risk_level]||C.muted) : C.muted;

  

  const downloadFile = async (url, filename) => {
    try {
      const res = await fetch(url, { method: 'GET' });
      if (!res.ok) {
        const text = await res.text();
        console.error('Download failed', res.status, text);
        alert(`Download failed: ${res.status} - check console for details`);
        return;
      }
      const blob = await res.blob();
      const link = document.createElement('a');
      const href = URL.createObjectURL(blob);
      link.href = href;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(href);
    } catch (e) {
      console.error(e);
      alert('Failed to download file. See console for details.');
    }
  };

  const downloadTrace = () => {
    if (!result?.case_id) return;
    const url = `${api}/cases/${result.case_id}/export/trace`;
    const filename = `${result?.case_id || 'agent-trace'}-trace.pdf`;
    downloadFile(url, filename);
  };

  const downloadReport = () => {
    if (!result?.case_id) return;
    const url = `${api}/cases/${result.case_id}/export/pdf`;
    const filename = `${result?.case_id || 'incident-report'}-report.pdf`;
    downloadFile(url, filename);
  };

  return (
    <div style={{ padding:28 }}>
      <h1 style={{ margin:"0 0 6px", fontSize:24, fontWeight:800 }}>🔬 Event Analysis</h1>
      <div style={{ color:C.muted, fontSize:13, marginBottom:24 }}>
        Run any security event through all 6 AI agents and get a full incident report
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>

        {/* Left: Input */}
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:C.silver, marginBottom:10 }}>
            Quick Scenarios
          </div>
          <div style={{ display:"flex", flexWrap:"wrap", gap:8, marginBottom:16 }}>
            {Object.entries(SCENARIOS).map(([label, ev]) => (
              <button key={label} onClick={()=>setEventJson(JSON.stringify(ev,null,2))}
                style={{ padding:"6px 14px", background:C.card, border:`1px solid ${C.border}`,
                         borderRadius:6, color:C.silver, cursor:"pointer", fontSize:12 }}>
                {label}
              </button>
            ))}
          </div>

          <div style={{ fontSize:13, fontWeight:700, color:C.silver, marginBottom:8 }}>
            Event JSON
          </div>
          <textarea value={eventJson} onChange={e=>setEventJson(e.target.value)}
            style={{ width:"100%", height:340, background:"#020810",
                     border:`1px solid ${C.border}`, borderRadius:8,
                     color:C.green, fontFamily:"monospace", fontSize:12,
                     padding:14, resize:"vertical", outline:"none", boxSizing:"border-box" }} />

          <button onClick={run} disabled={running}
            style={{ marginTop:12, width:"100%", padding:"12px 0",
                     background: running ? C.card : `${C.cyan}22`,
                     border:`1px solid ${running ? C.border : C.cyan}`,
                     borderRadius:8, color: running ? C.muted : C.cyan,
                     fontSize:15, fontWeight:700, cursor: running ? "not-allowed":"pointer",
                     transition:"all 0.2s" }}>
            {running ? "⟳  Running 6-Agent Pipeline..." : "▶  Run Pipeline"}
          </button>

          {error && (
            <div style={{ marginTop:12, padding:12, background:"#1A0008",
                          border:`1px solid ${C.red}`, borderRadius:6,
                          color:C.red, fontSize:12, fontFamily:"monospace" }}>
              {error}
            </div>
          )}
        </div>

        {/* Right: Result */}
        <div>
          {!result && !running && (
            <div style={{ background:C.card, border:`1px solid ${C.border}`,
                          borderRadius:10, height:"100%", display:"flex",
                          alignItems:"center", justifyContent:"center",
                          color:C.muted, fontSize:14 }}>
              Results will appear here after you run the pipeline
            </div>
          )}

          {running && (
            <div style={{ background:C.card, border:`1px solid ${C.cyan}`,
                          borderRadius:10, padding:24 }}>
              <div style={{ color:C.cyan, fontWeight:700, fontSize:15, marginBottom:18 }}>
                🤖 Agents Working...
              </div>
              {STAGES.map((a,i)=>(
                <div key={a} style={{ display:'flex', gap:10, padding:'8px 0',
                                       borderBottom:`1px solid ${C.border}` }}>
                  <span style={{ color:i <= activeStage ? C.cyan : C.muted, fontSize:12 }}>
                    {i <= activeStage ? '✔' : '⟳'}
                  </span>
                  <span style={{ fontSize:13, color:i <= activeStage ? C.silver : C.muted }}>
                    {a}
                  </span>
                </div>
              ))}
            </div>
          )}

          {result && (
            <div style={{ background:C.card, border:`1px solid ${clr}`,
                          borderRadius:10, overflow:"hidden" }}>
              {/* Result header */}
              <div style={{ padding:"16px 20px", background:`${clr}18`,
                            borderBottom:`1px solid ${clr}`,
                            display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                <div>
                  <div style={{ fontSize:11, color:C.muted, fontFamily:"monospace" }}>
                    {result.case_id}
                  </div>
                  <div style={{ fontSize:18, fontWeight:800, color:clr, marginTop:2 }}>
                    {result.risk_level} RISK
                  </div>
                </div>
                <div style={{ textAlign:"right", display:"flex", gap:12, alignItems:"flex-end" }}>
                  {pipelineLog.length > 0 && (
                    <button onClick={downloadTrace}
                      style={{ padding:"8px 12px", background:C.navy, border:`1px solid ${clr}`,
                               borderRadius:8, color:C.cyan, fontSize:11, cursor:"pointer", marginRight:8 }}>
                      Download Trace
                    </button>
                  )}
                  {result?.report && (
                    <button onClick={downloadReport}
                      style={{ padding:"8px 12px", background:C.navy, border:`1px solid ${clr}`,
                               borderRadius:8, color:C.green, fontSize:11, cursor:"pointer" }}>
                      Download Report
                    </button>
                  )}
                  <div>
                    <div style={{ fontSize:28, fontWeight:900, color:clr }}>
                      {(result.risk_score||0).toFixed(0)}/100
                    </div>
                    <div style={{ fontSize:11, color:C.green }}>
                      Contained in {result.mttc_seconds}s
                    </div>
                  </div>
                </div>
              </div>

              {/* Tabs */}
              <div style={{ display:"flex", borderBottom:`1px solid ${C.border}` }}>
                {["summary","anomalies","response","report","trace"].map(t=>(
                  <button key={t} onClick={()=>setTab(t)} style={{
                    flex:1, padding:"9px 0", background:"none", border:"none",
                    borderBottom: activeTab===t ? `2px solid ${clr}` : "2px solid transparent",
                    color: activeTab===t ? clr : C.muted,
                    fontSize:12, fontWeight: activeTab===t ? 700 : 400,
                    cursor:"pointer", textTransform:"capitalize" }}>
                    {t}
                  </button>
                ))}
              </div>

              <div style={{ padding:"16px 18px", maxHeight:420, overflowY:"auto" }}>
                {activeTab==="summary" && (
                  <>
                    {[
                      ["Case ID",      result.case_id,              true ],
                      ["Identity",     result.identity_id,          false],
                      ["Type",         result.identity_type,        false],
                      ["MITRE",        result.mitre_technique,      true ],
                      ["Technique",    result.mitre_technique_name, false],
                      ["Tactic",       result.mitre_tactic,         false],
                      ["Blast Radius", `${result.blast_radius||0}/100`, false],
                    ].map(([l,v,m])=>(
                      <div key={l} style={{ display:"flex", gap:12, padding:"6px 0",
                                             borderBottom:`1px solid ${C.border}` }}>
                        <span style={{ fontSize:11, color:C.muted, minWidth:120 }}>{l}</span>
                        <span style={{ fontSize:12, color:C.silver,
                                       fontFamily:m?"monospace":"inherit" }}>{v||"—"}</span>
                      </div>
                    ))}
                  </>
                )}

                {activeTab==="anomalies" && (result.anomalies||[]).map((a,i)=>(
                  <div key={i} style={{ display:"flex", gap:10, padding:"8px 0",
                                         borderBottom:`1px solid ${C.border}` }}>
                    <span style={{ color:C.red, fontWeight:700 }}>!</span>
                    <span style={{ fontSize:12, color:C.silver }}>{a}</span>
                  </div>
                ))}

                {activeTab==="response" && (result.response_actions||[]).map((a,i)=>(
                  <div key={i} style={{ display:"flex", gap:10, padding:"8px 0",
                                         borderBottom:`1px solid ${C.border}` }}>
                    <span style={{ color:C.green }}>✓</span>
                    <span style={{ fontSize:12, color:C.silver }}>{a}</span>
                  </div>
                ))}

                {activeTab==="report" && (
                  <pre style={{ whiteSpace:"pre-wrap", wordBreak:"break-word",
                                color:C.silver, fontSize:11.5, lineHeight:1.7,
                                margin:0, fontFamily:"'Segoe UI',sans-serif" }}>
                    {result.report || "Report not available."}
                  </pre>
                )}

                {activeTab==="trace" && (
                  <div style={{ display:"grid", gap:18 }}>
                    {pipelineLog.length === 0 ? (
                      <div style={{ color:C.muted, padding:16 }}>
                        Trace will appear here once the pipeline finishes.
                      </div>
                    ) : (
                      <>
                        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                          {buildTraceSections(result).map((section) => (
                            <div key={section.title} style={{ background:C.navy, border:`1px solid ${C.border}`, borderRadius:10, padding:16 }}>
                              <div style={{ fontSize:13, fontWeight:700, color:C.cyan, marginBottom:10 }}>{section.title}</div>
                              {section.rows.map(({ label, value }) => (
                                <div key={label} style={{ marginBottom:10 }}>
                                  <div style={{ fontSize:10, color:C.muted, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</div>
                                  <div style={{ fontSize:12, color:C.silver, marginTop:4, whiteSpace:"pre-wrap", wordBreak:"break-word" }}>
                                    {value || "—"}
                                  </div>
                                </div>
                              ))}
                            </div>
                          ))}
                        </div>

                        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10, padding:16 }}>
                          <div style={{ fontSize:13, fontWeight:700, color:C.green, marginBottom:12 }}>Pipeline Audit Log</div>
                          {pipelineLog.map((line,i) => (
                            <div key={i} style={{ padding:"6px 8px", borderBottom: i < pipelineLog.length -1 ? `1px solid ${C.border}` : "none", color:C.silver, fontSize:12, fontFamily:"monospace" }}>
                              {line}
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
