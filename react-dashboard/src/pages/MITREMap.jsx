import React, { useState, useEffect } from "react";

const C = { navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
            cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
            red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B" };

const SEV_CLR = { CRITICAL:C.red, HIGH:C.amber, MEDIUM:C.cyan, LOW:C.green };

export default function MITREMap({ api }) {
  const [techniques, setTechs]  = useState([]);
  const [selected,   setSelected] = useState(null);
  const [search,     setSearch]   = useState("");

  useEffect(() => {
    fetch(`${api}/mitre/techniques`)
      .then(r=>r.json()).then(setTechs).catch(()=>{});
  }, [api]);

  const filtered = techniques.filter(t =>
    !search ||
    t.id.toLowerCase().includes(search.toLowerCase()) ||
    t.name.toLowerCase().includes(search.toLowerCase()) ||
    t.tactic.toLowerCase().includes(search.toLowerCase())
  );

  const grouped = filtered.reduce((acc, t) => {
    const tac = t.tactic.split(",")[0].trim();
    if (!acc[tac]) acc[tac] = [];
    acc[tac].push(t);
    return acc;
  }, {});

  return (
    <div style={{ padding:28, display:"grid", gridTemplateColumns:"1fr 360px", gap:20 }}>

      <div>
        <h1 style={{ margin:"0 0 6px", fontSize:24, fontWeight:800 }}>🎯 MITRE ATT&CK Map</h1>
        <div style={{ color:C.muted, fontSize:13, marginBottom:20 }}>
          IAM & NHI-specific techniques loaded in ChromaDB RAG
        </div>

        <input value={search} onChange={e=>setSearch(e.target.value)}
          placeholder="Search technique, tactic, ID..."
          style={{ width:"100%", padding:"10px 14px", background:C.card,
                   border:`1px solid ${C.border}`, borderRadius:6,
                   color:"#fff", fontSize:13, outline:"none",
                   boxSizing:"border-box", marginBottom:18 }} />

        {Object.entries(grouped).map(([tactic, techs]) => (
          <div key={tactic} style={{ marginBottom:20 }}>
            <div style={{ fontSize:11, fontWeight:700, color:C.amber,
                          letterSpacing:1, textTransform:"uppercase",
                          marginBottom:10, borderBottom:`1px solid ${C.border}`,
                          paddingBottom:6 }}>
              {tactic}
            </div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
              {techs.map(t => {
                const sclr = SEV_CLR[t.severity] || C.cyan;
                const isSelected = selected?.id === t.id;
                return (
                  <div key={t.id} onClick={()=>setSelected(isSelected ? null : t)}
                    style={{ padding:"8px 14px", background: isSelected ? `${sclr}22` : C.card,
                             border:`1px solid ${isSelected ? sclr : C.border}`,
                             borderRadius:6, cursor:"pointer", minWidth:160,
                             transition:"all 0.15s" }}>
                    <div style={{ fontSize:11, color:sclr, fontWeight:700,
                                   fontFamily:"monospace" }}>{t.id}</div>
                    <div style={{ fontSize:12, color:C.silver, marginTop:2,
                                   lineHeight:1.3 }}>{t.name}</div>
                    <div style={{ fontSize:10, marginTop:4, padding:"2px 6px",
                                   display:"inline-block", borderRadius:3,
                                   background:`${sclr}33`, color:sclr,
                                   fontWeight:700 }}>
                      {t.severity}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel */}
      <div>
        <div style={{ background:C.card, border:`1px solid ${C.border}`,
                      borderRadius:10, position:"sticky", top:20 }}>
          {!selected
            ? <div style={{ padding:32, color:C.muted, fontSize:13,
                             textAlign:"center" }}>
                Click a technique to see details
              </div>
            : (() => {
                const sclr = SEV_CLR[selected.severity] || C.cyan;
                return (
                  <>
                    <div style={{ padding:"14px 18px", background:`${sclr}18`,
                                   borderBottom:`1px solid ${sclr}` }}>
                      <div style={{ fontSize:13, fontWeight:700, color:sclr,
                                     fontFamily:"monospace" }}>{selected.id}</div>
                      <div style={{ fontSize:15, fontWeight:800, color:"#fff",
                                     marginTop:4 }}>{selected.name}</div>
                      <div style={{ fontSize:11, color:C.amber, marginTop:4 }}>
                        {selected.tactic}
                      </div>
                    </div>
                    <div style={{ padding:"16px 18px" }}>
                      <div style={{ fontSize:11, color:C.muted, marginBottom:6,
                                     textTransform:"uppercase", letterSpacing:1 }}>
                        Description
                      </div>
                      <p style={{ fontSize:12, color:C.silver, lineHeight:1.65, margin:"0 0 16px" }}>
                        {selected.text}
                      </p>
                      <div style={{ fontSize:11, color:C.muted, marginBottom:6,
                                     textTransform:"uppercase", letterSpacing:1 }}>
                        Remediation
                      </div>
                      <p style={{ fontSize:12, color:C.green, lineHeight:1.65, margin:"0 0 16px" }}>
                        {selected.remediation}
                      </p>
                      <div style={{ fontSize:11, color:C.muted, marginBottom:6,
                                     textTransform:"uppercase", letterSpacing:1 }}>
                        PCI-DSS Mapping
                      </div>
                      <p style={{ fontSize:12, color:C.amber, lineHeight:1.65, margin:"0 0 16px" }}>
                        {selected.pci_dss}
                      </p>
                      <a href={`https://attack.mitre.org/techniques/${selected.id.replace(".","/")}`}
                         target="_blank" rel="noreferrer"
                         style={{ display:"block", padding:"8px 14px",
                                   background:`${C.cyan}18`, border:`1px solid ${C.cyan}`,
                                   borderRadius:6, color:C.cyan, textDecoration:"none",
                                   fontSize:12, textAlign:"center" }}>
                        ↗ View on MITRE ATT&CK
                      </a>
                    </div>
                  </>
                );
              })()
          }
        </div>
      </div>
    </div>
  );
}
