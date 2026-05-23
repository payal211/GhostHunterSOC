import React, { useState, useEffect, useRef } from "react";

const C = { navy:"#050E1F", card:"#0D1F3C", border:"#1A3A6B",
            cyan:"#00D4FF", green:"#00FF9C", amber:"#FFB400",
            red:"#FF3B5C", purple:"#9B5DE5", silver:"#CBD5E1", muted:"#64748B" };

const NODE_COLORS = {
  Identity:"#00D4FF", Resource:"#00FF9C", IP:"#FF3B5C",
  Incident:"#FFB400", MITRETechnique:"#9B5DE5", GeoLocation:"#00A896",
};

const REL_COLORS = {
  ACCESSED:"#00D4FF33", MOVED_LATERALLY:"#FF3B5C",
  ESCALATED_TO:"#FFB400", USED_IP:"#9B5DE5aa",
  INVOLVES:"#FFB40088", HAD_ROLE:"#64748B",
};

// Simple force-layout canvas renderer
function GraphCanvas({ nodes, edges, width, height }) {
  const canvasRef = useRef(null);
  const posRef    = useRef({});
  const velRef    = useRef({});
  const rafRef    = useRef(null);
  const [hover, setHover] = useState(null);

  // Initialise positions
  useEffect(() => {
    if (!nodes.length) return;
    const cx = width/2, cy = height/2;
    nodes.forEach((n, i) => {
      const angle = (i/nodes.length)*Math.PI*2;
      const r = Math.min(width,height)*0.3;
      posRef.current[n.id] = posRef.current[n.id] ||
        { x: cx + Math.cos(angle)*r, y: cy + Math.sin(angle)*r };
      velRef.current[n.id] = velRef.current[n.id] || { x:0, y:0 };
    });
  }, [nodes, width, height]);

  // Physics loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !nodes.length) return;
    const ctx = canvas.getContext("2d");

    const tick = () => {
      const pos = posRef.current;
      const vel = velRef.current;
      const cx = width/2, cy = height/2;

      // Repulsion
      nodes.forEach(a => nodes.forEach(b => {
        if (a.id === b.id) return;
        const dx = pos[a.id].x - pos[b.id].x;
        const dy = pos[a.id].y - pos[b.id].y;
        const d  = Math.max(Math.sqrt(dx*dx+dy*dy), 1);
        const f  = 3000 / (d*d);
        vel[a.id].x += (dx/d)*f;
        vel[a.id].y += (dy/d)*f;
      }));

      // Attraction (edges)
      edges.forEach(e => {
        if (!pos[e.source]||!pos[e.target]) return;
        const dx = pos[e.target].x - pos[e.source].x;
        const dy = pos[e.target].y - pos[e.source].y;
        const d  = Math.max(Math.sqrt(dx*dx+dy*dy),1);
        const f  = d * 0.015;
        vel[e.source].x += (dx/d)*f; vel[e.source].y += (dy/d)*f;
        vel[e.target].x -= (dx/d)*f; vel[e.target].y -= (dy/d)*f;
      });

      // Centre gravity
      nodes.forEach(n => {
        vel[n.id].x += (cx - pos[n.id].x)*0.002;
        vel[n.id].y += (cy - pos[n.id].y)*0.002;
      });

      // Apply + dampen + clamp
      nodes.forEach(n => {
        vel[n.id].x *= 0.85; vel[n.id].y *= 0.85;
        pos[n.id].x = Math.max(40, Math.min(width -40, pos[n.id].x + vel[n.id].x));
        pos[n.id].y = Math.max(40, Math.min(height-40, pos[n.id].y + vel[n.id].y));
      });

      // Draw
      ctx.clearRect(0,0,width,height);
      ctx.fillStyle = "#050E1F";
      ctx.fillRect(0,0,width,height);

      // Edges
      edges.forEach(e => {
        if (!pos[e.source]||!pos[e.target]) return;
        ctx.beginPath();
        ctx.moveTo(pos[e.source].x, pos[e.source].y);
        ctx.lineTo(pos[e.target].x, pos[e.target].y);
        ctx.strokeStyle = REL_COLORS[e.type] || "#1A3A6B";
        ctx.lineWidth   = e.anomalous ? 2 : 1;
        ctx.setLineDash(e.anomalous ? [] : [4,4]);
        ctx.stroke();
        ctx.setLineDash([]);
        // Label on edge midpoint
        const mx = (pos[e.source].x + pos[e.target].x)/2;
        const my = (pos[e.source].y + pos[e.target].y)/2;
        ctx.fillStyle = "#64748B";
        ctx.font = "9px monospace";
        ctx.fillText(e.type||"", mx, my);
      });

      // Nodes
      nodes.forEach(n => {
        const {x,y} = pos[n.id];
        const r = n.critical ? 18 : 13;
        const clr = NODE_COLORS[n.label] || C.cyan;
        ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
        ctx.fillStyle = clr+"44"; ctx.fill();
        ctx.strokeStyle = clr; ctx.lineWidth = n.critical ? 2.5 : 1.5; ctx.stroke();
        ctx.fillStyle = "#fff"; ctx.font = `bold ${r > 14 ? 10 : 9}px sans-serif`;
        ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.fillText(n.label?.charAt(0)||"?", x, y);
        ctx.fillStyle = "#CBD5E1"; ctx.font = "9px sans-serif";
        ctx.fillText((n.id||"").slice(0,20), x, y+r+10);
      });

      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [nodes, edges, width, height]);

  return <canvas ref={canvasRef} width={width} height={height}
                 style={{ borderRadius:8, display:"block" }} />;
}

export default function AttackGraph({ api }) {
  const [graphData, setGraph]   = useState({ nodes:[], edges:[] });
  const [stats,     setStats]   = useState(null);
  const [loading,   setLoading] = useState(true);
  const [demoLoaded,setDemo]    = useState(false);

  const loadGraph = async () => {
    setLoading(true);
    try {
      const [g, s] = await Promise.all([
        fetch(`${api}/graph/attack`).then(r=>r.json()),
        fetch(`${api}/graph/stats`).then(r=>r.json()),
      ]);
      setStats(s);

      // Transform API data into nodes + edges
      const nodeMap  = {};
      const edgeList = [];

      (g.nodes_and_edges||[]).forEach(row => {
        if (row.source && !nodeMap[row.source]) {
          nodeMap[row.source] = { id:row.source, label:row.source_type||"Identity",
                                   critical:(row.source_risk||0)>70 };
        }
        if (row.target && !nodeMap[row.target]) {
          nodeMap[row.target] = { id:row.target, label:row.target_label||"Resource",
                                   critical:false };
        }
        if (row.source && row.target) {
          edgeList.push({ source:row.source, target:row.target,
                          type:row.relationship, anomalous:true });
        }
      });

      setGraph({ nodes:Object.values(nodeMap), edges:edgeList });
    } catch(e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const loadDemo = async () => {
    try {
      await fetch(`${api.replace(":8000",":8000")}/graph/stats`); // ping
      // Load demo data into neo4j via backend
      setDemo(true);
    } catch {}
    await loadGraph();
  };

  useEffect(() => { loadGraph(); }, [api]);

  const W = Math.min(window.innerWidth - 300, 900);
  const H = 520;

  return (
    <div style={{ padding:28 }}>
      <h1 style={{ margin:"0 0 6px", fontSize:24, fontWeight:800 }}>🔗 Attack Graph</h1>
      <div style={{ color:C.muted, fontSize:13, marginBottom:22 }}>
        Neo4j-powered identity relationship and attack chain visualization
      </div>

      {/* Stats row */}
      {stats && (
        <div style={{ display:"flex", gap:14, marginBottom:22 }}>
          {[
            { l:"Identities",  v:stats.identities||0,   c:C.cyan   },
            { l:"Resources",   v:stats.resources||0,    c:C.green  },
            { l:"Incidents",   v:stats.incidents||0,    c:C.red    },
            { l:"High-Risk",   v:stats.high_risk||0,    c:C.amber  },
          ].map(m=>(
            <div key={m.l} style={{ background:C.card, border:`1px solid ${m.c}`,
                                     borderRadius:8, padding:"14px 20px", flex:1 }}>
              <div style={{ fontSize:11, color:C.muted }}>{m.l}</div>
              <div style={{ fontSize:28, fontWeight:900, color:m.c }}>{m.v}</div>
            </div>
          ))}
        </div>
      )}

      {/* Controls */}
      <div style={{ display:"flex", gap:10, marginBottom:16 }}>
        <button onClick={loadGraph} style={{ padding:"8px 18px", background:C.card,
            border:`1px solid ${C.border}`, borderRadius:6, color:C.cyan,
            cursor:"pointer", fontSize:13 }}>↺ Refresh Graph</button>
        <button onClick={loadDemo} style={{ padding:"8px 18px", background:`${C.purple}22`,
            border:`1px solid ${C.purple}`, borderRadius:6, color:C.purple,
            cursor:"pointer", fontSize:13 }}>🎮 Load Demo Scenario</button>
        <a href="http://localhost:7474" target="_blank" rel="noreferrer"
           style={{ padding:"8px 18px", background:C.card, border:`1px solid ${C.border}`,
                    borderRadius:6, color:C.green, fontSize:13, textDecoration:"none",
                    display:"flex", alignItems:"center" }}>
          ↗ Open Neo4j Browser
        </a>
      </div>

      {/* Graph canvas */}
      <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:10,
                    padding:16, marginBottom:16 }}>
        {loading
          ? <div style={{ height:H, display:"flex", alignItems:"center",
                          justifyContent:"center", color:C.muted }}>
              Loading graph from Neo4j...
            </div>
          : graphData.nodes.length === 0
            ? <div style={{ height:H, display:"flex", flexDirection:"column",
                             alignItems:"center", justifyContent:"center", gap:16 }}>
                <div style={{ color:C.muted, fontSize:14 }}>
                  No graph data yet. Run the demo or analyze some events first.
                </div>
                <div style={{ color:C.muted, fontSize:12 }}>
                  Or open Neo4j Browser at{" "}
                  <a href="http://localhost:7474" target="_blank" rel="noreferrer"
                     style={{ color:C.cyan }}>localhost:7474</a>
                </div>
              </div>
            : <GraphCanvas nodes={graphData.nodes} edges={graphData.edges} width={W} height={H} />
        }
      </div>

      {/* Legend */}
      <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:8,
                    padding:"12px 18px", display:"flex", gap:20, flexWrap:"wrap" }}>
        <span style={{ fontSize:11, color:C.muted, fontWeight:700, letterSpacing:1 }}>LEGEND:</span>
        {Object.entries(NODE_COLORS).map(([t,c])=>(
          <span key={t} style={{ fontSize:11, display:"flex", alignItems:"center", gap:6 }}>
            <span style={{ width:10, height:10, borderRadius:"50%", background:c,
                           display:"inline-block" }}/>
            <span style={{ color:C.silver }}>{t}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
