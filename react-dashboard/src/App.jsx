import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import AttackGraph from "./pages/AttackGraph";
import Analysis from "./pages/Analysis";
import MITREMap from "./pages/MITREMap";
import { AlertTriangle, Shield, Activity, GitBranch, Crosshair, Search } from "lucide-react";
import { useAlertStore } from "./store/alertStore";

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function App() {
  const { liveAlerts, addAlert } = useAlertStore();
  const [wsConnected, setWsConnected] = useState(false);

  // WebSocket for live alerts
  useEffect(() => {
    const connectWS = () => {
      const ws = new WebSocket(`${API.replace("http","ws")}/ws/alerts`);
      ws.onopen    = () => { setWsConnected(true); console.log("[WS] Connected"); };
      ws.onclose   = () => { setWsConnected(false); setTimeout(connectWS, 3000); };
      ws.onmessage = (e) => {
        try { addAlert(JSON.parse(e.data)); } catch {}
      };
      return ws;
    };
    const ws = connectWS();
    return () => ws.close();
  }, [addAlert]);

  const navItems = [
    { to: "/",         icon: Activity,      label: "Dashboard"   },
    { to: "/incidents",icon: AlertTriangle,  label: "Incidents"   },
    { to: "/graph",    icon: GitBranch,      label: "Attack Graph"},
    { to: "/analyze",  icon: Search,         label: "Analyze"     },
    { to: "/mitre",    icon: Crosshair,      label: "MITRE Map"   },
  ];

  return (
    <BrowserRouter>
      <div style={{ display:"flex", minHeight:"100vh", background:"#050E1F", color:"#fff",
                    fontFamily:"'Segoe UI', sans-serif" }}>

        {/* Sidebar */}
        <aside style={{ width:220, background:"#0A1628", borderRight:"1px solid #1A3A6B",
                        display:"flex", flexDirection:"column", padding:"0 0 24px" }}>

          {/* Logo */}
          <div style={{ padding:"24px 20px 20px", borderBottom:"1px solid #1A3A6B" }}>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <Shield size={26} color="#00D4FF" />
              <div>
                <div style={{ fontSize:16, fontWeight:800, color:"#fff", letterSpacing:0.5 }}>AutonomSOC</div>
                <div style={{ fontSize:10, color:"#64748B" }}>Ghost Identity Hunter</div>
              </div>
            </div>
          </div>

          {/* WS status */}
          <div style={{ padding:"10px 20px" }}>
            <span style={{ fontSize:10, color: wsConnected ? "#00FF9C" : "#FF3B5C",
                           display:"flex", alignItems:"center", gap:6 }}>
              <span style={{ width:6, height:6, borderRadius:"50%",
                             background: wsConnected ? "#00FF9C" : "#FF3B5C",
                             display:"inline-block" }}/>
              {wsConnected ? "Live" : "Reconnecting..."}
            </span>
          </div>

          {/* Nav */}
          <nav style={{ flex:1, padding:"8px 0" }}>
            {navItems.map(({ to, icon: Icon, label }) => (
              <NavLink key={to} to={to} end={to==="/"} style={({ isActive }) => ({
                display:"flex", alignItems:"center", gap:12, padding:"12px 20px",
                color: isActive ? "#00D4FF" : "#8BA4C7", textDecoration:"none",
                background: isActive ? "#0D2040" : "transparent",
                borderLeft: isActive ? "3px solid #00D4FF" : "3px solid transparent",
                fontSize:14, fontWeight: isActive ? 600 : 400,
                transition:"all 0.15s",
              })}>
                <Icon size={18} />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* Live alert count */}
          {liveAlerts.length > 0 && (
            <div style={{ margin:"0 12px", padding:"12px 16px", background:"#1A0010",
                          border:"1px solid #FF3B5C", borderRadius:8 }}>
              <div style={{ fontSize:11, color:"#FF3B5C", fontWeight:700 }}>
                🚨 {liveAlerts.length} Live Alert{liveAlerts.length>1?"s":""}
              </div>
              <div style={{ fontSize:10, color:"#8BA4C7", marginTop:2 }}>
                {liveAlerts[0]?.identity_id?.slice(0,20)}
              </div>
            </div>
          )}

          {/* Bottom tools */}
          <div style={{ padding:"16px 20px 0", borderTop:"1px solid #1A3A6B", marginTop:16 }}>
            <div style={{ fontSize:10, color:"#64748B", marginBottom:8 }}>TOOLS</div>
            {[
              { label:"Neo4j Browser",  url:"http://localhost:7474" },
              { label:"Kafka UI",       url:"http://localhost:8090" },
              { label:"TheHive",        url:"http://localhost:9000" },
              { label:"API Docs",       url:"http://localhost:8000/docs" },
            ].map(t => (
              <a key={t.label} href={t.url} target="_blank" rel="noreferrer"
                 style={{ display:"block", fontSize:11, color:"#8BA4C7",
                          textDecoration:"none", padding:"3px 0",
                          ":hover":{color:"#00D4FF"} }}>
                ↗ {t.label}
              </a>
            ))}
          </div>
        </aside>

        {/* Main content */}
        <main style={{ flex:1, overflow:"auto" }}>
          <Routes>
            <Route path="/"          element={<Dashboard   api={API} />} />
            <Route path="/incidents" element={<Incidents   api={API} />} />
            <Route path="/incidents/:id" element={<IncidentDetail api={API} />} />
            <Route path="/graph"     element={<AttackGraph api={API} />} />
            <Route path="/analyze"   element={<Analysis    api={API} />} />
            <Route path="/mitre"     element={<MITREMap    api={API} />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
