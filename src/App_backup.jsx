import React, { useMemo, useRef, useState } from "react";
import {
  Activity, ArrowRight, Bell, Check, Database, Download, Eye, EyeOff,
  FileCheck2, FileSearch, FileText, Fingerprint, Fish, Globe2, Hash,
  LayoutDashboard, Link2, LockKeyhole, LogOut, Mail, Menu, Network, Plus,
  Search, Settings, ShieldAlert, ShieldCheck, UploadCloud, X
} from "lucide-react";

const STAGES = [
  ["Email Input", "Upload and validate suspicious .eml evidence", Mail],
  ["Email Preprocessing", "Extract headers, sender, metadata and URLs", FileSearch],
  ["Threat Detection", "Rule-based checks and preliminary ML prediction", ShieldAlert],
  ["Threat Intelligence", "External IP/domain reputation is not configured", Globe2],
  ["Threat Correlation", "Group extracted indicators for analyst review", Network],
  ["Attack Graph & Timeline", "Visualize extracted evidence entities", Activity],
  ["Risk Score & Rating", "Calculate a transparent heuristic score", ShieldCheck],
  ["Forensic Report", "Prepare a downloadable evidence summary", FileText],
];

const navItems = [
  ["dashboard", "Dashboard", LayoutDashboard],
  ["cases", "Case Management", Database],
  ["upload", "Upload Evidence", UploadCloud],
  ["analysis", "Analysis Results", FileSearch],
  ["graph", "Attack Graph", Network],
  ["intel", "Threat Intelligence", Globe2],
  ["reports", "Forensic Report", FileText],
  ["pipeline", "Eight-Stage Pipeline", Activity],
];

function Brand({ compact = false }) {
  return <div className={`brand ${compact ? "brand-compact" : ""}`}><span className="brand-mark"><Fish size={25}/></span><span>MATSYA</span></div>;
}

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [message, setMessage] = useState("");
  function submit(e) {
    e.preventDefault();
    if (!username.trim() || !password) {
      setMessage("Username aur password dono enter karein.");
      return;
    }
    onLogin(username.trim());
  }
  return <main className="login-screen">
    <div className="login-glow glow-a"/><div className="login-glow glow-b"/>
    <div className="login-grid"/>
    <section className="login-card">
      <Brand/>
      <p className="login-subtitle">AI-Powered Email Threat Detection,<br/>Geolocation &amp; Forensic Intelligence</p>
      <div className="secure-pill"><ShieldCheck size={15}/> SECURE INVESTIGATOR ACCESS</div>
      <div className="login-heading"><h1>Welcome back</h1><p>Sign in to continue your investigations</p></div>
      <form onSubmit={submit} className="login-form">
        <label htmlFor="username">Username / Email</label>
        <div className="input-shell"><Mail size={18}/><input id="username" value={username} onChange={e=>setUsername(e.target.value)} placeholder="Enter your email or username" autoComplete="username"/></div>
        <div className="label-line"><label htmlFor="password">Password</label><button type="button" className="text-button" onClick={()=>setMessage("Password reset abhi configure nahi hai.")}>Forgot password?</button></div>
        <div className="input-shell"><LockKeyhole size={18}/><input id="password" type={show?"text":"password"} value={password} onChange={e=>setPassword(e.target.value)} placeholder="Enter your password" autoComplete="current-password"/><button type="button" className="eye-button" onClick={()=>setShow(v=>!v)} aria-label="Toggle password">{show?<EyeOff size={17}/>:<Eye size={17}/>}</button></div>
        {message && <p className="form-message">{message}</p>}
        <button className="primary login-button" type="submit">Sign in <ArrowRight size={17}/></button>
      </form>
      <div className="trust-grid">
        <div><Fingerprint/><b>Secure Access</b><small>Investigator workspace</small></div>
        <div><Database/><b>Evidence Integrity</b><small>SHA-256 fingerprint</small></div>
        <div><ShieldCheck/><b>Forensic Ready</b><small>Investigation tools</small></div>
      </div>
      <p className="login-footnote">Hackathon prototype · Demo login accepts any non-empty credentials</p>
    </section>
    <div className="login-bottom"><span><i/> SECURE FORENSIC WORKSPACE</span><span>DETECT · ANALYZE · INVESTIGATE</span></div>
  </main>;
}

function Metric({ icon: Icon, label, value, note, color }) {
  return <article className="metric-card"><div className={`metric-icon ${color}`}><Icon size={20}/></div><div className="metric-copy"><small>{label}</small><strong>{String(value).padStart(2,"0")}</strong><span>{note}</span></div></article>;
}

function Dashboard({ user, cases, analysis, onNavigate }) {
  const high = cases.filter(c=>c.analysis?.risk==="High").length;
  const done = cases.filter(c=>c.analysis).length;
  return <div className="page-content">
    <div className="welcome-row"><div><span className="eyebrow">SECURITY OPERATIONS / FORENSICS</span><h1>Investigation Dashboard</h1><p>Welcome, {user}. Monitor cases and investigate suspicious email evidence.</p></div><span className="status-pill"><i/> WORKSPACE READY</span></div>
    <div className="metrics-grid"><Metric icon={Database} label="Investigation Cases" value={cases.length} note="Current session" color="blue"/><Metric icon={Activity} label="Evidence Analyzed" value={done} note="Local .eml parsing" color="teal"/><Metric icon={ShieldAlert} label="High Risk Flags" value={high} note="Heuristic indicators" color="red"/><Metric icon={FileCheck2} label="Reports Ready" value={done} note="PDF export available" color="violet"/></div>
    <div className="dashboard-grid">
      <article className="panel map-panel"><div className="panel-heading"><div><h3>Global Threat Overview</h3><p>Illustrative network visualization · not live intelligence</p></div><span className="tag">DEMO MAP</span></div><div className="map-visual"><div className="map-grid-lines"/><svg viewBox="0 0 720 290" role="img" aria-label="Illustrative global network map"><g className="land"><path d="M48 76 91 40 151 47 185 75 153 104 145 136 111 147 96 178 67 144 47 108Z"/><path d="m176 170 38-7 28 34-11 43-22 21-19-36Z"/><path d="m294 61 52-17 45 14 23 21 37-8 40 18 31-12 55 25 26 29-32 19-37-14-23 24-33-12-28 29-28-20-26-32-31 15-24-29-30-7Z"/><path d="m358 159 47-3 28 30-13 45-25 22-17-31Z"/><path d="m548 190 40-12 35 16-11 24-38 4Z"/></g><g className="map-routes"><path d="M125 100 Q280 20 395 110 T560 120"/><path d="M210 210 Q360 270 475 150"/><path d="M395 110 Q460 70 560 120"/></g>{[[125,100],[395,110],[560,120],[210,210],[475,150]].map(([x,y],i)=><circle key={i} className={`map-node node-${i}`} cx={x} cy={y} r="6"/>)}</svg><div className="map-legend"><span><i className="legend-red"/> Alert marker (demo)</span><span><i className="legend-cyan"/> Network node</span></div></div></article>
      <article className="panel distribution-panel"><div className="panel-heading"><div><h3>Threat Distribution</h3><p>Illustrative sample categories</p></div></div><div className="distribution-content"><div className="donut"><div><b>100%</b><small>Sample</small></div></div><div className="legend-list">{[["Phishing","42%","red"],["Malware","24%","blue"],["Spam","18%","teal"],["Suspicious","10%","violet"],["Other","6%","amber"]].map(x=><span key={x[0]}><i className={`legend-${x[2]}`}/>{x[0]}<b>{x[1]}</b></span>)}</div></div><p className="small-note">Sample values only; not calculated from uploaded evidence.</p></article>
    </div>
    <article className="panel start-card"><div className="start-icon"><UploadCloud size={24}/></div><div><h3>Start a New Investigation</h3><p>Create a case, upload an .eml file, calculate its SHA-256 hash, and review findings.</p></div><button className="primary" onClick={()=>onNavigate("cases")}>Create case <ArrowRight size={16}/></button></article>
    <article className="panel workflow-card"><div className="panel-heading"><div><h3>Investigation Workflow</h3><p>From evidence intake to a documented forensic report</p></div><button className="subtle-button" onClick={()=>onNavigate("pipeline")}>View all stages <ArrowRight size={15}/></button></div><div className="workflow-steps">{STAGES.map((s,i)=><div className="workflow-step" key={s[0]}><span>{String(i+1).padStart(2,"0")}</span><b>{s[0]}</b>{i<STAGES.length-1&&<i>→</i>}</div>)}</div></article>
    {analysis && <article className="panel recent-analysis"><div><span className="eyebrow">LATEST ANALYSIS</span><h3>{analysis.subject}</h3><p>{analysis.file} · Risk {analysis.risk} · Score {analysis.score}/100</p></div><button className="secondary-button" onClick={()=>onNavigate("analysis")}>View results</button></article>}
  </div>;
}

function App() {
  const [user,setUser]=useState("");
  const [active,setActive]=useState("dashboard");
  const [cases,setCases]=useState([]);
  const [selectedCase,setSelectedCase]=useState("");
  const [file,setFile]=useState(null);
  const [hash,setHash]=useState("");
  const [hashBusy,setHashBusy]=useState(false);
  const [analysis,setAnalysis]=useState(null);
  const [busy,setBusy]=useState(false);
  const [toast,setToast]=useState("");
  const [caseTitle,setCaseTitle]=useState("");
  const [casePriority,setCasePriority]=useState("Medium");
  const [caseNotes,setCaseNotes]=useState("");
  const inputRef=useRef(null);
  const [search,setSearch]=useState("");
  const [graphSelection,setGraphSelection]=useState("");
  const [showMobileNav,setShowMobileNav]=useState(false);
  const notify=msg=>{setToast(msg);setTimeout(()=>setToast(""),3000)};
  const activeCase=cases.find(c=>c.id===selectedCase);
  const highCount=cases.filter(c=>c.analysis?.risk==="High").length;

  async function pickFile(f){
    if(!f)return;
    if(!f.name.toLowerCase().endsWith(".eml")){notify("Please select an .eml file.");return}
    setFile(f);setHash("");setAnalysis(null);setHashBusy(true);
    try{const bytes=await f.arrayBuffer();const digest=await crypto.subtle.digest("SHA-256",bytes);setHash([...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join(""))}
    catch{notify("SHA-256 requires localhost or HTTPS.")}
    finally{setHashBusy(false)}
  }
  function createCase(e){
    e.preventDefault();if(!caseTitle.trim())return;
    const c={id:`MTS-${Date.now().toString().slice(-6)}`,title:caseTitle.trim(),priority:casePriority,notes:caseNotes.trim(),created:new Date().toLocaleString(),file:"",hash:"",analysis:null};
    setCases(prev=>[c,...prev]);setSelectedCase(c.id);setCaseTitle("");setCaseNotes("");notify(`Case ${c.id} created.`);setActive("upload");
  }
  async function analyzeEvidence(){
    if(!file){notify("Upload an .eml file first.");return}
    if(!selectedCase){notify("Create or select a case first.");setActive("cases");return}
    setBusy(true);
    try{
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch("http://127.0.0.1:8000/api/analyze", {
        method: "POST",
        body: formData
      });
      const payload = await response.json().catch(()=>({}));
      if(!response.ok) throw new Error(payload.detail || `Backend request failed (${response.status}).`);
      const report = payload.report || {};
      const fingerprint = payload.sha256 || hash;
      if(fingerprint) setHash(fingerprint);
      const urls = Array.isArray(report.urls) ? report.urls : [];
      const ips = Array.isArray(report.ips) ? report.ips : [];
      const domains = Array.isArray(report.domains) ? report.domains : [...new Set(urls.map(u=>{try{return new URL(u).hostname}catch{return u}}))];
      const score = Number(report.risk_score ?? 0);
      const risk = report.risk_level || (score >= 70 ? "High" : score >= 35 ? "Medium" : "Low");
      const a = {
        caseId: selectedCase,
        file: payload.filename || file.name,
        hash: fingerprint,
        sender: report.sender || "Not found",
        recipient: report.recipient || "Not found",
        subject: report.subject || "(No subject)",
        date: report.date || "Not found",
        replyTo: report.reply_to || "",
        headers: report.headers || {},
        urls, ips, domains,
        findings: Array.isArray(report.findings) ? report.findings : [],
        mlPrediction: report.ml_prediction || "Unavailable",
mlProbability: report.ml_probability ?? null,
mlModelStatus: report.ml_model_status || "unknown",
        
        score, risk,
        analyzedAt: new Date().toLocaleString(),
        source: "FastAPI backend",
        limitations: Array.isArray(report.limitations) ? report.limitations : []
      };
      setAnalysis(a);
      setCases(prev=>prev.map(c=>c.id===selectedCase?{...c,file:a.file,hash:fingerprint,analysis:a}:c));
      setActive("analysis");
      notify("Backend analysis complete. Review findings before acting.");
    }catch(err){
      notify(err.message || "Analysis failed. Check that FastAPI is running on port 8000.");
    }finally{setBusy(false)}
  }
  
async function downloadReport() {
  if (!analysis) {
    notify("Analyze evidence before creating a report.");
    return;
  }

  try {
    const { jsPDF } = await import("jspdf");
    const doc = new jsPDF();
    const margin = 16;
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const maxWidth = pageWidth - margin * 2;
    let y = 20;

    function addText(text, size = 10, gap = 6) {
      doc.setFontSize(size);
      const lines = doc.splitTextToSize(String(text), maxWidth);

      if (y + lines.length * 5 + gap > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }

      doc.text(lines, margin, y);
      y += lines.length * 5 + gap;
    }

    doc.setFont("helvetica", "bold");
    addText("MATSYA", 20, 3);
    addText("EMAIL FORENSIC TRIAGE REPORT", 13);
    addText(
      "PRELIMINARY ANALYSIS - VERIFY FINDINGS INDEPENDENTLY",
      9
    );

    doc.setFont("helvetica", "normal");
    addText(`Case ID: ${analysis.caseId}`);
    addText(`Evidence file: ${analysis.file}`);
    addText(`SHA-256: ${analysis.hash}`);
    addText(`Generated: ${new Date().toLocaleString()}`);

    addText("EMAIL METADATA", 13, 4);
    addText(`Subject: ${analysis.subject}`);
    addText(`Sender: ${analysis.sender}`);
    addText(`Recipient: ${analysis.recipient}`);
    addText(`Date: ${analysis.date}`);
    addText(`Reply-To: ${analysis.replyTo || "Not found"}`);

    addText("RISK ASSESSMENT", 13, 4);
    addText(`Heuristic score: ${analysis.score}/100`);
    addText(`Risk rating: ${analysis.risk}`);
    addText(`ML prediction: ${analysis.mlPrediction}`);
    addText(
      `ML probability: ${
        analysis.mlProbability == null
          ? "Unavailable"
          : `${(analysis.mlProbability * 100).toFixed(2)}%`
      }`
    );
    addText(`ML model status: ${analysis.mlModelStatus}`);

    addText("DETECTED FINDINGS", 13, 4);
    if (analysis.findings.length) {
      analysis.findings.forEach((item, index) => {
        addText(`${index + 1}. ${item}`, 10, 3);
      });
    } else {
      addText("No findings returned by the analysis.");
    }

    addText("EXTRACTED URLS", 13, 4);
    (analysis.urls.length ? analysis.urls : ["None"]).forEach(item => {
      addText(item, 9, 2);
    });

    addText("EXTRACTED DOMAINS", 13, 4);
    (analysis.domains.length ? analysis.domains : ["None"]).forEach(item => {
      addText(item, 9, 2);
    });

    addText("EXTRACTED IP ADDRESSES", 13, 4);
    (analysis.ips.length ? analysis.ips : ["None"]).forEach(item => {
      addText(item, 9, 2);
    });

    addText("LIMITATIONS", 13, 4);
    const limitations = analysis.limitations.length
      ? analysis.limitations
      : ["External reputation and geolocation are not configured."];

    limitations.forEach(item => addText(`- ${item}`, 9, 3));

    addText(
      "This report is a preliminary triage aid. Scores and ML predictions are not confirmed verdicts.",
      9
    );

    doc.save(`MATSYA-${analysis.caseId}-forensic-report.pdf`);
    notify("PDF forensic report downloaded.");
  } catch (error) {
    console.error(error);
    notify("PDF export failed. Check the browser console.");
  }
}

  function navTo(id){setActive(id);setShowMobileNav(false)}
  const filteredCases=useMemo(()=>cases.filter(c=>`${c.id} ${c.title} ${c.file}`.toLowerCase().includes(search.toLowerCase())),[cases,search]);
  
  const graphNodes = useMemo(() => {
    if (!analysis) return [];

    const nodes = [];

    const add = (type, label) => {
      if (
        !label ||
        label === "Not found" ||
        label === "Not available"
      ) return;

      const cleanLabel = String(label).trim();
      if (!cleanLabel) return;

      const id = `${type}:${cleanLabel}`;

      if (!nodes.some((node) => node.id === id)) {
        nodes.push({
          id,
          type,
          label: cleanLabel,
          short:
            cleanLabel.length > 22
              ? `${cleanLabel.slice(0, 19)}…`
              : cleanLabel,
        });
      }
    };

    add("Email", analysis.file);
    add("Sender", analysis.sender);

    (analysis.domains || []).forEach((domain) =>
      add("Domain", domain)
    );

    (analysis.ips || []).forEach((ip) =>
      add("IP", ip)
    );

    (analysis.urls || []).forEach((url) =>
      add("URL", url)
    );

    const groups = {
      Email: [],
      Sender: [],
      Domain: [],
      URL: [],
      IP: [],
    };

    nodes.forEach((node) => {
      groups[node.type]?.push(node);
    });

    const positions = {
      Email: { x: 450, y: 250 },
      Sender: { x: 220, y: 120 },
      Domain: { x: 690, y: 120 },
      URL: { x: 690, y: 370 },
      IP: { x: 220, y: 370 },
    };

    Object.entries(groups).forEach(([type, group]) => {
      const base = positions[type];
      const spacing = 65;

      group.forEach((node, index) => {
        const offset =
          (index - (group.length - 1) / 2) * spacing;

        node.x = base.x + (type === "Email" ? 0 : offset);
        node.y = base.y + (type === "Email" ? 0 : offset * 0.35);
      });
    });

    return nodes;
  }, [analysis]);

  const graphEdges = useMemo(() => {
    if (!analysis) return [];

    const edges = [];
    const addEdge = (from, to, label) => {
      if (!from || !to || from.id === to.id) return;

      const id = `${from.id}->${to.id}`;

      if (!edges.some((edge) => edge.id === id)) {
        edges.push({
          id,
          from: from.id,
          to: to.id,
          label,
        });
      }
    };

    const email = graphNodes.find(
      (node) => node.type === "Email"
    );

    const sender = graphNodes.find(
      (node) => node.type === "Sender"
    );

    addEdge(email, sender, "Sender");

    const indicators = graphNodes.filter(
      (node) =>
        ["Domain", "URL", "IP"].includes(node.type)
    );

    indicators.forEach((node) => {
      addEdge(email, node, "Extracted indicator");
    });

    // Connect a URL to its domain only when the domain
    // was actually extracted and matches that URL's hostname.
    const domains = graphNodes.filter(
      (node) => node.type === "Domain"
    );

    const urls = graphNodes.filter(
      (node) => node.type === "URL"
    );

    urls.forEach((urlNode) => {
      try {
        const hostname = new URL(urlNode.label).hostname;

        const matchingDomain = domains.find(
          (domainNode) =>
            domainNode.label.toLowerCase() ===
            hostname.toLowerCase()
        );

        if (matchingDomain) {
          addEdge(urlNode, matchingDomain, "Hostname");
        }
      } catch {
        // Ignore malformed URLs.
      }
    });

    return edges;
  }, [analysis, graphNodes]);

  const selectedGraphNode = graphNodes.find(
    (node) => node.id === graphSelection
  );

 if(!user)return <Login onLogin={setUser}/>;
  return <div className="app-shell">
    <aside className={`sidebar ${showMobileNav?"sidebar-open":""}`}><div className="sidebar-brand"><Brand compact/><button className="mobile-close" onClick={()=>setShowMobileNav(false)}><X/></button></div><div className="side-label">INVESTIGATION WORKSPACE</div><nav>{navItems.map(([id,label,Icon])=><button key={id} className={`nav-item ${active===id?"active":""}`} onClick={()=>navTo(id)}><Icon size={17}/><span>{label}</span>{id==="cases"&&cases.length>0&&<em>{cases.length}</em>}</button>)}</nav><div className="sidebar-bottom"><div className="avatar">{user.charAt(0).toUpperCase()}</div><div className="sidebar-user"><b>{user}</b><small>Investigator · Demo</small></div><button className="logout" title="Sign out" onClick={()=>setUser("")}><LogOut size={17}/></button></div></aside>
    <main className="main-area"><header className="topbar"><button className="mobile-menu" onClick={()=>setShowMobileNav(true)}><Menu/></button><div className="topbar-title"><span className="eyebrow">MATSYA / CYBER FORENSICS</span><h2>{navItems.find(x=>x[0]===active)?.[1]||"Dashboard"}</h2></div><div className="topbar-right"><label className="global-search"><Search size={16}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search cases..."/></label><button className="top-icon" title="Notifications" onClick={()=>notify("No new notifications.")}><Bell size={18}/></button><div className="avatar top-avatar">{user.charAt(0).toUpperCase()}</div></div></header>
    {active==="dashboard"&&<Dashboard user={user} cases={cases} analysis={analysis} onNavigate={navTo}/>}
    {active==="cases"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">CASE WORKSPACE</span><h1>Case Management</h1><p>Create and organize investigation cases for this session.</p></div></div><div className="panel form-panel"><form className="case-form" onSubmit={createCase}><div><label htmlFor="caseTitle">Case title</label><input id="caseTitle" value={caseTitle} onChange={e=>setCaseTitle(e.target.value)} required placeholder="Suspicious vendor invoice email"/></div><div><label htmlFor="casePriority">Priority</label><select id="casePriority" value={casePriority} onChange={e=>setCasePriority(e.target.value)}><option>Medium</option><option>High</option><option>Low</option></select></div><div><label htmlFor="caseNotes">Investigation notes</label><input id="caseNotes" value={caseNotes} onChange={e=>setCaseNotes(e.target.value)} placeholder="Reason for investigation (optional)"/></div><button className="primary" type="submit"><Plus size={17}/> Create case</button></form></div><div className="panel cases-panel"><div className="panel-heading"><div><h3>Investigation Cases</h3><p>Session-only case list · {cases.length} total</p></div><span className="tag">{cases.length} CASES</span></div>{filteredCases.length===0?<div className="empty-state">No cases yet. Create a case above to begin.</div>:<div className="case-list">{filteredCases.map(c=><div className={`case-row ${selectedCase===c.id?"selected":""}`} key={c.id}><div><b>{c.id}</b><small>{c.created}</small></div><div><strong>{c.title}</strong><small>{c.file||"Evidence not uploaded yet"}</small></div><span className={`risk-badge ${c.analysis?.risk?.toLowerCase()||c.priority.toLowerCase()}`}>{c.analysis?.risk||c.priority} {c.analysis?"risk":"priority"}</span><button className="secondary-button" onClick={()=>{setSelectedCase(c.id);navTo("upload")}}>{selectedCase===c.id?"Selected":"Select case"}</button></div>)}</div>}</div></section>}
    {active==="upload"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">EVIDENCE INTAKE</span><h1>Upload Evidence</h1><p>Select a suspicious .eml file. It will be sent to your local FastAPI backend for analysis.</p></div><span className="tag">FASTAPI BACKEND</span></div><div className="upload-layout"><article className="panel upload-panel"><input ref={inputRef} className="file-input" type="file" accept=".eml,message/rfc822" onChange={e=>pickFile(e.target.files?.[0])}/><button className="drop-zone" onClick={()=>inputRef.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();pickFile(e.dataTransfer.files?.[0])}}><UploadCloud size={36}/><b>{file?file.name:"Drop your suspicious .eml file here"}</b><small>or click to browse · .eml format</small><span className="browse-button">Choose file</span></button><div className="hash-box"><div><b><Hash size={15}/> SHA-256 Evidence Fingerprint</b><small>Calculated from the exact uploaded file bytes</small></div><code>{hashBusy?"Calculating…":hash||"Waiting for evidence…"}</code><button className="secondary-button" disabled={!hash} onClick={()=>navigator.clipboard.writeText(hash).then(()=>notify("SHA-256 copied."))}>Copy hash</button></div><div className="upload-actions"><span>{file?`${(file.size/1024).toFixed(1)} KB · ready for analysis`:"No file selected"}</span><button className="primary" disabled={!file||busy} onClick={analyzeEvidence}>{busy?"Analyzing…":"Analyze evidence"} <ArrowRight size={16}/></button></div><p className="disclaimer">The selected evidence is sent to your local FastAPI server at 127.0.0.1:8000. Do not upload sensitive real-world evidence to an untrusted server.</p></article><article className="panel pipeline-panel"><div className="panel-heading"><div><h3>Forensic Pipeline</h3><p>Eight investigation stages</p></div></div><div className="stage-list">{STAGES.map((s,i)=>{const Icon=s[2];return <div className="stage-row" key={s[0]}><span className="stage-number">{String(i+1).padStart(2,"0")}</span><div><b>{s[0]}</b><small>{s[1]}</small></div><Icon size={18}/></div>})}</div></article></div></section>}
    {active==="analysis"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">ANALYSIS OUTPUT</span><h1>Email Analysis Results</h1><p>Extracted headers, suspicious indicators and transparent heuristic scoring.</p></div><button className="secondary-button" onClick={()=>navTo("upload")}>Analyze another email</button></div>{!analysis?<div className="panel empty-state"><FileSearch size={28}/><p>Upload and analyze an .eml file to display results here.</p><button className="primary" onClick={()=>navTo("upload")}>Upload evidence</button></div>:<><div className="results-grid"><article className="panel score-panel"><span className="eyebrow">HEURISTIC RISK SCORE</span><div className="score-value">{analysis.score}<small>/100</small></div><span className={`risk-badge ${analysis.risk.toLowerCase()}`}>{analysis.risk} risk</span><p>Preliminary indicator score, not a verified verdict.</p></article><article className="panel metadata-panel"><h3>Email Metadata</h3><dl>{[["Case ID",analysis.caseId],["Evidence file",analysis.file],["SHA-256",analysis.hash],["Subject",analysis.subject],["Sender",analysis.sender],["Date",analysis.date],["Reply-To",analysis.replyTo||"Not found"],["Analyzed at",analysis.analyzedAt]].map(([k,v])=><React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}</dl></article></div>

<article className="panel findings-panel">
  <h3>Machine Learning Assessment</h3>

  <div className="finding-row">
    <ShieldCheck size={16} />
    <span>
      ML Prediction: <strong>{analysis.mlPrediction}</strong>
    </span>
  </div>

  <div className="finding-row">
    <Activity size={16} />
    <span>
      ML Probability:{" "}
      <strong>
        {analysis.mlProbability == null
          ? "Unavailable"
          : `${(analysis.mlProbability * 100).toFixed(2)}%`}
      </strong>
    </span>
  </div>

  <p className="disclaimer">
    Model status: {analysis.mlModelStatus}.
    This is a preliminary prediction, not a confirmed verdict.
  </p>
</article>

<article className="panel findings-panel">
  <h3>Detected Indicators &amp; Findings</h3>{analysis.findings.map((f,i)=><div className="finding-row" key={i}><ShieldAlert size={16}/>{f}</div>)}<h3>Extracted URLs / Domains</h3><div className="indicator-list">{analysis.urls.length?analysis.urls.map(u=><code key={u}>{u}</code>):<p>No URLs extracted.</p>}</div><h3>Extracted IPv4 Addresses</h3><div className="indicator-list">{analysis.ips.length?analysis.ips.map(ip=><code key={ip}>{ip}</code>):<p>No IPv4 addresses extracted.</p>}</div><p className="disclaimer">Limitations: {analysis.limitations.length
  ? analysis.limitations.join(" ")
  : "Preliminary triage only. External reputation and geolocation are not configured."}.</p></article></>}</section>}
    {active==="graph"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">EVIDENCE RELATIONSHIPS</span><h1>Attack Graph</h1><p>Interactive graph built from the currently analyzed email. Connections show extraction associations, not proof of malicious activity.</p></div><div className="graph-actions"><button className="secondary-button" disabled={!analysis} onClick={()=>{setGraphSelection("");notify("Graph selection cleared.")}}>Reset selection</button><button className="secondary-button" onClick={()=>navTo("upload")}>Analyze evidence</button></div></div>
      {!analysis?<article className="panel graph-panel"><div className="graph-empty"><div className="graph-empty-icon"><Network size={32}/></div><h3>No investigation graph yet</h3><p>Upload an .eml file, select a case, and run backend analysis. The graph will then be built from the extracted sender, URLs, domains and IP addresses.</p><button className="primary" onClick={()=>navTo("upload")}>Go to Upload Evidence <ArrowRight size={16}/></button></div></article>:
      <div className="graph-workspace"><article className="panel graph-panel"><div className="graph-toolbar"><div><b>{analysis.file}</b><small>{graphNodes.length} entities · {graphEdges.length} relationships · {analysis.source||"Analyzed evidence"}</small></div><span className="tag">EVIDENCE GRAPH</span></div>
        <div className="interactive-graph"><svg viewBox="0 0 900 510" role="img" aria-label="Interactive email evidence relationship graph">
          <defs><pattern id="graphGrid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M 28 0 L 0 0 0 28" fill="none" stroke="#5badd51b" strokeWidth="1"/></pattern><filter id="graphGlow"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
          <rect width="900" height="510" fill="url(#graphGrid)"/>
          {graphEdges.map(edge=>{const a=graphNodes.find(n=>n.id===edge.from),b=graphNodes.find(n=>n.id===edge.to);return a&&b?<g key={edge.id}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className={`graph-edge ${graphSelection===a.id||graphSelection===b.id?"highlight":""}`} /><text x={(a.x+b.x)/2} y={(a.y+b.y)/2-7} className="graph-edge-label">{edge.label}</text></g>:null})}
          {graphNodes.map(node=><g key={node.id} className={`graph-svg-node ${graphSelection===node.id?"selected":""}`} role="button" tabIndex="0" aria-label={`Inspect ${node.type}: ${node.label}`} onClick={()=>setGraphSelection(node.id)} onKeyDown={e=>{if(e.key==="Enter"||e.key===" ")setGraphSelection(node.id)}}>
            <circle cx={node.x} cy={node.y} r={node.type==="Email"?37:node.type==="Sender"?31:29} className={`node-halo ${node.type.toLowerCase().replace(/[^a-z]/g,"-")}`}/>
            <circle cx={node.x} cy={node.y} r={node.type==="Email"?29:node.type==="Sender"?24:22} className={`node-core ${node.type.toLowerCase().replace(/[^a-z]/g,"-")}`}/>
            <text x={node.x} y={node.y-2} className="graph-node-type">{node.type}</text>
            <text x={node.x} y={node.y+12} className="graph-node-label">{node.short}</text>
          </g>)}
        </svg></div>
        <div className="graph-legend"><span><i className="legend-email"/> Email</span><span><i className="legend-sender"/> Sender</span><span><i className="legend-domain"/> Domain / URL</span><span><i className="legend-ip"/> IP address</span></div>
      </article><aside className="panel graph-details"><span className="eyebrow">SELECTED ENTITY</span>{selectedGraphNode?<><h3>{selectedGraphNode.type}</h3><code>{selectedGraphNode.label}</code><dl><dt>Entity type</dt><dd>{selectedGraphNode.type}</dd><dt>Source evidence</dt><dd>{analysis.file}</dd><dt>Case</dt><dd>{analysis.caseId}</dd><dt>Connected entities</dt><dd>{graphEdges.filter(e=>e.from===selectedGraphNode.id||e.to===selectedGraphNode.id).length}</dd><dt>Risk assessment</dt><dd>{analysis.risk} · {analysis.score}/100</dd></dl><p className="disclaimer">This connection is derived from extracted email content and should be validated by an investigator.</p></>:<div className="graph-detail-empty"><Network size={24}/><p>Select any node in the graph to inspect its details.</p></div>}<button className="secondary-button" onClick={()=>navTo("analysis")}>View analysis results</button></aside></div>}
    </section>}
    {active==="intel"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">EXTERNAL LOOKUPS</span><h1>Threat Intelligence</h1><p>Extracted indicators are shown separately from externally verified intelligence.</p></div></div><div className="intel-grid"><article className="panel info-panel"><Globe2/><h3>IP Intelligence</h3><p>{analysis?.ips.length?`Extracted IPs: ${analysis.ips.join(", ")}. Geolocation and ownership are not verified.`:"Analyze an email to extract IP indicators."}</p><span className="tag">LIVE LOOKUP NOT CONFIGURED</span></article><article className="panel info-panel"><Link2/><h3>Domain / URL Intelligence</h3><p>{analysis?.domains.length?`Extracted domains: ${analysis.domains.join(", ")}. No external reputation request was made.`:"Extracted domains and URLs will appear here."}</p><span className="tag">LIVE LOOKUP NOT CONFIGURED</span></article><article className="panel info-panel"><Settings/><h3>Production integrations</h3><p>Connect approved intelligence APIs from a secure backend. Keep API keys out of browser code and record source and lookup timestamps.</p></article></div></section>}
    {active==="reports"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">EVIDENCE DOCUMENTATION</span><h1>Forensic Report</h1><p>Download a report containing hash, metadata, indicators, findings and limitations.</p></div></div><article className="panel report-panel"><div className="report-icon"><FileText size={30}/></div><h3>{analysis?`Report ready · ${analysis.file}`:"No report prepared yet"}</h3><p>{analysis?`Case ${analysis.caseId} · SHA-256 fingerprint included · ${analysis.findings.length} findings.`:"Analyze an email to prepare a report."}</p><button className="primary" disabled={!analysis} onClick={downloadReport}><Download size={17}/> Download forensic report</button><p className="disclaimer">The report is exported as a PDF and includes evidence metadata, SHA-256, risk assessment, ML output, findings and limitations.</p></article></section>}
    {active==="pipeline"&&<section className="page-content"><div className="page-heading"><div><span className="eyebrow">INVESTIGATION WORKFLOW</span><h1>Eight-Stage Pipeline</h1><p>One evidence flow from intake to a structured investigation report.</p></div></div><div className="stage-grid">{STAGES.map((s,i)=>{const Icon=s[2];return <article className="panel stage-card" key={s[0]}><span className="stage-number">{String(i+1).padStart(2,"0")}</span><Icon size={23}/><h3>{s[0]}</h3><p>{s[1]}</p></article>})}</div><div className="technology-heading"><span className="eyebrow">BUILT FOR FORENSIC WORKFLOWS</span><h2>Technology Stack</h2><p>Core technologies planned for the MATSYA investigation platform.</p></div><div className="technology-grid">{[["Frontend","React.js, HTML, CSS","layout"],["Backend","Python, FastAPI","server"],["AI / ML","Python, NLP, Scikit-learn","brain"],["Email Forensics","Headers, Metadata, Attachments","mail"],["Threat Intelligence","IP, Domain, DNS, WHOIS, GeoIP","globe"],["Threat Correlation","Email, IP, Domain & URL Linking","network"],["Attack Visualization","Attack Graph, Timeline, Risk Score","activity"],["Forensic Reporting","Structured Evidence, Report","file"]].map(([title,detail,icon])=><article className="technology-card" key={title}><div className="technology-icon">{icon==="mail"?<Mail/>:icon==="globe"?<Globe2/>:icon==="network"?<Network/>:icon==="activity"?<Activity/>:icon==="file"?<FileText/>:icon==="brain"?<ShieldCheck/>:icon==="server"?<Database/>:<LayoutDashboard/>}</div><h3>{title}</h3><p>{detail}</p></article>)}</div>
<p className="tech-note">
  Note: The ML model provides preliminary predictions from a limited demo dataset.
  External threat feeds, reputation checks and geolocation are not configured.
</p></section>}
<footer className="app-footer"><b>MATSYA</b><span>Hackathon prototype · Verify findings before operational use.</span><span>Local browser session</span></footer></main>
{toast&&<div className="toast"><Check size={16}/>{toast}</div>}
</div>;
}
 
export default App;

