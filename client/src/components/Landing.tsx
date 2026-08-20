import { useState, useEffect, useRef } from "react";
import type { ChangeEvent, DragEvent, FormEvent } from "react";

const EXAMPLE_CODE = `import { template } from "lodash";

export function handleRequest(title) {
  return template(title, { interpolate: /{{([\\s\\S]+?)}}/g });
}`;

function StarCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let frameId: number;
    let stars: { x: number; y: number; size: number; speed: number; opacity: number }[] = [];
    const resize = () => {
      const parent = canvas.parentElement;
      if (parent) { canvas.width = parent.clientWidth; canvas.height = parent.clientHeight; }
      stars = [];
      for (let i = 0; i < 120; i++) {
        stars.push({ x: Math.random() * canvas.width, y: Math.random() * canvas.height, size: Math.random() * 1.5, speed: Math.random() * 0.15 + 0.04, opacity: Math.random() });
      }
    };
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const s of stars) {
        ctx.beginPath(); ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${s.opacity})`; ctx.fill();
        s.y -= s.speed; if (s.y < 0) s.y = canvas.height;
        s.opacity += (Math.random() - 0.5) * 0.04;
        if (s.opacity < 0.1) s.opacity = 0.1; if (s.opacity > 0.8) s.opacity = 0.8;
      }
      frameId = requestAnimationFrame(draw);
    };
    window.addEventListener("resize", resize); resize(); draw();
    return () => { window.removeEventListener("resize", resize); cancelAnimationFrame(frameId); };
  }, []);
  return <canvas ref={ref} className="hero-canvas" aria-hidden="true" />;
}

function SunburstGlow() {
  return (
    <div className="hero-sunburst">
      <svg viewBox="0 0 1000 1000" xmlns="http://www.w3.org/2000/svg" className="hero-sunburst-svg">
        <defs>
          <radialGradient id="sunburst" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.15)" />
            <stop offset="100%" stopColor="rgba(255,255,255,0)" />
          </radialGradient>
        </defs>
        <rect width="1000" height="1000" fill="url(#sunburst)" />
      </svg>
    </div>
  );
}

function HeroRays() {
  return (
    <div className="hero-rays-wrap">
      <svg className="hero-rays" viewBox="0 0 1440 400" fill="none" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMax slice">
        <path d="M720 400L0 0H1440L720 400Z" fill="url(#paint0_linear_hero)" fillOpacity="0.1" />
        <defs>
          <linearGradient id="paint0_linear_hero" x1="720" y1="0" x2="720" y2="400" gradientUnits="userSpaceOnUse">
            <stop stopColor="white" stopOpacity="0.4" />
            <stop offset="1" stopColor="white" stopOpacity="0" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

function DomeEmblem() {
  return (
    <img
      src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/icons/A1lHzLYnhHoe8Buhuz9cfj4DPY-1.png"
      alt="Dome Emblem"
      width={24}
      height={24}
      style={{ objectFit: "contain" }}
    />
  );
}

function SunburstIcon() {
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      {[0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330].map((deg) => (
        <rect key={deg} x="22" y="4" width="4" height="12" rx="2" fill="white" opacity="0.9" transform={`rotate(${deg} 24 24)`} />
      ))}
    </svg>
  );
}

function FloatingImg({ src, alt, style, className = "" }: { src: string; alt: string; style: React.CSSProperties; className?: string }) {
  return (
    <div className={`floating-img ${className}`} style={{ position: "absolute", ...style }}>
      <img src={src} alt={alt} style={{ width: "100%", height: "100%", objectFit: "contain", borderRadius: 8 }} />
    </div>
  );
}

function GraphPathIllustration() {
  return (
    <svg className="graph-path-illust" viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="60" cy="100" r="14" stroke="white" strokeWidth="2" fill="none" opacity="0.6" />
      <circle cx="180" cy="60" r="14" stroke="white" strokeWidth="2" fill="none" opacity="0.6" />
      <circle cx="300" cy="100" r="14" stroke="white" strokeWidth="2" fill="white" opacity="0.8" />
      <path d="M74,100 L166,60" stroke="white" strokeWidth="1.5" opacity="0.4" strokeDasharray="4 3" />
      <path d="M194,60 L286,100" stroke="white" strokeWidth="2" opacity="0.7" strokeDasharray="6 4" />
      <text x="60" y="130" textAnchor="middle" fill="white" fontSize="9" fontFamily="Inter" opacity="0.5">entry</text>
      <text x="180" y="42" textAnchor="middle" fill="white" fontSize="9" fontFamily="Inter" opacity="0.5">fn</text>
      <text x="300" y="130" textAnchor="middle" fill="white" fontSize="9" fontFamily="Inter" opacity="0.5">sink</text>
      <rect x="288" y="88" width="24" height="24" rx="4" transform="rotate(45 300 100)" stroke="white" strokeWidth="1.5" fill="white" opacity="0.3" />
    </svg>
  );
}

function StepIcon({ step }: { step: number }) {
  if (step === 1) return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="8" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.3" /><path d="M12,20 L18,26 L28,14" stroke="#000" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.6" /></svg>
  );
  if (step === 2) return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="8" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.3" /><circle cx="14" cy="20" r="4" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.6" /><circle cx="26" cy="14" r="4" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.6" /><circle cx="26" cy="26" r="4" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.6" /><line x1="18" y1="18" x2="22" y2="15" stroke="#000" strokeWidth="1" opacity="0.4" /><line x1="18" y1="22" x2="22" y2="25" stroke="#000" strokeWidth="1" opacity="0.4" /></svg>
  );
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="8" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.3" /><path d="M14,28 L14,16 L20,12 L26,16 L26,28" stroke="#000" strokeWidth="1.5" fill="none" opacity="0.6" /><line x1="14" y1="22" x2="26" y2="22" stroke="#000" strokeWidth="1" opacity="0.4" /><circle cx="20" cy="18" r="2" fill="#000" opacity="0.4" /></svg>
  );
}

export default function Landing({
  onScan,
  onScanCode,
  onScanZip,
}: {
  onScan: (repoPath: string) => void;
  onScanCode: (filename: string, content: string) => void;
  onScanZip: (file: File) => void;
}) {
  const [repoPath, setRepoPath] = useState("");
  const [code, setCode] = useState("");
  const [fileName, setFileName] = useState("main.js");
  const [draggingZip, setDraggingZip] = useState(false);

  const submitPath = (e: FormEvent) => { e.preventDefault(); const p = repoPath.trim(); if (p) onScan(p); };
  const submitCode = (e: FormEvent) => { e.preventDefault(); if (code.trim()) onScanCode(fileName.trim() || "main.js", code); };
  const handleZipFile = (file: File | undefined | null) => { if (!file || !file.name.toLowerCase().endsWith(".zip")) return; onScanZip(file); };
  const onDrop = (e: DragEvent) => { e.preventDefault(); setDraggingZip(false); handleZipFile(e.dataTransfer.files?.[0]); };
  const onPick = (e: ChangeEvent<HTMLInputElement>) => { handleZipFile(e.target.files?.[0]); };
  const scrollToInputs = () => { document.getElementById("scan-inputs")?.scrollIntoView({ behavior: "smooth" }); };

  return (
    <div className="landing">
      {/* --- NAV --- */}
      <header className="landing-nav anim-fade-in">
        <span className="landing-brand">
          <span className="landing-mark" aria-hidden="true"><DomeEmblem /></span>
          hydra-triage
        </span>
        <span className="landing-nav-note">Hack Hydra 2026</span>
      </header>

      {/* --- HERO --- */}
      <section className="landing-hero-shell">
        <div className="landing-hero-inner">
          <StarCanvas />
          <SunburstGlow />
          <div className="hero-content">
            <div className="hero-emblem-wrap anim-slide-up-1">
              <div className="hero-emblem"><DomeEmblem /></div>
              <span className="hero-emblem-word">hydra-triage</span>
            </div>
            <h1 className="anim-slide-up-2">
              Which flagged CVEs are<br />
              <span className="hero-accent">actually exploitable</span> in your code?
            </h1>
            <p className="landing-sub anim-slide-up-3">
              Package scanners flag every vulnerable library <em>installed</em> — including the dead code that
              never runs. hydra-triage parses your code into a call graph, stores it in HydraDB, and asks it a
              sharper question: <em>does a call path exist from an entry point to the vulnerable export?</em>
            </p>
            <div className="anim-slide-up-4">
              <button className="hero-cta" type="button" onClick={scrollToInputs}>Scan your code</button>
            </div>
            <div className="hero-graph-illust anim-fade-in">
              <GraphPathIllustration />
            </div>
          </div>
          <HeroRays />
        </div>
      </section>

      {/* --- INPUTS (black, #111 cards with floating decorations) --- */}
      <section id="scan-inputs" className="code-inputs anim-fade-in">
        <div className="code-card">
          <div className="code-card-visual">
            <SunburstIcon />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/zXayETlkOsew51GBaiG6Yv7VW58-1.png" alt="medallion" style={{ left: "8%", top: "8%", width: 48, height: 48, opacity: 0.4 }} />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/wlopfJZLEPXdGVFzwtl4VptjhYE-2.png" alt="medallion" style={{ right: "8%", bottom: "12%", width: 56, height: 56, opacity: 0.4 }} />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/JjbgYOkd5rnOKDS1Si6jdGCynA-3.png" alt="medallion" style={{ left: "3%", top: "45%", width: 40, height: 40, opacity: 0.3, filter: "blur(1px)" }} />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/97yT4ZeOlOyOfHLxQCIPoGupfzs-4.png" alt="medallion" style={{ right: "12%", top: "12%", width: 44, height: 44, opacity: 0.3, filter: "blur(1px)" }} />
          </div>
          <div className="code-card-body">
            <div className="code-card-title">Paste code</div>
            <p className="code-card-note">Drop a JS/TS file (or snippet) — exports become the entry points. Best for a quick check.</p>
            <button type="button" className="ghost code-example-btn" onClick={() => { setCode(EXAMPLE_CODE); setFileName("main.js"); }}>Load live example</button>
            <form onSubmit={submitCode}>
              <textarea className="code-textarea mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder={"export function renderPage(title) {\n  return template(title);\n}"} aria-label="Pasted code" spellCheck={false} />
              <div className="code-file-row">
                <input className="code-file-name mono" value={fileName} onChange={(e) => setFileName(e.target.value)} aria-label="Pasted file name" spellCheck={false} />
                <button className="primary" type="submit" disabled={!code.trim()}>Scan pasted code</button>
              </div>
            </form>
          </div>
        </div>

        <div className="code-card">
          <div className="code-card-visual">
            <SunburstIcon />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/wtbm79Q9AxFkqos3cnm6dFeLac-7.png" alt="refine asset" style={{ left: "25%", top: "25%", width: 60, height: 60, opacity: 0.6 }} />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/EKNAIRxRXH79f1RjXp4Serkd0k8-8.png" alt="refine asset" style={{ right: "25%", top: "25%", width: 60, height: 60, opacity: 0.6 }} />
            <FloatingImg src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/J7APqOZgVgfiWu8NSkEoCfMjHNg-9.png" alt="refine asset" style={{ left: "30%", bottom: "30%", width: 50, height: 50, opacity: 0.4, transform: "rotate(-15deg)" }} />
          </div>
          <div className="code-card-body">
            <div className="code-card-title">Upload your repo</div>
            <p className="code-card-note">Zip a JS/TS repository and drop it here — real imports and entry points resolve just like a local scan.</p>
            <div className={`dropzone${draggingZip ? " dropzone-active" : ""}`} onClick={() => document.getElementById("zip-input")?.click()} onDragOver={(e) => { e.preventDefault(); setDraggingZip(true); }} onDragLeave={() => setDraggingZip(false)} onDrop={onDrop} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") document.getElementById("zip-input")?.click(); }}>
              <div className="dropzone-icon" aria-hidden="true">↓</div>
              <div>Drag &amp; drop a <code>.zip</code> here</div>
              <div className="dropzone-sub">or click to browse — scanning starts immediately</div>
            </div>
            <input id="zip-input" type="file" accept=".zip,application/zip" className="visually-hidden" onChange={onPick} />
            <p className="code-card-hint mono">zip -r app.zip /path/to/repo · code is parsed, never executed</p>
          </div>
        </div>
      </section>

      {/* --- PATH STRIP --- */}
      <div className="landing-path-strip anim-fade-in">
        <span style={{ color: "var(--ink-faint)", fontSize: "0.82rem" }}>…or scan a repo on this machine</span>
        <form style={{ display: "contents" }} onSubmit={submitPath}>
          <input value={repoPath} onChange={(e) => setRepoPath(e.target.value)} placeholder="./demo/vulnerable-app" aria-label="Repository path" />
          <button className="primary" type="submit" style={{ fontSize: "0.72rem", padding: "0.5rem 1rem" }}>Scan path</button>
        </form>
      </div>

      {/* --- STEPS (white squircle with inline icons) --- */}
      <div className="squircle anim-fade-in">
        <div className="landing-steps">
          <div className="step step-highlight">
            <div className="step-visual">
              <GraphPathIllustration />
            </div>
            <div className="step-num mono">01</div>
            <div className="step-title">Parsed, not executed</div>
            <p>Your code is read by a parser into a call graph — every function, call edge and import. Nothing ever runs.</p>
          </div>
          <div className="step step-highlight">
            <div className="step-visual">
              <SunburstIcon />
            </div>
            <div className="step-num mono">02</div>
            <div className="step-title">Stored in HydraDB</div>
            <p>The call graph lands in HydraDB as labeled vertices and edges. HydraDB's native path procedures answer the reachability question in-graph — no client-side traversal.</p>
          </div>
          <div className="step step-highlight">
            <div className="step-visual">
              <img className="step-runner" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/VnOLWw13A23qqZXH9xrtZ6ENknk-12.png" alt="" width={80} height={80} />
              <img className="step-trophy" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/AddQ9vwlBU4KvkvWUb3hHumB0JU-11.png" alt="" width={40} height={40} />
            </div>
            <div className="step-num mono">03</div>
            <div className="step-title">Traced</div>
            <p>For each CVE in the bundled seed database, a bounded MSpaths search from any entry point to the vulnerable export decides the verdict — drawn as a graph path.</p>
          </div>
        </div>
      </div>

      {/* --- VERDICTS (black, monochrome badges) --- */}
      <div className="landing-verdicts anim-fade-in">
        <div className="verdict-card"><div className="verdict-sev">reachable</div><span className="verdict-badge solid">solid</span><p>A live path exists from an entry point to the vulnerable export. This CVE is exploitable from this codebase — fix it first.</p></div>
        <div className="verdict-card"><div className="verdict-sev">present, no path</div><span className="verdict-badge outline">outlined</span><p>The vulnerable export is called somewhere, but not from anything executable. Package scanners flag it; triage says it's noise — unless a future PR wires it in.</p></div>
        <div className="verdict-card"><div className="verdict-sev">never called</div><span className="verdict-badge dashed">dashed</span><p>The vulnerable function isn't referenced at all. Installed but inert — and the PR gate keeps it that way by diffing reachability per commit.</p></div>
      </div>

      {/* --- MISSION (inline medallions, Dome pattern) --- */}
      <div className="landing-mission anim-fade-in">
        <div className="mission-row">
          <span className="mission-text-dim">We parse</span>
          <img className="mission-medallion" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/48rCh0ajybT4YyeXJYaZx6tlQ-13.png" alt="" width={64} height={64} />
          <span className="mission-text">your code</span>
          <span className="mission-text-dim">into a</span>
          <img className="mission-medallion" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/gVW6bIRpmtScsiaiEqDitPGak-14.png" alt="" width={64} height={64} />
          <span className="mission-text">call graph,</span>
        </div>
        <div className="mission-row">
          <span className="mission-text-dim">then</span>
          <img className="mission-medallion" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/Kpd3F4ztFy3f9mbzJMuLSo6LD7k-15.png" alt="" width={64} height={64} />
          <span className="mission-text">trace reachability</span>
          <span className="mission-text-dim">to find the</span>
          <img className="mission-medallion" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/OzozoZrSNOCdHu10PhMGiKugZk-16.png" alt="" width={64} height={64} />
          <span className="mission-text">real risks.</span>
        </div>
        <div className="mission-row">
          <img className="mission-medallion" src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/images/UHv353vyX6GJi4rFAdcJBYhMhSk-17.png" alt="" width={64} height={64} />
          <span className="mission-text">Triage smarter.</span>
        </div>
      </div>

      {/* --- CTA FOOTER (white squircle) --- */}
      <div className="squircle landing-cta anim-fade-in">
        <h2>Triage your code, now.</h2>
        <button className="primary" type="button" onClick={scrollToInputs} style={{ fontSize: "16px", padding: "18px 40px" }}>Run a scan</button>
      </div>

      {/* --- FOOTER --- */}
      <footer className="landing-footer anim-fade-in">
        <span>call graph + reachability live in HydraDB</span>
        <span>reachability is a bounded search of up to 8 hops — a "no path" beyond the bound is a triage signal, not a formal proof</span>
        <a href="#" className="footer-x" aria-label="Follow us on X">
          <img src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/dcf13bf0-24b5-42a8-adc8-0441d6d4ca35-dome-run/assets/icons/Vw6yr8Ij253uOCeKhIN6ugpJHFg-2.png" alt="X" width={20} height={20} />
        </a>
      </footer>
    </div>
  );
}