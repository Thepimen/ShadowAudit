'use client';

import React, { useState, useEffect, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { 
  Shield, 
  Terminal as TerminalIcon, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  Loader2, 
  Server, 
  Globe, 
  Lock, 
  Cpu, 
  RefreshCw,
  Clock,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

// WebSocket connection config
const GATEWAY_URL = 'http://localhost:4000';

interface ScanPortResult {
  port: number;
  state: 'open' | 'closed';
  service: string;
  version: string;
  latency_ms?: number;
}

interface ScanLogPayload {
  auditId: string;
  stage: 'queued' | 'scanning' | 'completed' | 'failed' | 'log';
  message: string;
  data?: {
    ports?: ScanPortResult[];
    results?: ScanPortResult[];
    ai_insights?: string[];
    target?: string;
    ip?: string;
    scan_time?: string;
  };
  timestamp: string;
}

export default function Home() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [auditId, setAuditId] = useState<string | null>(null);
  const [scanState, setScanState] = useState<'idle' | 'queued' | 'scanning' | 'completed' | 'failed'>('idle');
  const [logs, setLogs] = useState<{ text: string; type: 'info' | 'success' | 'warn' | 'error' | 'ai' }[]>([]);
  const [ports, setPorts] = useState<ScanPortResult[]>([]);
  const [aiInsights, setAiInsights] = useState<string[]>([]);
  const [resolvedIp, setResolvedIp] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const socketRef = useRef<Socket | null>(null);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  // Setup Live WebSocket Socket.io Subscriber
  useEffect(() => {
    // Connect to Express Gateway
    const socket = io(GATEWAY_URL, {
      withCredentials: true,
      transports: ['websocket', 'polling']
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      addSystemLog('Connected to SecOps Socket Gateway successfully.', 'success');
    });

    socket.on('disconnect', () => {
      addSystemLog('Disconnected from Gateway server.', 'error');
    });

    // Realtime Scan Updates listener
    socket.on('scan_update', (payload: ScanLogPayload) => {
      const { stage, message, data } = payload;
      
      // Update global scan tracking status
      if (stage !== 'log') {
        setScanState(stage);
      }

      // Route and colorize incoming raw log streams
      if (message.includes('[AI Fix') || message.includes('[AI Threat') || message.includes('[AI Insight]')) {
        addSystemLog(message, 'ai');
      } else if (stage === 'failed') {
        addSystemLog(message, 'error');
        setLoading(false);
      } else if (stage === 'completed') {
        addSystemLog(message, 'success');
        setLoading(false);
      } else if (message.includes('WARNING') || message.includes('CRITICAL')) {
        addSystemLog(message, 'warn');
      } else {
        addSystemLog(message, 'info');
      }

      // Handle custom payload attachments
      if (data) {
        if (data.ports || data.results) {
          const portsList = data.ports || data.results;
          if (portsList) setPorts(portsList);
        }
        if (data.ai_insights) {
          setAiInsights(data.ai_insights);
        }
        if (data.ip) {
          setResolvedIp(data.ip);
        }
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // Auto-scroll terminal log container to bottom
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addSystemLog = (text: string, type: 'info' | 'success' | 'warn' | 'error' | 'ai' = 'info') => {
    setLogs((prev) => [...prev, { text, type }]);
  };

  const resetDashboard = () => {
    setAuditId(null);
    setScanState('idle');
    setLogs([]);
    setPorts([]);
    setAiInsights([]);
    setResolvedIp(null);
    setErrorMsg(null);
    setLoading(false);
  };

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    resetDashboard();
    setLoading(true);
    setErrorMsg(null);
    addSystemLog(`[Request] Contacting ShadowAudit API Gateway for target: "${target}"...`, 'info');

    try {
      const response = await fetch(`${GATEWAY_URL}/api/audit/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target.trim() })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Verification rejected by API Gateway.');
      }

      const { auditId: newAuditId } = data;
      setAuditId(newAuditId);
      setScanState('queued');

      // Join the live WebSocket channel room for this scan
      if (socketRef.current) {
        socketRef.current.emit('join_audit', newAuditId);
      }

    } catch (err: any) {
      setErrorMsg(err.message || 'Network error connecting to Express Gateway.');
      addSystemLog(`[SecOps Block] Request Denied: ${err.message || 'Network error'}`, 'error');
      setScanState('idle');
      setLoading(false);
    }
  };

  // Helper styles based on log category
  const getLogColor = (type: string) => {
    switch (type) {
      case 'success': return 'text-emerald-400 font-semibold';
      case 'warn': return 'text-amber-400';
      case 'error': return 'text-rose-400 font-bold';
      case 'ai': return 'text-cyan-400 font-mono tracking-wide';
      default: return 'text-slate-300';
    }
  };

  return (
    <main className="container mx-auto px-4 py-8 max-w-7xl relative scan-line min-h-screen">
      {/* Background radial effects */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent" />

      {/* Header section */}
      <header className="flex flex-col md:flex-row md:items-center md:justify-between pb-8 mb-8 border-b border-white/5 gap-4">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/10 border border-cyan-500/30 shadow-lg shadow-cyan-500/5">
            <Shield className="w-6 h-6 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight text-white font-sans">ShadowAudit</h1>
              <span className="px-2 py-0.5 text-[10px] uppercase font-mono tracking-widest font-semibold bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 rounded-full">SaaS SecOps</span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">Automated Pentesting and Vulnerability Orchestrator</p>
          </div>
        </div>

        {/* Live connections indicator */}
        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-white/5 text-slate-400">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Gateway: <strong className="text-slate-200">Port 4000</strong></span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-white/5 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span>Worker: <strong className="text-slate-200">Python + Redis</strong></span>
          </div>
        </div>
      </header>

      {/* Form Submission */}
      <section className="mb-8">
        <div className="glow-border p-6 rounded-2xl bg-slate-950/40 backdrop-blur-md relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-[0.02] pointer-events-none">
            <Shield className="w-32 h-32 text-cyan-400" />
          </div>

          <h2 className="text-sm font-semibold tracking-wider text-slate-300 uppercase mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" /> Target Audit Setup
          </h2>

          <form onSubmit={handleScanSubmit} className="flex flex-col md:flex-row gap-4 items-stretch">
            <div className="relative flex-1">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4.5 h-4.5 text-slate-500" />
              <input
                type="text"
                placeholder="Domain or IP Address (e.g. scanme.nmap.org or 127.0.0.1)"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
                className="w-full pl-12 pr-4 py-3.5 bg-slate-900/80 border border-white/5 focus:border-cyan-500/50 hover:border-white/10 rounded-xl text-sm font-mono text-white placeholder-slate-500 outline-none transition-all focus:ring-1 focus:ring-cyan-500/20"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="px-6 py-3.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white rounded-xl text-sm font-medium tracking-wide shadow-lg shadow-cyan-500/10 active:scale-[0.98] transition-all flex items-center justify-center gap-2 disabled:cursor-not-allowed group cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Enqueuing Scan...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 text-white fill-white group-hover:scale-110 transition-transform" />
                  <span>Launch Security Audit</span>
                </>
              )}
            </button>
          </form>

          {/* Validation Alert details */}
          <div className="flex items-center gap-2.5 mt-3.5 px-3 py-2 bg-cyan-950/20 border border-cyan-500/10 rounded-lg">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <p className="text-[11px] text-slate-400">
              <strong className="text-cyan-400">SecOps Policy Enforced:</strong> Target MUST belong to the permitted whitelist for safe demonstration: <code className="px-1 py-0.5 rounded bg-slate-900 text-slate-200">127.0.0.1</code>, <code className="px-1 py-0.5 rounded bg-slate-900 text-slate-200">localhost</code>, or <code className="px-1 py-0.5 rounded bg-slate-900 text-slate-200">scanme.nmap.org</code>.
            </p>
          </div>

          {errorMsg && (
            <div className="flex items-start gap-3 mt-4 p-4 bg-rose-950/20 border border-rose-500/20 text-rose-400 rounded-xl text-xs">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold mb-0.5">Authorization Rejected (403 Forbidden)</strong>
                {errorMsg}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Grid Dashboard layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Terminal logs viewer */}
        <section className="lg:col-span-2 flex flex-col">
          <div className="glow-border rounded-2xl bg-slate-950/60 backdrop-blur-md overflow-hidden flex flex-col flex-1 min-h-[500px]">
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/5 bg-slate-950/80">
              <div className="flex items-center gap-2">
                <TerminalIcon className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold uppercase tracking-widest text-slate-300 font-mono">Live Auditing Terminal Console</span>
              </div>
              <div className="flex items-center gap-2">
                {scanState === 'queued' && (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-500/20 animate-pulse">
                    Queued
                  </span>
                )}
                {scanState === 'scanning' && (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-500/20 animate-pulse">
                    Scanning
                  </span>
                )}
                {scanState === 'completed' && (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/20">
                    Finished
                  </span>
                )}
                {scanState === 'failed' && (
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/60 text-rose-400 border border-rose-500/20">
                    Failed
                  </span>
                )}
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
              </div>
            </div>

            {/* Terminal Body */}
            <div className="p-5 flex-1 font-mono text-xs overflow-y-auto max-h-[480px] bg-black/40 min-h-[400px]">
              {logs.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 py-12">
                  <TerminalIcon className="w-8 h-8 text-slate-600 mb-3 animate-pulse" />
                  <p>System listening. Awaiting target initialization...</p>
                  <p className="text-[10px] text-slate-600 mt-1">Submit domain above to launch pipeline.</p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  {logs.map((log, index) => (
                    <div key={index} className="flex items-start gap-2 leading-relaxed border-l-2 border-white/5 pl-2 hover:bg-white/[0.01]">
                      <ChevronRight className="w-3.5 h-3.5 text-slate-600 shrink-0 mt-0.5" />
                      <span className={getLogColor(log.type)}>
                        {log.text}
                      </span>
                    </div>
                  ))}
                  <div ref={terminalEndRef} />
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Port results and AI analytics report panel */}
        <section className="space-y-8">
          
          {/* Target Metadata status */}
          <div className="glow-border p-5 rounded-2xl bg-slate-950/40 backdrop-blur-md">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-3.5 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" /> Target Info
            </h3>
            
            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-500">Domain</span>
                <span className="text-slate-200">{target || 'N/A'}</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-500">IP Resolved</span>
                <span className="text-emerald-400 font-semibold">{resolvedIp || 'Resolving...'}</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-500">Audit Reference</span>
                <span className="text-indigo-400 text-[10px] truncate max-w-[150px]">{auditId || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Network Engine</span>
                <span className="text-cyan-400">Nmap/Sockets</span>
              </div>
            </div>
          </div>

          {/* Port Findings Panel */}
          <div className="glow-border p-5 rounded-2xl bg-slate-950/40 backdrop-blur-md">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" /> Port Vector Findings
            </h3>

            {ports.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-xs">
                <Lock className="w-6 h-6 mx-auto mb-2 text-slate-600" />
                <p>No port vectors discovered yet.</p>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
                {ports.map((p, idx) => (
                  <div 
                    key={idx} 
                    className={`flex items-center justify-between p-3 rounded-lg border text-xs font-mono transition-all ${
                      p.state === 'open' 
                        ? 'bg-emerald-950/20 border-emerald-500/20 hover:border-emerald-500/40' 
                        : 'bg-slate-900/40 border-white/5 opacity-60'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">Port {p.port}</span>
                        <span className="text-[10px] text-slate-400 uppercase">{p.service}</span>
                      </div>
                      <span className="text-[10px] text-slate-500 block mt-0.5 truncate max-w-[160px]">{p.version}</span>
                    </div>

                    <div>
                      {p.state === 'open' ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-900/60 border border-emerald-400/30 text-emerald-400 uppercase">
                          Open
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-400 uppercase">
                          Closed
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Full width AI Vulnerability Intelligence Analysis */}
      {aiInsights.length > 0 && (
        <section className="mt-8">
          <div className="glow-border p-6 rounded-2xl bg-cyan-950/10 border-cyan-500/20 backdrop-blur-md relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-[0.03] pointer-events-none">
              <Cpu className="w-40 h-40 text-cyan-400" />
            </div>

            <h3 className="text-sm font-semibold tracking-wider text-cyan-400 uppercase mb-4 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-cyan-400 animate-pulse" /> ShadowAudit AI Cyber Intelligence
            </h3>

            <div className="space-y-4">
              {aiInsights.map((insight, idx) => {
                let alertStyle = "border-cyan-500/20 bg-cyan-950/20 text-cyan-300";
                
                if (insight.includes("CRITICAL")) {
                  alertStyle = "border-rose-500/30 bg-rose-950/20 text-rose-300";
                } else if (insight.includes("WARNING")) {
                  alertStyle = "border-amber-500/30 bg-amber-950/20 text-amber-300";
                } else if (insight.includes("PERFECT")) {
                  alertStyle = "border-emerald-500/30 bg-emerald-950/20 text-emerald-300";
                }

                return (
                  <div key={idx} className={`p-4 rounded-xl border text-xs font-mono leading-relaxed ${alertStyle}`}>
                    {insight}
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* Footer copyright */}
      <footer className="mt-12 text-center text-[10px] text-slate-500 font-mono border-t border-white/5 pt-6">
        <span>ShadowAudit &copy; 2026 - Real-time Network Security Scanning Sandbox.</span>
      </footer>
    </main>
  );
}
