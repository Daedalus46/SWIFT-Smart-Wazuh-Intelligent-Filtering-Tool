import { AlertTriangle, CheckCircle, BrainCircuit, Shield, Globe, FileOutput, Sparkles, Zap, Target, XCircle, Download } from 'lucide-react';
import axios from 'axios';
import { useState, useEffect, useRef } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || 'https://daedalus26-swift-soc-backend.hf.space';

export default function IntelligenceReadout({ report, isBatch, onClear }: any) {
  const [downloading, setDownloading] = useState(false);
  const [nlpReport, setNlpReport] = useState<any>(null);
  const [nlpLoading, setNlpLoading] = useState(false);
  const [nlpTimer, setNlpTimer] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // NLP loading timer
  useEffect(() => {
    if (nlpLoading) {
      setNlpTimer(0);
      timerRef.current = setInterval(() => setNlpTimer(t => t + 1), 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [nlpLoading]);

  const downloadPDFReport = async () => {
    if (!report || !report.raw_malicious_logs) return;
    setDownloading(true);
    try {
      const payload = {
        total_logs: report.total_logs,
        malicious_count: report.malicious_count,
        raw_malicious_logs: report.raw_malicious_logs
      };

      const response = await axios.post(`${API_BASE}/generate_pdf`, payload, {
        responseType: 'blob'
      });

      const blob = new Blob([response.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `Security_Report_${new Date().toISOString().slice(0,10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (error) {
       console.error("PDF Export failed:", error);
       alert("Failed to generate PDF document.");
    } finally {
      setDownloading(false);
    }
  };

  const generateNLPReport = async () => {
    if (!report) return;
    setNlpLoading(true);
    setNlpReport(null);
    try {
      // Build payload — works for both single and batch modes
      const unique_threats = isBatch
        ? report.unique_threats
        : [{
            threat_classification: report.threat_classification,
            rule_description: report.rule_description || "Single log analysis",
            mitre_tactic: report.mitre_tactic,
            owasp_category: report.owasp_category,
            mitigation_steps: report.mitigation_steps || [],
            occurrence_count: 1,
            ai_confidence_score: report.ai_confidence_score,
          }];

      const payload = {
        total_logs: isBatch ? report.total_logs : 1,
        benign_count: isBatch ? report.benign_count : (report.threat_classification === "Benign Noise" ? 1 : 0),
        malicious_count: isBatch ? report.malicious_count : (report.threat_classification === "Malicious Threat" ? 1 : 0),
        unique_threats,
      };
      const response = await axios.post(`${API_BASE}/generate_nlp_report`, payload);
      setNlpReport(response.data);
    } catch (error) {
      console.error("NLP Report failed:", error);
      alert("NLP report generation failed. Ensure transformers & torch are installed.");
    } finally {
      setNlpLoading(false);
    }
  };

  const exportCSV = () => {
    if (!report?.raw_malicious_logs) return;
    const header = "Timestamp,Rule Description,MITRE ID,OWASP,Agent IP\n";
    const rows = report.raw_malicious_logs.map((l: any) =>
      `"${l.timestamp}","${l.rule_description}","${l.mitre_id}","${l.owasp_cat}","${l.agent_ip}"`
    ).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = `Malicious_Logs_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const riskColors: Record<string, string> = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH: 'bg-orange-500 text-white',
    MEDIUM: 'bg-yellow-500 text-black',
    LOW: 'bg-emerald-600 text-white',
    NONE: 'bg-slate-600 text-white',
  };

  // Confidence bar component
  const ConfidenceBar = ({ score, label }: { score: number; label?: string }) => (
    <div className="w-full">
      {label && <div className="text-[9px] text-slate-500 font-mono mb-0.5">{label}</div>}
      <div className="w-full bg-slate-700 rounded-full h-1.5">
        <div
          className={`h-1.5 rounded-full transition-all duration-700 ${score >= 80 ? 'bg-red-500' : score >= 50 ? 'bg-orange-400' : 'bg-emerald-500'}`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>
    </div>
  );

  // NLP Report Panel — shared between single and batch
  const NLPReportPanel = () => (
    <>
      {nlpLoading && (
        <div className="mb-4 p-4 bg-violet-950/30 border border-violet-500/30 rounded animate-pulse">
          <div className="flex items-center space-x-2">
            <BrainCircuit className="w-4 h-4 text-violet-400 animate-spin" />
            <span className="text-violet-300 text-xs font-mono tracking-widest">
              NLP MODEL PROCESSING... {nlpTimer}s {nlpTimer < 5 ? '(First run downloads ~300MB model)' : 'elapsed'}
            </span>
          </div>
        </div>
      )}

      {nlpReport && (
        <div className="mb-4 p-4 bg-violet-950/20 border border-violet-500/30 rounded space-y-3">
          {/* Header + Risk Badge */}
          <div className="flex items-center justify-between border-b border-violet-500/20 pb-2">
            <div className="flex items-center space-x-2">
              <Sparkles className="w-4 h-4 text-violet-400" />
              <span className="text-violet-300 text-[10px] font-bold tracking-widest uppercase">AI-Generated Incident Report (NLP)</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`px-3 py-1 rounded text-[10px] font-bold tracking-widest ${riskColors[nlpReport.risk_assessment?.level] || 'bg-slate-600 text-white'}`}>
                RISK: {nlpReport.risk_assessment?.level} ({nlpReport.risk_assessment?.score}/100)
              </span>
              <span className="text-violet-500 text-[9px] font-mono">{nlpReport.model_used} | {nlpReport.device}</span>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <div className="text-[10px] text-violet-400 font-mono tracking-widest uppercase mb-1">Executive Summary</div>
            <p className="text-xs text-slate-200 leading-relaxed">{nlpReport.executive_summary}</p>
          </div>

          {/* Top Threat Vectors + Priority Actions side by side */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <div className="flex items-center space-x-1 mb-1">
                <Target className="w-3 h-3 text-neonRed" />
                <span className="text-[10px] text-violet-400 font-mono tracking-widest uppercase">Top Threat Vectors</span>
              </div>
              <div className="space-y-1">
                {nlpReport.top_threat_vectors?.map((v: any, i: number) => (
                  <div key={i} className="bg-slate-900/50 rounded px-2 py-1 border border-slate-700/50">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-neonRed font-mono truncate mr-2">{v.description}</span>
                      <span className="text-[9px] text-slate-400 font-mono whitespace-nowrap">x{v.occurrences} | {v.confidence}%</span>
                    </div>
                    <ConfidenceBar score={v.confidence} />
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-1 mb-1">
                <Zap className="w-3 h-3 text-yellow-400" />
                <span className="text-[10px] text-violet-400 font-mono tracking-widest uppercase">Priority Actions</span>
              </div>
              <ul className="space-y-1">
                {nlpReport.priority_actions?.map((action: string, i: number) => (
                  <li key={i} className="text-[10px] text-slate-300 font-mono bg-slate-900/50 rounded px-2 py-1 border border-slate-700/50 flex items-start space-x-1">
                    <span className="text-yellow-400 font-bold">{i+1}.</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Stats Bar */}
          <div className="flex space-x-4 pt-2 border-t border-violet-500/20">
            <span className="text-[9px] text-slate-500 font-mono">
              {nlpReport.stats?.threat_ratio_pct}% threat ratio | {nlpReport.stats?.unique_threat_types} unique types | {nlpReport.stats?.unique_tactics} tactics detected
            </span>
          </div>
        </div>
      )}
    </>
  );

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-slate-800 border border-slate-700 rounded-lg p-4 shadow-xl text-slate-500">
        <BrainCircuit className="w-12 h-12 mb-4 opacity-50" />
        <p className="font-mono text-sm tracking-widest text-center">AWAITING IDENTIFICATION...<br/>READY FOR SINGLE LOG OR CSV BULK</p>
      </div>
    );
  }

  // =================== BATCH VIEW ===================
  if (isBatch && report.unique_threats) {
    return (
      <div className="flex flex-col h-full border rounded-lg p-6 shadow-xl bg-slate-800 border-slate-700 transition-all duration-500">
        <div className="flex items-center justify-between mb-4 border-b border-slate-700/50 pb-4">
          <div className="flex items-center space-x-3">
            <Shield className="w-6 h-6 text-slate-200" />
            <div>
              <h2 className="text-lg font-bold tracking-widest uppercase text-slate-200 leading-tight">
                Batch Analysis Report
              </h2>
              <div className="flex flex-wrap gap-2 mt-2">
                <button 
                  onClick={downloadPDFReport}
                  disabled={downloading}
                  aria-label="Download PDF security report"
                  className="flex items-center space-x-1 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-[10px] font-bold tracking-widest rounded border border-slate-600 transition disabled:opacity-50"
                >
                  <FileOutput className="w-3 h-3" />
                  <span>{downloading ? "GENERATING..." : "DOWNLOAD PDF"}</span>
                </button>
                <button 
                  onClick={generateNLPReport}
                  disabled={nlpLoading}
                  aria-label="Generate AI-powered NLP incident report"
                  className="flex items-center space-x-1 px-3 py-1 bg-violet-800/60 hover:bg-violet-700/60 text-violet-200 text-[10px] font-bold tracking-widest rounded border border-violet-600/50 transition disabled:opacity-50"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>{nlpLoading ? "AI THINKING..." : "GENERATE AI REPORT"}</span>
                </button>
                <button 
                  onClick={exportCSV}
                  aria-label="Export malicious logs as CSV"
                  className="flex items-center space-x-1 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-[10px] font-bold tracking-widest rounded border border-slate-600 transition"
                >
                  <Download className="w-3 h-3" />
                  <span>EXPORT CSV</span>
                </button>
                {onClear && (
                  <button 
                    onClick={onClear}
                    aria-label="Clear analysis results"
                    className="flex items-center space-x-1 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-400 text-[10px] font-bold tracking-widest rounded border border-slate-600 transition"
                  >
                    <XCircle className="w-3 h-3" />
                    <span>CLEAR</span>
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="text-right flex space-x-4">
             <div>
                <div className="text-[10px] text-slate-400 font-mono tracking-widest">BENIGN</div>
                <div className="text-xl font-bold font-mono text-emeraldGreen">{report.benign_count}</div>
             </div>
             <div>
                <div className="text-[10px] text-slate-400 font-mono tracking-widest">THREATS</div>
                <div className="text-xl font-bold font-mono text-neonRed">{report.malicious_count}</div>
             </div>
          </div>
        </div>

        {/* NLP Report Panel */}
        <NLPReportPanel />

        <div className="flex-grow overflow-y-auto space-y-4 pr-2">
          {report.unique_threats.length === 0 ? (
             <div className="text-center p-8 text-emeraldGreen font-mono border border-emeraldGreen/30 bg-emerald-950/20 rounded">
               NO MALICIOUS ACTIVITY DETECTED IN BATCH
             </div>
          ) : (
            report.unique_threats.map((threat: any, idx: number) => (
              <div key={idx} className="relative bg-red-950/20 border border-neonRed/30 rounded p-4 flex flex-col space-y-2">
                 <div className="absolute top-2 right-2 bg-neonRed/20 border border-neonRed text-neonRed text-[10px] font-bold px-2 py-1 rounded tracking-widest">
                    COUNT: {threat.occurrence_count}
                 </div>
                 
                 <div className="flex justify-between items-center border-b border-slate-700/50 pb-2 mr-20">
                    <span className="font-bold text-neonRed uppercase text-sm">{threat.rule_description}</span>
                 </div>

                 {/* Confidence bar */}
                 <div className="flex items-center space-x-3">
                   <span className="text-[10px] text-slate-400 font-mono tracking-widest whitespace-nowrap">AI CONF: {threat.ai_confidence_score}%</span>
                   <ConfidenceBar score={threat.ai_confidence_score} />
                 </div>
                 
                 <div className="grid grid-cols-2 gap-4">
                    <div>
                       <div className="text-[10px] text-slate-400 font-mono tracking-widest">MITRE ATT&CK</div>
                       <div className="text-xs text-slate-200 font-mono mt-1 truncate">{threat.mitre_tactic}</div>
                    </div>
                    <div>
                       <div className="text-[10px] text-slate-400 font-mono tracking-widest">OWASP TOP 10</div>
                       <div className="text-xs text-slate-200 font-mono mt-1 truncate">{threat.owasp_category}</div>
                    </div>
                 </div>
                 
                 <div className="mt-2 pt-2 border-t border-slate-700/50">
                    <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest mb-2">Automated Mitigation Strategy</div>
                    <ul className="list-disc pl-4 space-y-1">
                      {threat.mitigation_steps.map((step: string, i: number) => (
                         <li key={i} className="text-[11px] font-mono text-slate-300">{step}</li>
                      ))}
                    </ul>
                 </div>
              </div>
            ))
          )}
        </div>
      </div>
    );
  }

  // =================== SINGLE LOG VIEW ===================
  const isMalicious = report.threat_classification === "Malicious Threat";
  const themeColor = isMalicious ? "text-neonRed" : "text-emeraldGreen";
  const bgTheme = isMalicious ? "bg-red-950/20 border-neonRed/30" : "bg-emerald-950/20 border-emeraldGreen/30";

  return (
    <div className={`flex flex-col h-full border rounded-lg p-6 shadow-xl transition-all duration-500 ${bgTheme} bg-slate-800`}>
      <div className="flex items-center justify-between mb-4 border-b border-slate-700/50 pb-4">
        <div className="flex items-center space-x-3">
          {isMalicious ? <AlertTriangle className={`w-6 h-6 ${themeColor}`} /> : <CheckCircle className={`w-6 h-6 ${themeColor}`} />}
          <h2 className={`text-lg font-bold tracking-widest uppercase ${themeColor}`}>
            {report.threat_classification}
          </h2>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest">AI Confidence</div>
          <div className={`text-2xl font-bold font-mono ${themeColor}`}>{report.ai_confidence_score}%</div>
          <ConfidenceBar score={report.ai_confidence_score} />
        </div>
      </div>

      {/* Action buttons for single log */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button 
          onClick={generateNLPReport}
          disabled={nlpLoading}
          aria-label="Generate AI-powered NLP incident report"
          className="flex items-center space-x-1 px-3 py-1 bg-violet-800/60 hover:bg-violet-700/60 text-violet-200 text-[10px] font-bold tracking-widest rounded border border-violet-600/50 transition disabled:opacity-50"
        >
          <Sparkles className="w-3 h-3" />
          <span>{nlpLoading ? "AI THINKING..." : "GENERATE AI REPORT"}</span>
        </button>
        {onClear && (
          <button 
            onClick={onClear}
            aria-label="Clear analysis results"
            className="flex items-center space-x-1 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-400 text-[10px] font-bold tracking-widest rounded border border-slate-600 transition"
          >
            <XCircle className="w-3 h-3" />
            <span>CLEAR</span>
          </button>
        )}
      </div>

      {/* NLP Report Panel */}
      <NLPReportPanel />
      
      <div className="space-y-4 flex-grow flex flex-col">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest mb-1">MITRE ATT&CK Mapping</div>
            <div className="flex items-center space-x-2 text-slate-200 bg-slate-900/50 px-3 py-2 rounded border border-slate-700/50">
              <Shield className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="font-mono text-xs tracking-wide truncate">{report.mitre_tactic}</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest mb-1">OWASP Top 10 Category</div>
            <div className="flex items-center space-x-2 text-slate-200 bg-slate-900/50 px-3 py-2 rounded border border-slate-700/50">
              <Globe className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="font-mono text-xs tracking-wide truncate">{report.owasp_category}</span>
            </div>
          </div>
        </div>

        <div className="flex-grow flex flex-col mt-4">
          <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest mb-2">Automated Mitigation Strategy</div>
          <div className="bg-slate-900/50 rounded p-4 border border-slate-700/50 flex-grow overflow-y-auto">
             <ul className="list-disc pl-4 space-y-2">
               {report.mitigation_steps.map((step: string, i: number) => (
                  <li key={i} className="text-xs font-mono text-slate-300 leading-relaxed">{step}</li>
               ))}
             </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
