import { AlertTriangle, CheckCircle, BrainCircuit, Shield, Globe, FileOutput } from 'lucide-react';
import axios from 'axios';
import { useState } from 'react';

export default function IntelligenceReadout({ report, isBatch }: any) {
  const [downloading, setDownloading] = useState(false);

  const downloadPDFReport = async () => {
    if (!report || !report.raw_malicious_logs) return;
    setDownloading(true);
    try {
      const payload = {
        total_logs: report.total_logs,
        malicious_count: report.malicious_count,
        raw_malicious_logs: report.raw_malicious_logs
      };

      const response = await axios.post('http://127.0.0.1:8080/generate_pdf', payload, {
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

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-slate-800 border border-slate-700 rounded-lg p-4 shadow-xl text-slate-500">
        <BrainCircuit className="w-12 h-12 mb-4 opacity-50" />
        <p className="font-mono text-sm tracking-widest text-center">AWAITING IDENTIFICATION...<br/>READY FOR SINGLE LOG OR CSV BULK</p>
      </div>
    );
  }

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
              <button 
                onClick={downloadPDFReport}
                disabled={downloading}
                className="mt-2 flex items-center space-x-1 px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-[10px] font-bold tracking-widest rounded border border-slate-600 transition disabled:opacity-50"
              >
                <FileOutput className="w-3 h-3" />
                <span>{downloading ? "GENERATING..." : "DOWNLOAD SECURITY PDF"}</span>
              </button>
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

  const isMalicious = report.threat_classification === "Malicious Threat";
  const themeColor = isMalicious ? "text-neonRed" : "text-emeraldGreen";
  const bgTheme = isMalicious ? "bg-red-950/20 border-neonRed/30" : "bg-emerald-950/20 border-emeraldGreen/30";

  return (
    <div className={`flex flex-col h-full border rounded-lg p-6 shadow-xl transition-all duration-500 ${bgTheme} bg-slate-800`}>
      <div className="flex items-center justify-between mb-6 border-b border-slate-700/50 pb-4">
        <div className="flex items-center space-x-3">
          {isMalicious ? <AlertTriangle className={`w-6 h-6 ${themeColor}`} /> : <CheckCircle className={`w-6 h-6 ${themeColor}`} />}
          <h2 className={`text-lg font-bold tracking-widest uppercase ${themeColor}`}>
            {report.threat_classification}
          </h2>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-slate-400 font-mono uppercase tracking-widest">AI Confidence</div>
          <div className={`text-2xl font-bold font-mono ${themeColor}`}>{report.ai_confidence_score}%</div>
        </div>
      </div>
      
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
