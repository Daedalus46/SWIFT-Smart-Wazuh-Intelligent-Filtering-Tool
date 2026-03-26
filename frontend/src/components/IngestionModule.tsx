import { useState } from 'react';
import { Terminal, Send, UploadCloud } from 'lucide-react';

export default function IngestionModule({ onAnalyze, onAnalyzeCSV, isLoading }: any) {
  const defaultLog = '{\n  "timestamp": "2026-03-25T14:05:22.123Z",\n  "rule_level": 3,\n  "decoder_name": "web-accesslog",\n  "rule_description": "Normal GET request to /index.html",\n  "agent_ip": "192.168.1.50"\n}';
  const [logInput, setLogInput] = useState(defaultLog);
  const [file, setFile] = useState<File | null>(null);

  const handleSubmit = () => {
    if (file) {
      onAnalyzeCSV(file);
      // Clean UI: Clear tracking states locally
      setFile(null);
    } else {
      try {
        const parsed = JSON.parse(logInput);
        onAnalyze(parsed);
      } catch (e) {
        alert("Invalid JSON format.");
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-800 border border-slate-700 rounded-lg p-4 shadow-xl">
      <div className="flex items-center space-x-2 mb-4 text-slate-300 border-b border-slate-700 pb-2">
        <Terminal className="w-5 h-5 text-slate-400" />
        <h2 className="text-sm font-bold tracking-widest uppercase">Raw Telemetry Ingestion</h2>
      </div>
      
      {!file ? (
        <textarea
          value={logInput}
          onChange={(e) => setLogInput(e.target.value)}
          className="flex-grow w-full bg-slate-950 text-emeraldGreen font-mono text-xs p-4 rounded focus:outline-none focus:ring-1 focus:ring-slate-500 resize-none"
          spellCheck="false"
          aria-label="Raw JSON log payload input"
        />
      ) : (
        <div className="flex-grow flex flex-col items-center justify-center bg-slate-950/50 rounded border-2 border-dashed border-emeraldGreen/50">
          <UploadCloud className="w-12 h-12 text-emeraldGreen mb-3" />
          <p className="text-emeraldGreen font-mono text-sm">Target Locked: {file.name}</p>
          <button 
            onClick={() => setFile(null)}
            className="mt-4 text-xs text-slate-400 hover:text-white underline font-mono cursor-pointer"
          >
            Clear Selected File
          </button>
        </div>
      )}

      <div className="mt-4 flex space-x-2">
        <label className="flex-1 flex items-center justify-center space-x-2 py-3 bg-slate-700 hover:bg-slate-600 text-slate-300 cursor-pointer text-xs font-semibold rounded transition" aria-label="Upload CSV file for bulk analysis">
          <UploadCloud className="w-4 h-4" />
          <span>UPLOAD CSV</span>
          <input type="file" accept=".csv" className="hidden" onChange={handleFileChange} aria-label="Select CSV file" />
        </label>

        <button 
          onClick={handleSubmit}
          disabled={isLoading}
          aria-label={file ? "Execute batch CSV analysis" : "Execute single log AI analysis"}
          className="flex-[2] flex items-center justify-center space-x-2 py-3 bg-emerald-700/80 hover:bg-emerald-600/80 text-white font-bold rounded transition disabled:opacity-50 text-xs tracking-widest"
        >
          {isLoading ? (
            <span className="animate-pulse">PROCESSING TELEMETRY...</span>
          ) : (
            <>
              <Send className="w-4 h-4" />
              <span>{file ? "EXECUTE BATCH ANALYSIS" : "EXECUTE AI ANALYSIS"}</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
