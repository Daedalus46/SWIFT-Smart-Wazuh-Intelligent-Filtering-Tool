import { useState } from 'react';
import { Terminal, Send, UploadCloud } from 'lucide-react';

export default function IngestionModule({ onAnalyzeCSV, isLoading }: any) {
  const [file, setFile] = useState<File | null>(null);

  const handleSubmit = () => {
    if (file) {
      onAnalyzeCSV(file);
      // Clean UI: Clear tracking states locally
      setFile(null);
    } else {
      alert("Please upload a CSV file first.");
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
        <h2 className="text-sm font-bold tracking-widest uppercase">Batch Telemetry Ingestion</h2>
      </div>
      
      {!file ? (
        <div className="flex-grow flex flex-col items-center justify-center bg-slate-950/50 rounded border-2 border-dashed border-slate-600/50">
          <UploadCloud className="w-10 h-10 text-slate-500 mb-3" />
          <p className="text-slate-500 font-mono text-sm text-center px-4">
            Upload Wazuh logs or Kibana exports (.csv) to begin AI analysis.
          </p>
        </div>
      ) : (
        <div className="flex-grow flex flex-col items-center justify-center bg-slate-950/50 rounded border-2 border-dashed border-emeraldGreen/50">
          <UploadCloud className="w-12 h-12 text-emeraldGreen mb-3" />
          <p className="text-emeraldGreen font-mono text-sm text-center px-4">Target Locked:<br/>{file.name}</p>
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
          disabled={isLoading || !file}
          aria-label="Execute batch CSV analysis"
          className="flex-[2] flex items-center justify-center space-x-2 py-3 bg-emerald-700/80 hover:bg-emerald-600/80 text-white font-bold rounded transition disabled:opacity-50 text-xs tracking-widest"
        >
          {isLoading ? (
            <span className="animate-pulse">PROCESSING TELEMETRY...</span>
          ) : (
            <>
              <Send className="w-4 h-4" />
              <span>EXECUTE BATCH ANALYSIS</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
