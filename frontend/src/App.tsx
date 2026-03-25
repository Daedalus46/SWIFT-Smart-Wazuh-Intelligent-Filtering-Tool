import { useState } from 'react';
import axios from 'axios';
import Header from './components/Header';
import IngestionModule from './components/IngestionModule';
import IntelligenceReadout from './components/IntelligenceReadout';
import TelemetryDashboard from './components/TelemetryDashboard';

const API_BASE = 'http://127.0.0.1:8080';

export default function App() {
  const [report, setReport] = useState<any>(null);
  const [isBatch, setIsBatch] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalyze = async (payload: any) => {
    setIsLoading(true);
    setReport(null);
    setIsBatch(false);
    try {
      const response = await axios.post(`${API_BASE}/analyze`, payload);
      setReport(response.data);
    } catch (e: any) {
      console.error(e);
      if (e.response && e.response.status === 422) {
        alert("Invalid JSON Schema! Require: timestamp, rule_level, decoder_name, rule_description, agent_ip.");
      } else {
        alert("Analysis failed. Backend might be offline or caching previous version. Restart Uvicorn.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeCSV = async (file: File) => {
    setIsLoading(true);
    setReport(null);
    setIsBatch(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post(`${API_BASE}/analyze_csv`, formData);
      setReport(response.data);
    } catch (e) {
      console.error(e);
      alert("CSV Bulk Analysis failed. Check logs.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col min-h-screen font-sans text-slate-200 bg-slate-900">
      <Header />
      
      <main className="flex-grow p-6">
        <div className="max-w-7xl mx-auto flex flex-col space-y-6 h-full">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ minHeight: '500px' }}>
            <IngestionModule 
                onAnalyze={handleAnalyze} 
                onAnalyzeCSV={handleAnalyzeCSV} 
                isLoading={isLoading} 
            />
            <IntelligenceReadout report={report} isBatch={isBatch} />
          </div>
          
          <div className="h-[500px] mt-6">
            <TelemetryDashboard batchReport={isBatch ? report : null} />
          </div>
        </div>
      </main>
    </div>
  );
}
