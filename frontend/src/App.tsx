import { useState } from 'react';
import axios from 'axios';
import Header from './components/Header';
import IngestionModule from './components/IngestionModule';
import IntelligenceReadout from './components/IntelligenceReadout';
import TelemetryDashboard from './components/TelemetryDashboard';

const API_BASE = import.meta.env.VITE_API_BASE || "https://daedalus26-swift-soc-backend.hf.space";


export default function App() {
  const [report, setReport] = useState<any>(null);
  const [isBatch, setIsBatch] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalyzeCSV = async (file: File) => {
    setIsLoading(true);
    setReport(null);
    setIsBatch(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API_BASE}/analyze_csv`, formData);
      setReport(response.data);
    } catch (e: any) {
      console.error(e);
      const backendMsg = e?.response?.data?.detail;
      alert(backendMsg || "CSV Bulk Analysis failed. Backend might be offline.");
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
              onAnalyzeCSV={handleAnalyzeCSV}
              isLoading={isLoading}
            />
            <IntelligenceReadout report={report} isBatch={isBatch} onClear={() => { setReport(null); setIsBatch(false); }} />
          </div>

          <div className="w-full mt-6 flex-grow">
            <TelemetryDashboard batchReport={isBatch ? report : null} />
          </div>
        </div>
      </main>
    </div>
  );
}
