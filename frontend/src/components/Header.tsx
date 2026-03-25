import { useState, useEffect } from 'react';
import { ShieldAlert } from 'lucide-react';

export default function Header() {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="flex items-center justify-between px-6 py-4 bg-slate-900 border-b border-slate-800">
      <div className="flex items-center space-x-3">
        <ShieldAlert className="w-6 h-6 text-emeraldGreen" />
        <h1 className="text-xl font-bold tracking-widest uppercase text-slate-100">SWIFT: Smart Wazuh Intelligent Filtering Tool</h1>
      </div>
      <div className="text-sm font-mono text-slate-400">SYS_TIME: {time}</div>
    </header>
  );
}
