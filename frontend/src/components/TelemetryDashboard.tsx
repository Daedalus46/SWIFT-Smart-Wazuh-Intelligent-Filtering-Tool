import { useState } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { Activity } from 'lucide-react';

const COLORS = ['#10b981', '#ef4444']; // emerald, neonRed

export default function TelemetryDashboard({ batchReport }: any) {
  // If we have a live batch report, process its counts dynamically!
  // Otherwise use the default static background baseline data
  const [activeFilter, setActiveFilter] = useState<string | null>(null);

  const pieData = batchReport 
    ? [
        { name: 'Benign Noise', value: batchReport.benign_count },
        { name: 'Malicious Events', value: batchReport.malicious_count }
      ]
    : [
        { name: 'Benign Noise', value: 7000 },
        { name: 'Malicious Events', value: 3000 },
      ];

  const totalLogs = pieData[0].value + pieData[1].value;
  const maliciousRatio = totalLogs > 0 ? Math.round((pieData[1].value / totalLogs) * 100) : 30;
  const ratioString = batchReport ? `${100 - maliciousRatio}/${maliciousRatio}` : `70/30`;

  // Scale bars realistically depending on batch threats
  const barData = batchReport
    ? [
        { severity: 'Low', count: Math.floor(batchReport.benign_count * 0.8) },
        { severity: 'Medium', count: Math.floor(batchReport.benign_count * 0.2) + Math.floor(batchReport.malicious_count * 0.1) },
        { severity: 'High', count: Math.floor(batchReport.malicious_count * 0.6) },
        { severity: 'Critical', count: Math.floor(batchReport.malicious_count * 0.3) },
      ]
    : [
        { severity: 'Low', count: 4000 },
        { severity: 'Medium', count: 2500 },
        { severity: 'High', count: 1800 },
        { severity: 'Critical', count: 568 },
      ];

  return (
    <div className="flex flex-col h-full bg-slate-800 border border-slate-700 rounded-lg p-4 shadow-xl">
      <div className="flex items-center justify-between mb-2 border-b border-slate-700 pb-2">
        <div className="flex items-center space-x-2 text-slate-300">
           <Activity className="w-5 h-5 text-slate-400" />
           <h2 className="text-sm font-bold tracking-widest uppercase">
              {batchReport ? "Live Batch Telemetry" : "System Baseline Telemetry"}
           </h2>
        </div>
        {activeFilter && (
           <div className="text-[10px] bg-slate-700 px-2 py-1 rounded text-slate-300 font-mono cursor-pointer" onClick={() => setActiveFilter(null)}>
             CLEAR FILTER: {activeFilter}
           </div>
        )}
      </div>
      <div className="flex flex-col md:flex-row flex-grow min-h-0">
        <div className="flex-1 h-32 md:h-full min-h-0 relative cursor-pointer" onClick={() => setActiveFilter('PIE')}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                innerRadius="60%"
                outerRadius="90%"
                paddingAngle={2}
                dataKey="value"
                stroke="transparent"
              >
                {pieData.map((_entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <RechartsTooltip 
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '4px', fontSize: '12px', zIndex: 10 }}
                itemStyle={{ color: '#f8fafc' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <span className="text-[10px] font-mono tracking-widest text-slate-400 text-center">{ratioString}<br/>SPLIT</span>
          </div>
        </div>
        <div className="flex-[2] h-40 md:h-full min-h-0 pt-4 px-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="severity" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
              <RechartsTooltip 
                cursor={{ fill: '#1e293b' }}
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '4px', fontSize: '12px' }}
              />
              <Bar 
                 dataKey="count" 
                 radius={[4, 4, 0, 0]} 
                 maxBarSize={40} 
                 onClick={(data) => setActiveFilter(data.severity)}
                 style={{ cursor: 'pointer' }}
              >
                {
                  barData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={
                        activeFilter && activeFilter !== entry.severity ? '#334155' :
                        (entry.severity === 'Critical' || entry.severity === 'High' ? '#ef4444' : '#3b82f6')
                    } />
                  ))
                }
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
