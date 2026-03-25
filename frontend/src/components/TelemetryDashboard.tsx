import { useState } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { Activity, Shield, Target } from 'lucide-react';

const PIE_COLORS = ['#10b981', '#ef4444']; // emerald, neonRed
const SEV_COLORS: Record<string, string> = { Low: '#3b82f6', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
const TACTIC_COLOR = '#8b5cf6'; // violet

export default function TelemetryDashboard({ batchReport }: any) {
  const [activeFilter, setActiveFilter] = useState<string | null>(null);

  // Pie: Benign vs Malicious
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

  // Severity: Use real rule_level breakdown if available, otherwise static
  const barData = batchReport?.severity_breakdown
    ? [
        { severity: 'Low', count: batchReport.severity_breakdown.low },
        { severity: 'Medium', count: batchReport.severity_breakdown.medium },
        { severity: 'High', count: batchReport.severity_breakdown.high },
        { severity: 'Critical', count: batchReport.severity_breakdown.critical },
      ]
    : [
        { severity: 'Low', count: 4000 },
        { severity: 'Medium', count: 2500 },
        { severity: 'High', count: 1800 },
        { severity: 'Critical', count: 568 },
      ];

  // MITRE Tactic Distribution (from threat_categories)
  const tacticData = batchReport?.threat_categories
    ? batchReport.threat_categories.map((cat: any) => ({
        tactic: cat.tactic.length > 20 ? cat.tactic.slice(0, 18) + '...' : cat.tactic,
        fullTactic: cat.tactic,
        count: cat.total_occurrences,
        types: cat.threat_count,
      }))
    : null;

  // Top 5 Threats by Frequency
  const topThreats = batchReport?.unique_threats
    ? [...batchReport.unique_threats]
        .sort((a: any, b: any) => b.occurrence_count - a.occurrence_count)
        .slice(0, 5)
        .map((t: any) => ({
          name: t.rule_description.length > 25 ? t.rule_description.slice(0, 23) + '...' : t.rule_description,
          fullName: t.rule_description,
          count: t.occurrence_count,
          confidence: t.ai_confidence_score,
        }))
    : null;

  return (
    <div className="flex flex-col h-full bg-slate-800 border border-slate-700 rounded-lg p-4 shadow-xl">
      <div className="flex items-center justify-between mb-4 border-b border-slate-700 pb-3">
        <div className="flex items-center space-x-2 text-slate-300">
           <Activity className="w-5 h-5 text-slate-400" />
           <h2 className="text-base font-bold tracking-widest uppercase">
              {batchReport ? "Live Batch Telemetry" : "System Baseline Telemetry"}
           </h2>
        </div>
        {activeFilter && (
           <div className="text-xs bg-slate-700 px-3 py-1 rounded text-slate-300 font-mono cursor-pointer" onClick={() => setActiveFilter(null)}>
             CLEAR FILTER: {activeFilter}
           </div>
        )}
      </div>

      {/* Row 1: Pie + Severity Bar */}
      <div className="flex flex-col md:flex-row flex-grow min-h-0" style={{ maxHeight: tacticData || topThreats ? '45%' : '100%' }}>
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
                  <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
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
          <div className="text-xs text-slate-400 font-mono tracking-widest uppercase mb-2">Severity Breakdown {batchReport?.severity_breakdown ? '(REAL)' : '(BASELINE)'}</div>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={barData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="severity" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <RechartsTooltip 
                cursor={{ fill: '#1e293b' }}
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '4px', fontSize: '12px' }}
              />
              <Bar 
                 dataKey="count" 
                 radius={[4, 4, 0, 0]} 
                 maxBarSize={60} 
                 onClick={(data) => setActiveFilter(data.severity)}
                 style={{ cursor: 'pointer' }}
              >
                {
                  barData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={
                        activeFilter && activeFilter !== entry.severity ? '#334155' :
                        (SEV_COLORS[entry.severity] || '#3b82f6')
                    } />
                  ))
                }
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 2: MITRE Tactics + Top Threats (only when batch data available) */}
      {(tacticData || topThreats) && (
        <div className="flex flex-col md:flex-row min-h-0 mt-2 border-t border-slate-700 pt-2" style={{ height: '50%' }}>
          {/* MITRE Tactic Distribution */}
          {tacticData && tacticData.length > 0 && (
            <div className="flex-1 min-h-0 pr-2 pt-2">
              <div className="flex items-center space-x-1 mb-2">
                <Shield className="w-4 h-4 text-violet-400" />
                <span className="text-xs text-slate-400 font-mono tracking-widest uppercase">MITRE ATT&CK Tactics</span>
              </div>
              <ResponsiveContainer width="100%" height="90%">
                <BarChart data={tacticData} layout="vertical" margin={{ top: 0, right: 10, left: 10, bottom: 0 }}>
                  <XAxis type="number" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="tactic" stroke="#475569" tick={{ fill: '#c4b5fd', fontSize: 11 }} axisLine={false} tickLine={false} width={130} />
                  <RechartsTooltip 
                    cursor={{ fill: '#1e293b' }}
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '4px', fontSize: '12px' }}
                    formatter={(value: any, _name: any, props: any) => [`${value} occurrences (${props.payload.types} types)`, 'Tactic']}
                  />
                  <Bar dataKey="count" fill={TACTIC_COLOR} radius={[0, 4, 4, 0]} maxBarSize={30} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Top Threats by Frequency */}
          {topThreats && topThreats.length > 0 && (
            <div className="flex-1 min-h-0 pl-2 pt-2">
              <div className="flex items-center space-x-1 mb-2">
                <Target className="w-4 h-4 text-neonRed" />
                <span className="text-xs text-slate-400 font-mono tracking-widest uppercase">Top Threats by Frequency</span>
              </div>
              <ResponsiveContainer width="100%" height="90%">
                <BarChart data={topThreats} layout="vertical" margin={{ top: 0, right: 10, left: 0, bottom: 0 }}>
                  <XAxis type="number" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" stroke="#475569" tick={{ fill: '#fca5a5', fontSize: 11 }} axisLine={false} tickLine={false} width={150} />
                  <RechartsTooltip 
                    cursor={{ fill: '#1e293b' }}
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '4px', fontSize: '12px' }}
                    formatter={(value: any, _name: any, props: any) => [`${value} hits (${props.payload.confidence}% conf)`, 'Threat']}
                  />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} maxBarSize={30} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
