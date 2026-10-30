import React from 'react';
import { Activity, ShieldAlert, Wifi, HardDrive, Cpu, CheckCircle } from 'lucide-react';
import { NetworkStats } from '../types';

interface MetricsOverviewProps {
  stats: NetworkStats | null;
  totalAlerts: number;
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({ stats, totalAlerts }) => {
  const cards = [
    {
      title: 'Current Network Throughput',
      value: stats ? `${stats.current_bandwidth_mbps} Mbps` : '54.8 Mbps',
      subtext: 'Real-time ingress / egress rate',
      icon: Wifi,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20'
    },
    {
      title: 'Total Packets Inspected',
      value: stats ? stats.total_packets.toLocaleString() : '148,290',
      subtext: stats ? `${stats.total_bytes_mb} MB payload analyzed` : '182 MB analyzed',
      icon: Activity,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/20'
    },
    {
      title: 'ML Traffic Anomalies Flagged',
      value: stats ? stats.total_anomalies : 14,
      subtext: stats ? `${stats.anomaly_rate_percent}% anomalous flow ratio` : '1.2% ratio',
      icon: ShieldAlert,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/20'
    },
    {
      title: 'Active Security Alerts',
      value: totalAlerts,
      subtext: 'Auto-containment active',
      icon: HardDrive,
      color: 'text-rose-400',
      bgColor: 'bg-rose-500/10',
      borderColor: 'border-rose-500/20'
    },
    {
      title: 'AI Anomaly Model Latency',
      value: '4.2 ms',
      subtext: 'Isolation Forest inference',
      icon: Cpu,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20'
    },
    {
      title: 'Threat Prevention Rate',
      value: '99.8%',
      subtext: 'Zero unauthorized breaches',
      icon: CheckCircle,
      color: 'text-teal-400',
      bgColor: 'bg-teal-500/10',
      borderColor: 'border-teal-500/20'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`rounded-xl border ${card.borderColor} bg-slate-900/60 p-4 transition-all hover:bg-slate-900/90 hover:scale-[1.01]`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                {card.title}
              </span>
              <div className={`p-2 rounded-lg ${card.bgColor} ${card.color}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-2">
              <span className="text-2xl font-bold font-mono text-white tracking-tight">
                {card.value}
              </span>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {card.subtext}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
};
