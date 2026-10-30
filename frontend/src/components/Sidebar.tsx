import React from 'react';
import {
  LayoutDashboard,
  Activity,
  Mail,
  Bug,
  FileText,
  Globe,
  BellRing,
  Cpu,
  Bot
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  alertCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  alertCount
}) => {
  const navItems = [
    { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'traffic', label: 'Live Traffic & ML Anomalies', icon: Activity },
    { id: 'phishing', label: 'AI Phishing Scanner', icon: Mail },
    { id: 'malware', label: 'Malware Sandbox & MITRE', icon: Bug },
    { id: 'incidents', label: 'AI Incident Summaries & Copilot', icon: Bot },
    { id: 'intel', label: 'Threat Intelligence', icon: Globe },
    { id: 'alerts', label: 'Alert Center & Containment', icon: BellRing, badge: alertCount },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#090d16] p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-6">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold px-3">
            Core Modules
          </span>
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-red-500/20 text-red-400 border border-red-500/40">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* AI & ML Engine Status Card */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3 space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="flex items-center space-x-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>AI Engine Fleet</span>
            </span>
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          </div>

          <div className="space-y-1.5 text-[11px] font-mono">
            <div className="flex justify-between text-slate-300">
              <span className="text-slate-500">Anomaly Detector:</span>
              <span className="text-cyan-400">Isolation Forest</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span className="text-slate-500">NLP Classifier:</span>
              <span className="text-cyan-400">TF-IDF + LogReg</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span className="text-slate-500">Behavioral Engine:</span>
              <span className="text-cyan-400">MITRE Matrix</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span className="text-slate-500">Incident Synthesizer:</span>
              <span className="text-cyan-400">GenAI SOC</span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-3 rounded-lg border border-slate-800/70 bg-slate-950/40 text-[11px] text-slate-500 font-mono">
        <p>Protected by CyberSentinel</p>
        <p className="text-[10px] text-slate-600 mt-0.5">Enterprise Edition (Active)</p>
      </div>
    </aside>
  );
};
