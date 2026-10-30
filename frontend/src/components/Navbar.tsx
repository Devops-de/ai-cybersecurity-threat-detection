import React from 'react';
import { Shield, Zap, AlertTriangle, Radio, Activity, Terminal } from 'lucide-react';
import { NetworkStats } from '../types';

interface NavbarProps {
  stats: NetworkStats | null;
  onSimulateAttack: (type: string | null) => void;
  activeSimulation: string | null;
}

export const Navbar: React.FC<NavbarProps> = ({
  stats,
  onSimulateAttack,
  activeSimulation
}) => {
  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#0b0f19]/90 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Brand */}
      <div className="flex items-center space-x-3">
        <div className="relative">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5" />
          </div>
          <span className="absolute -top-1 -right-1 flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
          </span>
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-bold text-lg tracking-wide text-white font-mono">
              CyberSentinel <span className="text-cyan-400">AI</span>
            </h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              v2.0 SOC
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans">
            AI Automated Threat Detection & Incident Response Platform
          </p>
        </div>
      </div>

      {/* Attack Simulation Quick Controls */}
      <div className="hidden lg:flex items-center space-x-2 bg-slate-900/90 border border-slate-800 rounded-lg p-1.5 shadow-inner">
        <div className="flex items-center space-x-1.5 px-2 text-xs font-mono text-slate-400 border-r border-slate-800">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>Attack Simulation:</span>
        </div>

        <button
          onClick={() => onSimulateAttack(null)}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
            !activeSimulation
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
              : 'text-slate-400 hover:text-white hover:bg-slate-800'
          }`}
        >
          Normal Baseline
        </button>

        <button
          onClick={() => onSimulateAttack('DDOS_SYN_FLOOD')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
            activeSimulation === 'DDOS_SYN_FLOOD'
              ? 'bg-red-500/20 text-red-300 border border-red-500/50 shadow-sm'
              : 'text-slate-400 hover:text-red-400 hover:bg-slate-800'
          }`}
        >
          ⚡ DDoS Flood
        </button>

        <button
          onClick={() => onSimulateAttack('PORT_SCAN')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
            activeSimulation === 'PORT_SCAN'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 shadow-sm'
              : 'text-slate-400 hover:text-amber-400 hover:bg-slate-800'
          }`}
        >
          🔍 Port Scan
        </button>

        <button
          onClick={() => onSimulateAttack('DATA_EXFILTRATION')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
            activeSimulation === 'DATA_EXFILTRATION'
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-sm'
              : 'text-slate-400 hover:text-purple-400 hover:bg-slate-800'
          }`}
        >
          📤 Exfiltration
        </button>

        <button
          onClick={() => onSimulateAttack('C2_BEACON')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-all ${
            activeSimulation === 'C2_BEACON'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50 shadow-sm'
              : 'text-slate-400 hover:text-rose-400 hover:bg-slate-800'
          }`}
        >
          📡 C2 Beacon
        </button>
      </div>

      {/* Real-time Status Badges */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
          <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span className="text-slate-400">Stream:</span>
          <span className="text-emerald-400 font-semibold">LIVE</span>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
          <Radio className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-slate-400">Bandwidth:</span>
          <span className="text-cyan-400 font-bold">
            {stats ? `${stats.current_bandwidth_mbps} Mbps` : '64.2 Mbps'}
          </span>
        </div>
      </div>
    </header>
  );
};
