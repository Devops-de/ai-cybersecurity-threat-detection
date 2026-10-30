import React, { useState } from 'react';
import { 
  Activity, 
  AlertTriangle, 
  Radio, 
  Terminal, 
  Eye, 
  ShieldAlert, 
  CheckCircle,
  Filter,
  ArrowUpRight
} from 'lucide-react';
import { NetworkFlow, SeverityLevel } from '../types';
import { getSeverityBadgeClass, formatBytes } from '../utils/helpers';

interface LiveTrafficMonitorProps {
  flows: NetworkFlow[];
  onSimulateAttack: (type: string | null) => void;
  activeSimulation: string | null;
  onInspectFlow: (flow: NetworkFlow) => void;
}

export const LiveTrafficMonitor: React.FC<LiveTrafficMonitorProps> = ({
  flows,
  onSimulateAttack,
  activeSimulation,
  onInspectFlow
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [selectedFlow, setSelectedFlow] = useState<NetworkFlow | null>(null);

  const filteredFlows = flows.filter(flow => {
    if (filterSeverity === 'ALL') return true;
    if (filterSeverity === 'ANOMALIES_ONLY') return flow.is_anomaly;
    return flow.severity === filterSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Simulation Controls Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              Live Attack Vector Injection Testbed
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Inject realistic adversary traffic into the real-time stream to test the ML Isolation Forest anomaly detection engine.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onSimulateAttack(null)}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono font-medium transition-all ${
              !activeSimulation
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            Baseline Normal
          </button>
          <button
            onClick={() => onSimulateAttack('DDOS_SYN_FLOOD')}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono font-medium transition-all ${
              activeSimulation === 'DDOS_SYN_FLOOD'
                ? 'bg-red-500/20 text-red-300 border border-red-500/60 shadow-lg shadow-red-500/20'
                : 'bg-slate-800 text-slate-400 hover:text-red-400'
            }`}
          >
            ⚡ Volumetric DDoS
          </button>
          <button
            onClick={() => onSimulateAttack('PORT_SCAN')}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono font-medium transition-all ${
              activeSimulation === 'PORT_SCAN'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/60 shadow-lg shadow-amber-500/20'
                : 'bg-slate-800 text-slate-400 hover:text-amber-400'
            }`}
          >
            🔍 Port Scan
          </button>
          <button
            onClick={() => onSimulateAttack('DATA_EXFILTRATION')}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono font-medium transition-all ${
              activeSimulation === 'DATA_EXFILTRATION'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/60'
                : 'bg-slate-800 text-slate-400 hover:text-purple-400'
            }`}
          >
            📤 Exfiltration
          </button>
          <button
            onClick={() => onSimulateAttack('C2_BEACON')}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono font-medium transition-all ${
              activeSimulation === 'C2_BEACON'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/60'
                : 'bg-slate-800 text-slate-400 hover:text-rose-400'
            }`}
          >
            📡 C2 Beacon
          </button>
        </div>
      </div>

      {/* Real-time Flow Stream Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        {/* Table Header Controls */}
        <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-[#0a0f1d]">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h3 className="text-sm font-bold text-white font-mono">
              Live Network Packet Flow Ingestion
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {flows.length} flows buffered
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400 font-mono">Filter:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Flows</option>
              <option value="ANOMALIES_ONLY">Anomalies Only</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Severity</option>
              <option value="LOW">Normal Baseline</option>
            </select>
          </div>
        </div>

        {/* Packet Flow Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Flow ID</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Target IP:Port</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Volume</th>
                <th className="py-3 px-4">Anomaly Score</th>
                <th className="py-3 px-4">Threat State</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No flows matching the current filter.
                  </td>
                </tr>
              ) : (
                filteredFlows.slice(0, 18).map((flow) => {
                  const isCritical = flow.anomaly_score >= 0.85;
                  const isHigh = flow.anomaly_score >= 0.65;
                  return (
                    <tr
                      key={flow.flow_id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        flow.is_anomaly ? 'bg-red-500/5' : ''
                      }`}
                    >
                      <td className="py-3 px-4 text-slate-400">
                        {flow.timestamp.split('T')[1]?.split('.')[0] || flow.timestamp}
                      </td>
                      <td className="py-3 px-4 font-semibold text-cyan-400">
                        {flow.flow_id}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-300">
                        {flow.src_ip}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {flow.dst_ip}:{flow.dst_port}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                          {flow.protocol}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {flow.packet_count} pkts ({formatBytes(flow.byte_count)})
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-2">
                          <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                isCritical
                                  ? 'bg-red-500'
                                  : isHigh
                                  ? 'bg-amber-400'
                                  : 'bg-emerald-400'
                              }`}
                              style={{ width: `${Math.min(flow.anomaly_score * 100, 100)}%` }}
                            />
                          </div>
                          <span
                            className={`text-[11px] font-bold ${
                              isCritical
                                ? 'text-red-400'
                                : isHigh
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {(flow.anomaly_score * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] uppercase font-semibold ${getSeverityBadgeClass(
                            flow.severity
                          )}`}
                        >
                          {flow.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => {
                            setSelectedFlow(flow);
                            onInspectFlow(flow);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 hover:text-cyan-300 text-slate-400 text-xs transition-colors"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Flow Inspection Drawer / Card */}
      {selectedFlow && (
        <div className="rounded-xl border border-cyan-500/30 bg-slate-900/90 p-5 space-y-4 shadow-2xl relative">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-white font-mono text-sm">
                  Deep Flow Inspection: {selectedFlow.flow_id} ({selectedFlow.flow_label})
                </h4>
                <p className="text-xs text-slate-400">
                  {selectedFlow.src_ip} ➔ {selectedFlow.dst_ip}:{selectedFlow.dst_port} via {selectedFlow.protocol}
                </p>
              </div>
            </div>
            <button
              onClick={() => setSelectedFlow(null)}
              className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800"
            >
              ✕ Close
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500">ML Anomaly Score:</span>
              <p className="text-base font-bold text-cyan-400 mt-1">
                {(selectedFlow.anomaly_score * 100).toFixed(1)}%
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500">SYN Packet Ratio:</span>
              <p className="text-base font-bold text-slate-200 mt-1">
                {(selectedFlow.syn_ratio * 100).toFixed(1)}%
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500">Payload Entropy:</span>
              <p className="text-base font-bold text-purple-400 mt-1">
                {selectedFlow.payload_entropy.toFixed(2)} / 8.0
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-500">Duration / Throughput:</span>
              <p className="text-base font-bold text-slate-200 mt-1">
                {selectedFlow.flow_duration_ms} ms
              </p>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1.5 text-xs font-mono">
            <span className="text-slate-400 font-bold uppercase text-[10px] tracking-wider">
              Diagnostic Finding:
            </span>
            <ul className="list-disc list-inside space-y-1 text-slate-300">
              {selectedFlow.top_reasons.map((r, i) => (
                <li key={i} className="text-cyan-300">{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
