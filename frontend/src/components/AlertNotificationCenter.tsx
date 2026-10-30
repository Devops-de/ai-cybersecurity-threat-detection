import React, { useState } from 'react';
import { 
  BellRing, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  CheckCircle, 
  Filter, 
  Zap,
  Server
} from 'lucide-react';
import { SecurityAlert, SeverityLevel } from '../types';
import { api } from '../services/api';
import { getSeverityBadgeClass } from '../utils/helpers';

interface AlertNotificationCenterProps {
  alerts: SecurityAlert[];
  onRefreshAlerts: () => void;
}

export const AlertNotificationCenter: React.FC<AlertNotificationCenterProps> = ({
  alerts,
  onRefreshAlerts
}) => {
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);

  const filteredAlerts = alerts.filter(a => {
    if (categoryFilter === 'ALL') return true;
    return a.category === categoryFilter;
  });

  const handleContain = async (alertId: string, actionType: string) => {
    setActionLoadingId(alertId);
    try {
      await api.containAlert(alertId, actionType);
      onRefreshAlerts();
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoadingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <BellRing className="w-5 h-5 text-rose-400" />
            <h2 className="text-lg font-bold text-white font-mono">
              Automated Security Alerts & Incident Containment Center
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time policy threshold evaluator with automated mitigation rules (firewall blocking, host network isolation, email quarantining).
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">Category:</span>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            <option value="NETWORK">Network Anomaly</option>
            <option value="PHISHING">Phishing Detection</option>
            <option value="MALWARE">Malware Behavior</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-[#0a0f1d] flex items-center justify-between">
          <h3 className="text-sm font-bold text-white font-mono flex items-center space-x-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>Active Security Incident Feed</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">
            {filteredAlerts.length} Total Alerts
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Alert ID</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Incident Title</th>
                <th className="py-3 px-4">Source / Target</th>
                <th className="py-3 px-4">Containment Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No active alerts matching the selected category.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isContained = alert.status === 'CONTAINED';
                  return (
                    <tr key={alert.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-bold text-cyan-400">
                        {alert.id}
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] uppercase font-semibold ${getSeverityBadgeClass(
                            alert.severity
                          )}`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        {alert.category}
                      </td>
                      <td className="py-3.5 px-4">
                        <p className="font-semibold text-white">{alert.title}</p>
                        <p className="text-[11px] text-slate-400 truncate max-w-xs">{alert.details}</p>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        <p><span className="text-slate-500">Src:</span> {alert.source}</p>
                        <p><span className="text-slate-500">Tgt:</span> {alert.target}</p>
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            isContained
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : 'bg-red-500/15 text-red-400 border border-red-500/30'
                          }`}
                        >
                          {alert.status}
                        </span>
                        <p className="text-[10px] text-slate-500 mt-0.5">{alert.mitigation_action}</p>
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        {!isContained ? (
                          <button
                            onClick={() => handleContain(alert.id, 'AUTO_CONTAINMENT_EXECUTE')}
                            disabled={actionLoadingId === alert.id}
                            className="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-all shadow-md shadow-red-500/20"
                          >
                            {actionLoadingId === alert.id ? 'Containing...' : 'Execute Containment'}
                          </button>
                        ) : (
                          <span className="text-emerald-400 text-xs flex items-center justify-end space-x-1">
                            <CheckCircle className="w-3.5 h-3.5" />
                            <span>Contained</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
