import React, { useState, useEffect } from 'react';
import { Globe, ShieldAlert, Search, MapPin, Server, AlertTriangle, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import { ThreatIntelligenceItem } from '../types';

export const ThreatIntelligenceMap: React.FC = () => {
  const [threats, setThreats] = useState<ThreatIntelligenceItem[]>([]);
  const [searchIp, setSearchIp] = useState('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    api.getThreatFeed().then(res => setThreats(res.global_threats || []));
  }, []);

  const handleLookup = async () => {
    if (!searchIp.trim()) return;
    setIsLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/threat-intel/lookup/${searchIp}`);
      const data = await res.json();
      setLookupResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white font-mono">
              Global Threat Intelligence & Adversary Attribution
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated IOC feeds, GeoIP threat origin tracking, ASN classification, and known Advanced Persistent Threat (APT) actor profiles.
          </p>
        </div>

        {/* IP Search Bar */}
        <div className="flex items-center space-x-2 w-full md:w-auto">
          <input
            type="text"
            placeholder="Lookup IP (e.g. 185.220.101.5)..."
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-64"
          />
          <button
            onClick={handleLookup}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition-colors flex items-center space-x-1"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Search</span>
          </button>
        </div>
      </div>

      {/* Lookup Result Modal/Card */}
      {lookupResult && (
        <div className="p-4 rounded-xl border border-cyan-500/40 bg-slate-900/90 shadow-xl space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-bold text-white flex items-center space-x-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>IP Intelligence Report: {lookupResult.ip}</span>
            </span>
            <button
              onClick={() => setLookupResult(null)}
              className="text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-1">
            <div>
              <span className="text-slate-500">Location:</span>
              <p className="text-slate-200">{lookupResult.city}, {lookupResult.country}</p>
            </div>
            <div>
              <span className="text-slate-500">ASN / Provider:</span>
              <p className="text-slate-200">{lookupResult.asn}</p>
            </div>
            <div>
              <span className="text-slate-500">Threat Category:</span>
              <p className="text-amber-400">{lookupResult.category}</p>
            </div>
            <div>
              <span className="text-slate-500">Risk Score:</span>
              <p className="text-red-400 font-bold">{lookupResult.reputation_score} / 100</p>
            </div>
          </div>
        </div>
      )}

      {/* Global Threat Feed Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-[#0a0f1d] flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              High-Risk International Threat Indicators (IOCs)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {threats.length} Active Nodes Tracked
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Threat Origin IP</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Autonomous System (ASN)</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Threat Actor / Campaign</th>
                <th className="py-3 px-4 text-right">Reputation Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {threats.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 px-4 font-bold text-cyan-400">
                    {item.ip}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">
                    <span className="flex items-center space-x-1.5">
                      <MapPin className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.city}, {item.country}</span>
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-400">
                    {item.asn}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px]">
                      {item.category}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-rose-300 font-semibold">
                    {item.associated_threat_actor}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <span className="text-sm font-bold text-red-400">
                      {item.reputation_score} / 100
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
