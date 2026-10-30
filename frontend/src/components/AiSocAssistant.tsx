import React, { useState, useEffect } from 'react';
import { 
  Bot, 
  Send, 
  FileText, 
  Terminal, 
  ShieldAlert, 
  Clock, 
  Copy, 
  Check, 
  Sparkles,
  ChevronRight
} from 'lucide-react';
import { api } from '../services/api';
import { IncidentSummary } from '../types';
import { getSeverityBadgeClass } from '../utils/helpers';

export const AiSocAssistant: React.FC = () => {
  const [selectedIncidentType, setSelectedIncidentType] = useState('RANSOMWARE_OUTBREAK');
  const [incidentSummary, setIncidentSummary] = useState<IncidentSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState(false);

  // Chatbot State
  const [messages, setMessages] = useState<Array<{ sender: 'user' | 'assistant'; text: string; time: string }>>([
    {
      sender: 'assistant',
      text: "👋 Hello SOC Analyst. I am CyberSentinel's AI Copilot. I continuously monitor active incidents, synthesize root causes, and write tactical containment scripts. How can I assist your investigation today?",
      time: 'Just now'
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [copiedScript, setCopiedScript] = useState<string | null>(null);

  const fetchSummary = async (type: string) => {
    setIsLoadingSummary(true);
    try {
      const summary = await api.getIncidentSummary({
        type,
        severity: type === 'RANSOMWARE_OUTBREAK' ? 'CRITICAL' : 'HIGH',
        source_ip: type === 'RANSOMWARE_OUTBREAK' ? '192.168.1.45' : '185.220.101.5',
        target_ip: '10.0.1.15'
      });
      setIncidentSummary(summary);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoadingSummary(false);
    }
  };

  useEffect(() => {
    fetchSummary(selectedIncidentType);
  }, [selectedIncidentType]);

  const handleSendMessage = async (textToSend?: string) => {
    const q = textToSend || inputQuery;
    if (!q.trim()) return;

    const userMsg = { sender: 'user' as const, text: q, time: new Date().toLocaleTimeString() };
    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInputQuery('');
    setIsSending(true);

    try {
      const res = await api.sendCopilotMessage(q);
      const assistantMsg = {
        sender: 'assistant' as const,
        text: res.reply,
        time: new Date().toLocaleTimeString()
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (e) {
      console.error(e);
    } finally {
      setIsSending(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(id);
    setTimeout(() => setCopiedScript(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Bot className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white font-mono">
              AI Incident Summaries & SOC Copilot Assistant
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Generative AI synthesizes multi-stage attack telemetry into executive briefings, MITRE kill-chain timelines, and generates firewall remediation scripts.
          </p>
        </div>

        {/* Incident Type Selector */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-500">Incident Template:</span>
          <select
            value={selectedIncidentType}
            onChange={(e) => setSelectedIncidentType(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="RANSOMWARE_OUTBREAK">LockBit Ransomware Outbreak</option>
            <option value="PHISHING_CREDENTIAL_HARVEST">Phishing Credential Harvest</option>
            <option value="VOLUMETRIC_SYN_FLOOD">Volumetric DDoS SYN Flood</option>
            <option value="C2_BEACONING">Cobalt Strike C2 Beaconing</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: AI Incident Report Briefing */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2 font-mono">
              <FileText className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">
                {incidentSummary ? incidentSummary.title : 'Incident Briefing'}
              </h3>
            </div>
            {incidentSummary && (
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold ${getSeverityBadgeClass(
                  incidentSummary.severity
                )}`}
              >
                {incidentSummary.severity}
              </span>
            )}
          </div>

          {isLoadingSummary || !incidentSummary ? (
            <div className="h-96 flex items-center justify-center text-slate-500 font-mono text-xs">
              <Sparkles className="w-5 h-5 text-cyan-400 animate-spin mr-2" />
              Synthesizing SOC Incident Briefing...
            </div>
          ) : (
            <div className="space-y-4 font-mono text-xs">
              {/* Executive Summary Box */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                  Executive Briefing:
                </span>
                <p className="text-slate-200 text-xs leading-relaxed">
                  {incidentSummary.executive_summary}
                </p>
                <div className="pt-2 flex items-center space-x-2 text-[11px] text-cyan-400">
                  <span className="text-slate-500">MITRE Kill-Chain Stage:</span>
                  <span className="font-semibold">{incidentSummary.mitre_kill_chain}</span>
                </div>
              </div>

              {/* Timeline of events */}
              <div className="space-y-2">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                  Chronological Event Timeline:
                </span>
                <div className="space-y-2 border-l-2 border-cyan-500/30 pl-3 ml-1">
                  {incidentSummary.timeline.map((item, idx) => (
                    <div key={idx} className="space-y-0.5">
                      <span className="text-cyan-400 text-[10px] flex items-center space-x-1">
                        <Clock className="w-3 h-3" />
                        <span>{item.time}</span>
                      </span>
                      <p className="text-slate-300 text-xs">{item.event}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Containment Playbook */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                  Tactical Containment Steps:
                </span>
                <ul className="space-y-1 text-slate-300 text-xs">
                  {incidentSummary.containment_playbook.map((step, idx) => (
                    <li key={idx} className="flex items-start space-x-1.5">
                      <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Runnable Remediation Scripts */}
              <div className="space-y-2">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                  Automated Remediation Scripts:
                </span>

                <div className="space-y-2">
                  <div className="rounded-lg bg-slate-950 border border-slate-800 p-2.5 space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Linux iptables Firewall Rule</span>
                      <button
                        onClick={() => copyToClipboard(incidentSummary.remediation_scripts.linux_iptables, 'iptables')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedScript === 'iptables' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedScript === 'iptables' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="text-[11px] text-emerald-400 font-mono bg-black/40 p-2 rounded overflow-x-auto">
                      {incidentSummary.remediation_scripts.linux_iptables}
                    </pre>
                  </div>

                  <div className="rounded-lg bg-slate-950 border border-slate-800 p-2.5 space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Windows Defender Firewall (PowerShell)</span>
                      <button
                        onClick={() => copyToClipboard(incidentSummary.remediation_scripts.windows_powershell, 'ps')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedScript === 'ps' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedScript === 'ps' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="text-[11px] text-cyan-300 font-mono bg-black/40 p-2 rounded overflow-x-auto">
                      {incidentSummary.remediation_scripts.windows_powershell}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right: Interactive AI SOC Copilot Chat */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col justify-between h-[640px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <div className="flex items-center space-x-2">
                <Bot className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Interactive SOC AI Copilot
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>

            {/* Quick Prompt Pills */}
            <div className="flex flex-wrap gap-1.5 mb-3">
              <button
                onClick={() => handleSendMessage("Generate a firewall rule to block the threat actor IP.")}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono"
              >
                🛡️ Generate Firewall Script
              </button>
              <button
                onClick={() => handleSendMessage("Explain ransomware containment protocol step-by-step.")}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono"
              >
                ☣️ Ransomware Protocol
              </button>
              <button
                onClick={() => handleSendMessage("Give me an operational summary of active alerts.")}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono"
              >
                📊 Active Alerts Summary
              </button>
            </div>
          </div>

          {/* Messages Scroll Area */}
          <div className="flex-1 overflow-y-auto space-y-3 pr-1 text-xs font-mono">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-xl max-w-[92%] ${
                  m.sender === 'user'
                    ? 'ml-auto bg-cyan-600/20 border border-cyan-500/30 text-cyan-200'
                    : 'mr-auto bg-slate-950 border border-slate-800 text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>{m.sender === 'user' ? 'Analyst' : 'CyberSentinel Copilot'}</span>
                  <span>{m.time}</span>
                </div>
                <div className="whitespace-pre-wrap leading-relaxed">{m.text}</div>
              </div>
            ))}
            {isSending && (
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-400 text-xs font-mono flex items-center space-x-2">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                <span>CyberSentinel Copilot analyzing telemetry...</span>
              </div>
            )}
          </div>

          {/* Input Box */}
          <div className="mt-3 pt-3 border-t border-slate-800 flex items-center space-x-2">
            <input
              type="text"
              placeholder="Ask Copilot (e.g. Generate iptables rule, explain attack)..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={isSending || !inputQuery.trim()}
              className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
