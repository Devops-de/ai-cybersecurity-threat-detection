import { 
  NetworkStats, 
  NetworkFlow, 
  PhishingAnalysisResult, 
  MalwareClassificationResult, 
  SecurityAlert, 
  ThreatIntelligenceItem, 
  IncidentSummary 
} from '../types';

const API_BASE = 'http://localhost:8000/api';

export const api = {
  // Network Traffic
  async getRecentTraffic(): Promise<{ flows: NetworkFlow[]; stats: NetworkStats }> {
    const res = await fetch(`${API_BASE}/traffic/recent`);
    return res.json();
  },

  async getTrafficStats(): Promise<NetworkStats> {
    const res = await fetch(`${API_BASE}/traffic/stats`);
    return res.json();
  },

  async simulateAttack(attackType: string | null): Promise<any> {
    const res = await fetch(`${API_BASE}/traffic/simulate-attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType })
    });
    return res.json();
  },

  // Phishing Detection
  async analyzeEmail(payload: {
    sender: string;
    subject: string;
    body: string;
    headers?: Record<string, string>;
  }): Promise<PhishingAnalysisResult> {
    const res = await fetch(`${API_BASE}/phishing/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  // Malware Behavior
  async classifyMalware(payload: {
    process_name: string;
    pid: number;
    api_calls: string[];
    file_events: string[];
    reg_events: string[];
    net_events: string[];
  }): Promise<MalwareClassificationResult> {
    const res = await fetch(`${API_BASE}/malware/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  // Incident Summaries & SOC Copilot
  async getIncidentSummary(payload: {
    incident_id?: string;
    type: string;
    severity: string;
    source_ip: string;
    target_ip: string;
  }): Promise<IncidentSummary> {
    const res = await fetch(`${API_BASE}/incidents/summary`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async sendCopilotMessage(message: string): Promise<{ reply: string }> {
    const res = await fetch(`${API_BASE}/incidents/copilot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    return res.json();
  },

  // Threat Intel
  async getThreatFeed(): Promise<{ global_threats: ThreatIntelligenceItem[]; active_indicators: number }> {
    const res = await fetch(`${API_BASE}/threat-intel/feed`);
    return res.json();
  },

  // Alerts
  async getAlerts(): Promise<{ alerts: SecurityAlert[]; total: number }> {
    const res = await fetch(`${API_BASE}/alerts`);
    return res.json();
  },

  async containAlert(alertId: string, actionType: string = 'ISOLATE_HOST'): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, action_type: actionType })
    });
    return res.json();
  }
};
