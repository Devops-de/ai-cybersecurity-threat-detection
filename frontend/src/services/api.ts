import {
  NetworkStats,
  NetworkFlow,
  PhishingAnalysisResult,
  MalwareClassificationResult,
  SecurityAlert,
  ThreatIntelligenceItem,
  IncidentSummary,
  AttackSimulationResponse,
  ContainmentResponse,
  HealthStatus,
} from '../types';

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const res = await fetch(url, { ...options, headers });
    if (!res.ok) {
      let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const errorJson = await res.json();
        if (errorJson.detail) {
          errorDetail = errorJson.detail;
        }
      } catch {
        // Fallback to generic message
      }
      throw new ApiError(errorDetail, res.status);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      err instanceof Error ? err.message : 'Network communication error',
      0
    );
  }
}

export const api = {
  // System Health
  async getHealth(): Promise<HealthStatus> {
    return request<HealthStatus>('/health');
  },

  // Network Traffic
  async getRecentTraffic(): Promise<{ flows: NetworkFlow[]; stats: NetworkStats }> {
    return request<{ flows: NetworkFlow[]; stats: NetworkStats }>('/traffic/recent');
  },

  async getTrafficStats(): Promise<NetworkStats> {
    return request<NetworkStats>('/traffic/stats');
  },

  async simulateAttack(attackType: string | null): Promise<AttackSimulationResponse> {
    return request<AttackSimulationResponse>('/traffic/simulate-attack', {
      method: 'POST',
      body: JSON.stringify({ attack_type: attackType }),
    });
  },

  // Phishing Detection
  async analyzeEmail(payload: {
    sender: string;
    subject: string;
    body: string;
    headers?: Record<string, string>;
  }): Promise<PhishingAnalysisResult> {
    return request<PhishingAnalysisResult>('/phishing/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
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
    return request<MalwareClassificationResult>('/malware/classify', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Incident Summaries & SOC Copilot
  async getIncidentSummary(payload: {
    incident_id?: string;
    type: string;
    severity: string;
    source_ip: string;
    target_ip: string;
  }): Promise<IncidentSummary> {
    return request<IncidentSummary>('/incidents/summary', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async sendCopilotMessage(message: string): Promise<{ reply: string }> {
    return request<{ reply: string }>('/incidents/copilot', {
      method: 'POST',
      body: JSON.stringify({ message }),
    });
  },

  // Threat Intel
  async getThreatFeed(): Promise<{ global_threats: ThreatIntelligenceItem[]; active_indicators: number }> {
    return request<{ global_threats: ThreatIntelligenceItem[]; active_indicators: number }>('/threat-intel/feed');
  },

  async lookupIp(ip: string): Promise<ThreatIntelligenceItem> {
    return request<ThreatIntelligenceItem>(`/threat-intel/lookup/${encodeURIComponent(ip)}`);
  },

  // Alerts & Containment
  async getAlerts(): Promise<{ alerts: SecurityAlert[]; total: number }> {
    return request<{ alerts: SecurityAlert[]; total: number }>('/alerts');
  },

  async containAlert(alertId: string, actionType: string = 'ISOLATE_HOST'): Promise<ContainmentResponse> {
    return request<ContainmentResponse>('/alerts/contain', {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId, action_type: actionType }),
    });
  },
};
