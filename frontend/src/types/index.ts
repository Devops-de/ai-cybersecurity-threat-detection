export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN' | 'SUSPICIOUS';

export interface NetworkFlow {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  flow_duration_ms: number;
  syn_ratio: number;
  payload_entropy: number;
  flow_label: string;
  is_anomaly: boolean;
  anomaly_score: number;
  severity: SeverityLevel;
  top_reasons: string[];
  features?: Record<string, number>;
}

export interface NetworkStats {
  total_packets: number;
  total_bytes_mb: number;
  total_anomalies: number;
  current_bandwidth_mbps: number;
  anomaly_rate_percent: number;
  active_simulation: string | null;
}

export interface PhishingIndicator {
  detected_urgency_triggers: string[];
  credential_harvesting_cues: string[];
  sender_flags: string[];
  urls_scanned: Array<{
    url: string;
    risk_score: number;
    reasons: string[];
  }>;
}

export interface PhishingAnalysisResult {
  is_phishing: boolean;
  phishing_score: number;
  threat_level: SeverityLevel;
  ml_confidence: number;
  indicators: PhishingIndicator;
  soc_recommendations: string[];
}

export interface MitreTactic {
  id: string;
  name: string;
  tactic: string;
}

export interface MalwareClassificationResult {
  process_name: string;
  pid: number;
  is_malicious: boolean;
  threat_family: string;
  confidence: number;
  severity: SeverityLevel;
  detected_behaviors: string[];
  mitre_attack_mappings: MitreTactic[];
  containment_playbook: string[];
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  category: 'NETWORK' | 'PHISHING' | 'MALWARE' | 'SYSTEM';
  severity: SeverityLevel;
  title: string;
  source: string;
  target: string;
  details: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  mitigation_action: string;
}

export interface ThreatIntelligenceItem {
  ip: string;
  country: string;
  city: string;
  asn: string;
  reputation_score: number;
  category: string;
  associated_threat_actor: string;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: SeverityLevel;
  executive_summary: string;
  mitre_kill_chain: string;
  timeline: Array<{ time: string; event: string }>;
  indicators_of_compromise: Array<{ type: string; value: string; reputation: string }>;
  containment_playbook: string[];
  remediation_scripts: {
    linux_iptables: string;
    windows_powershell: string;
  };
}
