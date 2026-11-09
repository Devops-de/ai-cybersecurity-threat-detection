from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================

class EmailAnalysisRequest(BaseModel):
    """Payload for submitting an email for NLP phishing and urgency analysis."""
    sender: str = Field(
        ...,
        min_length=3,
        description="Sender email address with domain",
    )
    subject: str = Field(
        ...,
        min_length=1,
        description="Subject line of the email",
    )
    body: str = Field(
        ...,
        min_length=1,
        description="Raw or plain text email body content",
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional email headers (e.g. spf, dmarc, dkim)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sender": "security-update@micros0ft.xyz",
                "subject": "Action Required: Microsoft 365 Account Suspension",
                "body": "Your password expired. Click here to verify credentials immediately: http://192.168.1.1/login.php",
                "headers": {"spf": "fail", "dmarc": "fail"},
            }
        }
    )


class MalwareAnalysisRequest(BaseModel):
    """Payload for behavioral process sandbox classification."""
    process_name: str = Field(
        ...,
        min_length=1,
        description="Binary executable name (e.g. updater.exe)",
    )
    pid: int = Field(
        default=4821,
        ge=0,
        description="Operating system Process Identifier",
    )
    api_calls: List[str] = Field(
        default_factory=list,
        description="List of observed Windows API calls or system calls",
    )
    file_events: List[str] = Field(
        default_factory=list,
        description="File modifications, creations, or deletions",
    )
    reg_events: List[str] = Field(
        default_factory=list,
        description="Registry key creations or autorun modifications",
    )
    net_events: List[str] = Field(
        default_factory=list,
        description="Network socket events, outbound connections, or DNS queries",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "process_name": "svchost_update.exe",
                "pid": 4821,
                "api_calls": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
                "file_events": ["vssadmin delete shadows /all /quiet", "finance_2026.docx.locked"],
                "reg_events": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"],
                "net_events": ["Beacon POST to 198.51.100.42:443 (jitter 15s)"],
            }
        }
    )


class IncidentSummaryRequest(BaseModel):
    """Request payload to generate GenAI executive incident briefing."""
    incident_id: Optional[str] = Field(default="INC-CURRENT")
    type: str = Field(default="RANSOMWARE_OUTBREAK")
    severity: str = Field(default="CRITICAL")
    source_ip: str = Field(default="192.168.1.105")
    target_ip: str = Field(default="10.0.1.15")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "incident_id": "INC-9041",
                "type": "RANSOMWARE_OUTBREAK",
                "severity": "CRITICAL",
                "source_ip": "192.168.1.105",
                "target_ip": "10.0.1.15",
            }
        }
    )


class AiChatRequest(BaseModel):
    """Interactive SOC Copilot prompt."""
    message: str = Field(
        ...,
        min_length=1,
        description="Natural language question or command for SOC Copilot",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Explain the LockBit ransomware incident and generate an iptables rule to block the attacker IP."
            }
        }
    )


class ContainmentRequest(BaseModel):
    """Payload to trigger containment actions on an active alert."""
    alert_id: str = Field(..., min_length=1)
    action_type: str = Field(default="BLOCK_IP_FIREWALL")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "ALT-9041",
                "action_type": "BLOCK_IP_FIREWALL",
            }
        }
    )


class AttackSimulationRequest(BaseModel):
    """Payload to trigger an adversary traffic vector simulation."""
    attack_type: Optional[str] = Field(
        default=None,
        description="One of: DDOS_SYN_FLOOD, PORT_SCAN, DATA_EXFILTRATION, C2_BEACON or null for Baseline",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"attack_type": "DDOS_SYN_FLOOD"}
        }
    )


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================

class NetworkFlowResponse(BaseModel):
    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    flow_duration_ms: float
    syn_ratio: float
    payload_entropy: float
    flow_label: str
    is_anomaly: bool
    anomaly_score: float
    severity: str
    top_reasons: List[str]
    features: Optional[Dict[str, float]] = None


class NetworkStatsResponse(BaseModel):
    total_packets: int
    total_bytes_mb: float
    total_anomalies: int
    current_bandwidth_mbps: float
    anomaly_rate_percent: float
    active_simulation: Optional[str] = None


class RecentTrafficResponse(BaseModel):
    flows: List[NetworkFlowResponse]
    stats: NetworkStatsResponse


class AttackSimulationResponse(BaseModel):
    status: str
    current_simulation: Optional[str]
    message: str


class UrlFinding(BaseModel):
    url: str
    risk_score: float
    reasons: List[str]


class PhishingIndicators(BaseModel):
    detected_urgency_triggers: List[str]
    credential_harvesting_cues: List[str]
    sender_flags: List[str]
    urls_scanned: List[UrlFinding]


class EmailAnalysisResponse(BaseModel):
    is_phishing: bool
    phishing_score: float
    threat_level: str
    ml_confidence: float
    indicators: PhishingIndicators
    soc_recommendations: List[str]


class MitreTacticResponse(BaseModel):
    id: str
    name: str
    tactic: str


class MalwareAnalysisResponse(BaseModel):
    process_name: str
    pid: int
    is_malicious: bool
    threat_family: str
    confidence: float
    severity: str
    detected_behaviors: List[str]
    mitre_attack_mappings: List[MitreTacticResponse]
    containment_playbook: List[str]


class TimelineEvent(BaseModel):
    time: str
    event: str


class IocItem(BaseModel):
    type: str
    value: str
    reputation: str


class RemediationScripts(BaseModel):
    linux_iptables: str
    windows_powershell: str


class IncidentSummaryResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    executive_summary: str
    mitre_kill_chain: str
    timeline: List[TimelineEvent]
    indicators_of_compromise: List[IocItem]
    containment_playbook: List[str]
    remediation_scripts: RemediationScripts


class AiChatResponse(BaseModel):
    reply: str


class AlertResponse(BaseModel):
    id: str
    timestamp: str
    category: str
    severity: str
    title: str
    source: str
    target: str
    details: str
    status: str
    mitigation_action: str


class AlertsListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int


class ContainmentResponse(BaseModel):
    success: bool
    alert: Optional[AlertResponse] = None
    error: Optional[str] = None


class ThreatIntelItemResponse(BaseModel):
    ip: str
    country: str
    city: str
    asn: str
    reputation_score: int
    category: str
    associated_threat_actor: str


class ThreatFeedResponse(BaseModel):
    global_threats: List[ThreatIntelItemResponse]
    active_indicators: int


class HealthResponse(BaseModel):
    status: str
    version: str
    models: Dict[str, str]


class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
