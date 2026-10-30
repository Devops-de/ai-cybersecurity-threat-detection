from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., example="security-update@micros0ft.xyz")
    subject: str = Field(..., example="Action Required: Microsoft 365 Account Suspension")
    body: str = Field(..., example="Your password expired. Click here to verify credentials immediately: http://192.168.1.1/login.php")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)

class MalwareAnalysisRequest(BaseModel):
    process_name: str = Field(..., example="svchost_update.exe")
    pid: int = Field(default=4821, example=4821)
    api_calls: List[str] = Field(default_factory=list, example=["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"])
    file_events: List[str] = Field(default_factory=list, example=["vssadmin delete shadows /all /quiet", "finance_2026.docx.locked"])
    reg_events: List[str] = Field(default_factory=list, example=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"])
    net_events: List[str] = Field(default_factory=list, example=["Beacon POST to 198.51.100.42:443 (jitter 15s)"])

class IncidentSummaryRequest(BaseModel):
    incident_id: Optional[str] = "INC-CURRENT"
    type: str = Field(default="RANSOMWARE_OUTBREAK")
    severity: str = Field(default="CRITICAL")
    source_ip: str = Field(default="192.168.1.105")
    target_ip: str = Field(default="10.0.1.15")

class AiChatRequest(BaseModel):
    message: str = Field(..., example="Explain the LockBit ransomware incident and generate an iptables rule to block the attacker IP.")

class ContainmentRequest(BaseModel):
    alert_id: str
    action_type: str = "BLOCK_IP_FIREWALL"
