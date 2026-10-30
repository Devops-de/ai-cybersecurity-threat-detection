import datetime
import uuid
from typing import Dict, Any, List

class AlertEngine:
    """
    Automated Security Alert and Incident Containment Engine.
    Evaluates streaming telemetry against policy thresholds, generates alerts,
    and executes automated security containment actions (e.g. IP block, host quarantine).
    """
    def __init__(self):
        self.alerts: List[Dict[str, Any]] = []
        self.auto_mitigation_enabled = True
        self.mitigation_log: List[Dict[str, Any]] = []
        self._seed_initial_alerts()

    def _seed_initial_alerts(self):
        # Prepopulate with sample alerts for initial dashboard display
        now = datetime.datetime.utcnow()
        self.alerts.extend([
            {
                "id": "ALT-9041",
                "timestamp": (now - datetime.timedelta(minutes=14)).isoformat() + "Z",
                "category": "NETWORK",
                "severity": "CRITICAL",
                "title": "Volumetric SYN Flood Against Web Gateway",
                "source": "185.220.101.5",
                "target": "10.0.1.15:443",
                "details": "ML Anomaly Score: 0.94. Packet rate exceeded 15,000 pps with 98% SYN ratio.",
                "status": "CONTAINED",
                "mitigation_action": "Automated Firewall Block (iptables drop rule applied)"
            },
            {
                "id": "ALT-9042",
                "timestamp": (now - datetime.timedelta(minutes=32)).isoformat() + "Z",
                "category": "PHISHING",
                "severity": "HIGH",
                "title": "Credential Harvester Impersonating Microsoft 365",
                "source": "admin@micros0ft-support.xyz",
                "target": "cfo@enterprise.org",
                "details": "NLP Score: 0.91. Urgency cues and fraudulent authentication link detected.",
                "status": "CONTAINED",
                "mitigation_action": "Email Quarantined in SEG & Domain Blocked"
            },
            {
                "id": "ALT-9043",
                "timestamp": (now - datetime.timedelta(hours=2)).isoformat() + "Z",
                "category": "MALWARE",
                "severity": "CRITICAL",
                "title": "LockBit Behavioral Heuristics Triggered on Workstation-45",
                "source": "192.168.1.45 (PID 4892 - update_svc.exe)",
                "target": "Local Filesystem & Volume Shadow Copies",
                "details": "MITRE T1490 (Inhibit Recovery) & T1486 (Data Encrypted) detected in process trace.",
                "status": "INVESTIGATING",
                "mitigation_action": "Pending Analyst Approval (Host Isolation Recommended)"
            }
        ])

    def evaluate_network_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Triggered when network anomaly detector flags a flow."""
        if flow.get("anomaly_score", 0.0) >= 0.70:
            alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"
            severity = flow.get("severity", "HIGH")
            src_ip = flow.get("src_ip", "Unknown")
            dst_ip = flow.get("dst_ip", "Unknown")
            dst_port = flow.get("dst_port", 0)

            action = "Alert Dispatched to SOC SIEM"
            if self.auto_mitigation_enabled and severity == "CRITICAL":
                action = f"Auto-Mitigation: Border Firewall dropped traffic from {src_ip}"
                self.mitigation_log.append({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "action": f"Firewall Rule Added: Block {src_ip}",
                    "reason": f"Anomaly score {flow.get('anomaly_score')} triggered auto-containment"
                })

            alert = {
                "id": alert_id,
                "timestamp": flow.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z"),
                "category": "NETWORK",
                "severity": severity,
                "title": f"Network Anomaly ({flow.get('flow_label', 'Suspicious Flow')})",
                "source": src_ip,
                "target": f"{dst_ip}:{dst_port}",
                "details": f"Anomaly Score: {flow.get('anomaly_score')}. Reasons: {', '.join(flow.get('top_reasons', []))}",
                "status": "CONTAINED" if "Auto-Mitigation" in action else "OPEN",
                "mitigation_action": action
            }
            self.alerts.insert(0, alert)
            return alert
        return None

    def trigger_containment(self, alert_id: str, action_type: str = "ISOLATE_HOST") -> Dict[str, Any]:
        """Manual or automated containment executor."""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["status"] = "CONTAINED"
                alert["mitigation_action"] = f"SOC Analyst Executed: {action_type} on {alert['source']}"
                self.mitigation_log.append({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "alert_id": alert_id,
                    "action": action_type,
                    "target": alert["source"]
                })
                return {"success": True, "alert": alert}
        return {"success": False, "error": "Alert not found"}

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        return self.alerts
