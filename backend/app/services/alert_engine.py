import datetime
import threading
import uuid
from typing import Any, Dict, List, Optional
from app.core.config import settings


def _utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AlertEngine:
    """
    Automated Security Alert and Incident Containment Engine.
    Evaluates streaming telemetry against policy thresholds, generates alerts,
    and executes automated security containment actions (e.g. IP block, host quarantine).
    """

    def __init__(self, max_alerts: int = settings.MAX_ALERTS) -> None:
        self.max_alerts = max_alerts
        self.alerts: List[Dict[str, Any]] = []
        self.auto_mitigation_enabled: bool = True
        self.mitigation_log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._seed_initial_alerts()

    def _seed_initial_alerts(self) -> None:
        """Pre-populate with sample alerts for initial dashboard display."""
        now = datetime.datetime.now(datetime.timezone.utc)
        self.alerts.extend([
            {
                "id": "ALT-9041",
                "timestamp": (now - datetime.timedelta(minutes=14)).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
                "timestamp": (now - datetime.timedelta(minutes=32)).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
                "timestamp": (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
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

    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Thread-safely prepends an alert to the collection, enforcing buffer limits."""
        with self._lock:
            self.alerts.insert(0, alert)
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop()
        return alert

    def add_phishing_alert(
        self,
        sender: str,
        subject: str,
        threat_level: str,
        phishing_score: float,
        urgency_count: int,
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Convenience method to register a phishing incident alert."""
        alert_id = f"ALT-PHISH-{str(uuid.uuid4())[:8].upper()}"
        alert = {
            "id": alert_id,
            "timestamp": timestamp or _utc_now_iso(),
            "category": "PHISHING",
            "severity": threat_level,
            "title": f"Phishing Email: {subject[:45]}...",
            "source": sender,
            "target": "Corporate Inbox",
            "details": f"Phishing Score: {phishing_score}. {urgency_count} urgency cues.",
            "status": "OPEN",
            "mitigation_action": "Quarantine Recommended"
        }
        return self.add_alert(alert)

    def add_malware_alert(
        self,
        process_name: str,
        pid: int,
        threat_family: str,
        severity: str,
        confidence: float,
        mitre_count: int
    ) -> Dict[str, Any]:
        """Convenience method to register a malware execution incident alert."""
        alert_id = f"ALT-MALW-{str(uuid.uuid4())[:8].upper()}"
        alert = {
            "id": alert_id,
            "timestamp": _utc_now_iso(),
            "category": "MALWARE",
            "severity": severity,
            "title": f"Malware Execution: {threat_family}",
            "source": f"{process_name} (PID {pid})",
            "target": "Host Endpoint Subsystem",
            "details": f"Confidence: {confidence}. MITRE Tactics: {mitre_count}.",
            "status": "OPEN",
            "mitigation_action": "EDR Host Isolation Recommended"
        }
        return self.add_alert(alert)

    def evaluate_network_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Triggered when network anomaly detector flags an anomalous flow."""
        if flow.get("anomaly_score", 0.0) >= 0.70:
            alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"
            severity = flow.get("severity", "HIGH")
            src_ip = flow.get("src_ip", "Unknown")
            dst_ip = flow.get("dst_ip", "Unknown")
            dst_port = flow.get("dst_port", 0)

            action = "Alert Dispatched to SOC SIEM"
            if self.auto_mitigation_enabled and severity == "CRITICAL":
                action = f"Auto-Mitigation: Border Firewall dropped traffic from {src_ip}"
                with self._lock:
                    self.mitigation_log.append({
                        "timestamp": _utc_now_iso(),
                        "action": f"Firewall Rule Added: Block {src_ip}",
                        "reason": f"Anomaly score {flow.get('anomaly_score')} triggered auto-containment"
                    })

            alert = {
                "id": alert_id,
                "timestamp": flow.get("timestamp", _utc_now_iso()),
                "category": "NETWORK",
                "severity": severity,
                "title": f"Network Anomaly ({flow.get('flow_label', 'Suspicious Flow')})",
                "source": src_ip,
                "target": f"{dst_ip}:{dst_port}",
                "details": f"Anomaly Score: {flow.get('anomaly_score')}. Reasons: {', '.join(flow.get('top_reasons', []))}",
                "status": "CONTAINED" if "Auto-Mitigation" in action else "OPEN",
                "mitigation_action": action
            }
            return self.add_alert(alert)
        return None

    def trigger_containment(self, alert_id: str, action_type: str = "ISOLATE_HOST") -> Dict[str, Any]:
        """Manual or automated containment executor."""
        with self._lock:
            for alert in self.alerts:
                if alert["id"] == alert_id:
                    alert["status"] = "CONTAINED"
                    alert["mitigation_action"] = f"SOC Analyst Executed: {action_type} on {alert['source']}"
                    self.mitigation_log.append({
                        "timestamp": _utc_now_iso(),
                        "alert_id": alert_id,
                        "action": action_type,
                        "target": alert["source"]
                    })
                    return {"success": True, "alert": alert}
        return {"success": False, "error": f"Alert '{alert_id}' not found"}

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Returns a snapshot of all active alerts."""
        with self._lock:
            return list(self.alerts)
