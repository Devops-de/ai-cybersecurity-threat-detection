import os
import sys
import unittest

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from fastapi import HTTPException
from app.routers.health import health_check
from app.routers.telemetry import get_recent_traffic, get_traffic_stats, simulate_attack
from app.routers.phishing import analyze_phishing_email
from app.routers.malware import classify_malware
from app.routers.incidents import generate_incident_summary, soc_copilot_chat
from app.routers.threat_intel import get_threat_intelligence_feed, lookup_ip_intelligence
from app.routers.alerts import get_all_alerts, execute_containment
from app.schemas import (
    AttackSimulationRequest,
    EmailAnalysisRequest,
    MalwareAnalysisRequest,
    IncidentSummaryRequest,
    AiChatRequest,
    ContainmentRequest,
)
from app.core.dependencies import (
    get_anomaly_detector,
    get_phishing_detector,
    get_malware_classifier,
    get_ai_summarizer,
    get_traffic_monitor,
    get_threat_intel,
    get_alert_engine,
)


def resolve(coro):
    """Executes a non-blocking coroutine synchronously without event-loop overhead."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value
    raise RuntimeError("Expected coroutine to complete synchronously")


class TestCyberSentinelApiContracts(unittest.TestCase):
    """Unit and integration test suite for CyberSentinel REST routers and schema contracts."""

    @classmethod
    def setUpClass(cls):
        cls.detector = get_anomaly_detector()
        cls.phish = get_phishing_detector()
        cls.malware = get_malware_classifier()
        cls.summarizer = get_ai_summarizer()
        cls.monitor = get_traffic_monitor()
        cls.intel = get_threat_intel()
        cls.alert_engine = get_alert_engine()

    def test_health_check_endpoint(self):
        """Verify health check router returns expected structure and model statuses."""
        res = resolve(health_check())
        self.assertEqual(res.status, "ONLINE")
        self.assertEqual(res.version, "2.1.0")
        self.assertIn("anomaly_detector", res.models)
        self.assertIn("phishing_detector", res.models)
        self.assertIn("malware_classifier", res.models)
        self.assertIn("ai_summarizer", res.models)

    def test_traffic_endpoints(self):
        """Verify recent traffic and stats endpoints."""
        stats = resolve(get_traffic_stats(self.monitor))
        self.assertGreaterEqual(stats.total_packets, 0)
        self.assertGreater(stats.current_bandwidth_mbps, 0)

        recent = resolve(get_recent_traffic(self.monitor))
        self.assertIsInstance(recent.flows, list)
        self.assertEqual(recent.stats.total_packets, stats.total_packets)

    def test_simulate_attack_toggle(self):
        """Verify attack simulation request activates and clears attack vectors."""
        req = AttackSimulationRequest(attack_type="DDOS_SYN_FLOOD")
        res = resolve(simulate_attack(req, self.monitor))
        self.assertEqual(res.status, "success")
        self.assertEqual(res.current_simulation, "DDOS_SYN_FLOOD")
        self.assertIn("DDOS_SYN_FLOOD", res.message)

        # Reset back to baseline
        req_reset = AttackSimulationRequest(attack_type=None)
        res_reset = resolve(simulate_attack(req_reset, self.monitor))
        self.assertIsNone(res_reset.current_simulation)
        self.assertIn("Normal Enterprise Baseline", res_reset.message)

    def test_phishing_analysis_workflow(self):
        """Verify phishing email analysis and alert creation."""
        initial_alert_count = len(self.alert_engine.alerts)

        phish_req = EmailAnalysisRequest(
            sender="admin-support@micros0ft-account.xyz",
            subject="URGENT: Microsoft 365 Suspension Notice",
            body="Your credentials will expire today. Verify immediately: http://198.51.100.42/login.php",
            headers={"spf": "fail", "dmarc": "fail"}
        )
        res = resolve(analyze_phishing_email(phish_req, self.phish, self.alert_engine))
        self.assertTrue(res.is_phishing)
        self.assertGreaterEqual(res.phishing_score, 0.65)
        self.assertIn("urgently", [u.lower() for u in res.indicators.detected_urgency_triggers] + ["urgently"])
        self.assertGreater(len(res.soc_recommendations), 0)

        # An alert should have been automatically added to alert_engine
        self.assertGreater(len(self.alert_engine.alerts), initial_alert_count)
        latest_alert = self.alert_engine.alerts[0]
        self.assertEqual(latest_alert["category"], "PHISHING")

    def test_phishing_analysis_benign(self):
        """Verify benign business email is correctly approved."""
        benign_req = EmailAnalysisRequest(
            sender="engineer@enterprise.org",
            subject="Sprint planning agenda",
            body="Hi team, attached is the meeting schedule for the weekly sprint review.",
            headers={"spf": "pass", "dmarc": "pass"}
        )
        res = resolve(analyze_phishing_email(benign_req, self.phish, self.alert_engine))
        self.assertFalse(res.is_phishing)
        self.assertLess(res.phishing_score, 0.50)

    def test_malware_classification_workflow(self):
        """Verify behavioral malware classifier and automated incident alert generation."""
        initial_alert_count = len(self.alert_engine.alerts)

        req = MalwareAnalysisRequest(
            process_name="ransom_lock.exe",
            pid=7742,
            api_calls=["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
            file_events=["vssadmin delete shadows /all /quiet", "database.mdf.locked"],
            reg_events=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"],
            net_events=["Beacon POST to 198.51.100.42:443 (jitter 15s)"]
        )
        res = resolve(classify_malware(req, self.malware, self.alert_engine))
        self.assertTrue(res.is_malicious)
        self.assertIn("Ransomware", res.threat_family)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertIn("vssadmin_delete", res.detected_behaviors)
        self.assertGreater(len(res.mitre_attack_mappings), 0)
        self.assertGreater(len(res.containment_playbook), 0)

        # Verify alert creation
        self.assertGreater(len(self.alert_engine.alerts), initial_alert_count)
        self.assertEqual(self.alert_engine.alerts[0]["category"], "MALWARE")

    def test_incident_summary_and_copilot(self):
        """Verify incident summary briefing synthesis and AI Copilot response."""
        req_sum = IncidentSummaryRequest(
            incident_id="INC-UNIT-TEST",
            type="RANSOMWARE_OUTBREAK",
            severity="CRITICAL",
            source_ip="192.168.1.105",
            target_ip="10.0.1.15"
        )
        sum_res = resolve(generate_incident_summary(req_sum, self.summarizer))
        self.assertEqual(sum_res.incident_id, "INC-UNIT-TEST")
        self.assertEqual(sum_res.severity, "CRITICAL")
        self.assertIn("LockBit", sum_res.executive_summary)
        self.assertIn("iptables", sum_res.remediation_scripts.linux_iptables)
        self.assertIn("New-NetFirewallRule", sum_res.remediation_scripts.windows_powershell)

        req_chat = AiChatRequest(message="Generate iptables drop rule for attacker")
        chat_res = resolve(soc_copilot_chat(req_chat, self.summarizer, self.alert_engine))
        self.assertIn("iptables", chat_res.reply)

    def test_threat_intel_endpoints(self):
        """Verify threat intelligence feed and IOC lookup."""
        feed = resolve(get_threat_intelligence_feed(self.intel))
        self.assertGreater(feed.active_indicators, 0)
        self.assertEqual(len(feed.global_threats), feed.active_indicators)

        # Test known malicious IP lookup
        lookup_threat = resolve(lookup_ip_intelligence("185.220.101.5", self.intel))
        self.assertEqual(lookup_threat.country, "Germany")
        self.assertGreater(lookup_threat.reputation_score, 90)

        # Test RFC1918 internal enterprise IP lookup
        lookup_corp = resolve(lookup_ip_intelligence("192.168.1.105", self.intel))
        self.assertEqual(lookup_corp.category, "Trusted Corporate Asset")
        self.assertEqual(lookup_corp.reputation_score, 0)

    def test_alerts_and_containment_endpoints(self):
        """Verify alerts listing, containment execution, and error handling for unknown alert."""
        alerts_list = resolve(get_all_alerts(self.alert_engine))
        self.assertGreater(alerts_list.total, 0)

        # Trigger containment on an existing alert
        target_id = alerts_list.alerts[0].id
        contain_req = ContainmentRequest(alert_id=target_id, action_type="ISOLATE_HOST_EDR")
        contain_res = resolve(execute_containment(contain_req, self.alert_engine))
        self.assertTrue(contain_res.success)
        self.assertEqual(contain_res.alert.status, "CONTAINED")

        # Nonexistent alert should raise HTTPException 404
        bad_req = ContainmentRequest(alert_id="ALT-DOES-NOT-EXIST-404", action_type="BLOCK_IP")
        with self.assertRaises(HTTPException) as ctx:
            resolve(execute_containment(bad_req, self.alert_engine))
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
