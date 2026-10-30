import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.models.anomaly_detector import NetworkAnomalyDetector
from app.models.phishing_detector import PhishingEmailDetector
from app.models.malware_classifier import MalwareBehaviorClassifier
from app.models.ai_summarizer import IncidentSummarizer
from app.services.traffic_monitor import NetworkTrafficMonitor
from app.services.alert_engine import AlertEngine

def run_tests():
    print("=" * 60)
    print("RUNNING CYBERSENTINEL AI TEST SUITE")
    print("=" * 60)

    # 1. Test Network Anomaly Detector
    print("\n[1] Testing ML Network Anomaly Detector...")
    detector = NetworkAnomalyDetector()
    
    # Normal flow
    normal_flow = {
        "flow_duration_ms": 250,
        "packet_count": 15,
        "byte_count": 8000,
        "syn_ratio": 0.05,
        "payload_entropy": 4.2,
        "dst_port": 443
    }
    score_normal = detector.score_flow(normal_flow)
    print(f"  -> Normal flow score: {score_normal['anomaly_score']} (Severity: {score_normal['severity']})")
    assert score_normal["anomaly_score"] < 0.70, "Normal flow flagged as high anomaly!"

    # DDoS Attack flow
    ddos_flow = {
        "flow_duration_ms": 25,
        "packet_count": 2000,
        "byte_count": 120000,
        "syn_ratio": 0.98,
        "payload_entropy": 1.5,
        "dst_port": 80
    }
    score_ddos = detector.score_flow(ddos_flow)
    print(f"  -> DDoS flow score: {score_ddos['anomaly_score']} (Severity: {score_ddos['severity']})")
    print(f"  -> Detected reasons: {score_ddos['top_reasons']}")
    assert score_ddos["anomaly_score"] >= 0.65, "DDoS flow failed to trigger anomaly threshold!"
    print("  [PASS] Network Anomaly Detector passed.")

    # 2. Test Phishing Email Classifier
    print("\n[2] Testing Phishing Email NLP Classifier...")
    phish_detector = PhishingEmailDetector()

    phish_email = phish_detector.analyze_email(
        sender="security@micros0ft-365.xyz",
        subject="URGENT: Password Expired - Verify Microsoft Account",
        body="Your account will be suspended in 24 hours. Click here to login: http://192.168.1.1/login.php",
        headers={"spf": "fail", "dmarc": "fail"}
    )
    print(f"  -> Phishing email score: {phish_email['phishing_score']} (Threat: {phish_email['threat_level']})")
    print(f"  -> Extracted cues: {phish_email['indicators']['detected_urgency_triggers']}")
    assert phish_email["is_phishing"] is True, "Phishing email was not detected!"

    benign_email = phish_detector.analyze_email(
        sender="colleague@enterprise.org",
        subject="Sprint Review Meeting",
        body="Hi team, see you at the sprint review at 3pm today. All unit tests passed.",
        headers={"spf": "pass", "dmarc": "pass"}
    )
    print(f"  -> Benign email score: {benign_email['phishing_score']} (Threat: {benign_email['threat_level']})")
    assert benign_email["is_phishing"] is False, "Benign email misclassified as phishing!"
    print("  [PASS] Phishing Email Detector passed.")

    # 3. Test Malware Behavior Classifier
    print("\n[3] Testing Malware Behavior Sandbox Classifier...")
    malware_detector = MalwareBehaviorClassifier()

    lockbit_trace = malware_detector.classify_behavior(
        process_name="lockbit_encrypt.exe",
        pid=5512,
        api_calls=["NtUnmapViewOfSection", "VirtualAllocEx"],
        file_events=["vssadmin delete shadows /all /quiet", "finance_2026.docx.locked"],
        reg_events=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"],
        net_events=["Beacon POST to 198.51.100.42:443"]
    )
    print(f"  -> Predicted Family: {lockbit_trace['threat_family']} (Confidence: {lockbit_trace['confidence']})")
    print(f"  -> MITRE ATT&CK Mappings ({len(lockbit_trace['mitre_attack_mappings'])}): {[m['id'] for m in lockbit_trace['mitre_attack_mappings']]}")
    assert lockbit_trace["is_malicious"] is True, "Malware trace was marked benign!"
    assert "T1490" in [m["id"] for m in lockbit_trace["mitre_attack_mappings"]], "T1490 not detected!"
    print("  [PASS] Malware Behavior Classifier passed.")

    # 4. Test AI Incident Summarizer & SOC Copilot
    print("\n[4] Testing AI Incident Summarizer & SOC Copilot...")
    summarizer = IncidentSummarizer()
    summary = summarizer.generate_incident_summary({
        "id": "INC-TEST-1",
        "type": "RANSOMWARE_OUTBREAK",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.45",
        "target_ip": "10.0.1.15"
    })
    print(f"  -> Executive briefing generated: {summary['executive_summary'][:80]}...")
    print(f"  -> Firewall script: {summary['remediation_scripts']['linux_iptables']}")
    assert "iptables" in summary["remediation_scripts"]["linux_iptables"]

    copilot_reply = summarizer.chat_soc_copilot("How to block this attacker with firewall rules?", [])
    print(f"  -> Copilot response preview: {copilot_reply[:90]}...")
    assert "iptables" in copilot_reply
    print("  [PASS] AI Incident Summarizer passed.")

    # 5. Test Traffic Monitor & Alert Engine
    print("\n[5] Testing Traffic Monitor & Alert Engine...")
    monitor = NetworkTrafficMonitor(detector)
    alert_eng = AlertEngine()
    
    # Trigger attack simulation
    monitor.set_simulation_attack("DDOS_SYN_FLOOD")
    flow = monitor.generate_flow()
    print(f"  -> Generated attack flow: {flow['flow_label']} (Score: {flow['anomaly_score']})")
    alert = alert_eng.evaluate_network_flow(flow)
    assert alert is not None, "Alert engine failed to create alert for DDoS attack!"
    print(f"  -> Alert created: {alert['id']} - {alert['title']} (Status: {alert['status']})")
    print("  [PASS] Traffic Monitor & Alert Engine passed.")

    print("\n" + "=" * 60)
    print("ALL 5 CORE AI THREAT DETECTION ENGINES PASSED WITH ZERO ERRORS!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
