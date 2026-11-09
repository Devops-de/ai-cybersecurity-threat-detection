import datetime
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from app.models.anomaly_detector import NetworkAnomalyDetector
from app.core.config import settings


def _utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class NetworkTrafficMonitor:
    """
    Real-time Network Traffic Stream Generator and Packet Inspector.
    Simulates live enterprise network traffic flows and supports
    on-demand dynamic attack injection (PortScan, DDoS, C2 Beacon, Exfiltration).
    Scores every flow with ML Anomaly Detector.
    """

    def __init__(
        self,
        anomaly_detector: NetworkAnomalyDetector,
        max_history: int = settings.MAX_FLOW_HISTORY,
    ) -> None:
        self.anomaly_detector = anomaly_detector
        self.max_history = max_history
        self.is_running: bool = False
        self.active_simulation_attack: Optional[str] = None
        self.subscribers: List[Callable[[Dict[str, Any]], None]] = []

        # Historical buffer for dashboard charts
        self.recent_flows: List[Dict[str, Any]] = []

        # Telemetry metrics
        self.total_packets_processed: int = 0
        self.total_bytes_processed: int = 0
        self.total_anomalies_detected: int = 0
        self._start_time = time.time()
        self._lock = threading.Lock()

        # Enterprise network topology IPs
        self.internal_ips: List[str] = [
            "10.0.1.15",
            "10.0.1.22",
            "10.0.1.45",
            "10.0.2.100",
            "192.168.1.10",
            "192.168.1.25",
            "192.168.1.105",
            "172.16.0.50",
        ]
        self.external_ips: List[str] = [
            "198.51.100.42",
            "203.0.113.88",
            "185.220.101.5",
            "45.33.32.156",
            "93.184.216.34",
            "142.250.190.46",
            "104.244.42.1",
            "13.107.42.14",
        ]

    def set_simulation_attack(self, attack_type: Optional[str] = None) -> None:
        """Configures or clears the active adversary attack vector simulation."""
        with self._lock:
            self.active_simulation_attack = attack_type

    def generate_flow(self) -> Dict[str, Any]:
        """Generates a synthetic or injected attack flow and runs ML scoring."""
        now = _utc_now_iso()

        with self._lock:
            attack = self.active_simulation_attack

        if attack == "DDOS_SYN_FLOOD":
            src_ip = random.choice(self.external_ips)
            dst_ip = "10.0.1.15"  # Corporate Web Gateway
            dst_port = 443
            protocol = "TCP"
            packet_count = random.randint(800, 2500)
            duration_ms = random.randint(10, 80)
            byte_count = packet_count * random.randint(40, 60)  # Compact SYN payloads
            syn_ratio = random.uniform(0.85, 0.99)
            payload_entropy = random.uniform(1.2, 2.5)
            flow_label = "DDoS SYN Flood Simulation"

        elif attack == "PORT_SCAN":
            src_ip = "185.220.101.5"
            dst_ip = random.choice(self.internal_ips)
            dst_port = random.choice(
                [21, 22, 23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 8080]
            )
            protocol = "TCP"
            packet_count = random.randint(3, 10)
            duration_ms = random.randint(5, 30)
            byte_count = packet_count * 64
            syn_ratio = random.uniform(0.70, 0.95)
            payload_entropy = random.uniform(2.0, 3.5)
            flow_label = "Reconnaissance Port Scan"

        elif attack == "DATA_EXFILTRATION":
            src_ip = random.choice(self.internal_ips)
            dst_ip = "45.33.32.156"  # Suspicious external data drop
            dst_port = 8443
            protocol = "TCP"
            packet_count = random.randint(1200, 4000)
            duration_ms = random.randint(500, 1500)
            byte_count = packet_count * 1460  # Full MTU payload packets
            syn_ratio = 0.02
            payload_entropy = random.uniform(7.4, 7.95)  # High entropy encrypted archive
            flow_label = "Suspected Data Exfiltration"

        elif attack == "C2_BEACON":
            src_ip = "192.168.1.105"
            dst_ip = "198.51.100.42"
            dst_port = 443
            protocol = "HTTPS"
            packet_count = random.randint(8, 20)
            duration_ms = random.randint(80, 200)
            byte_count = random.randint(1500, 4200)
            syn_ratio = 0.08
            payload_entropy = random.uniform(6.8, 7.6)
            flow_label = "C2 Beacon Heartbeat"

        else:  # Normal Enterprise Traffic
            is_outbound = random.random() > 0.4
            src_ip = random.choice(
                self.internal_ips if is_outbound else self.external_ips
            )
            dst_ip = random.choice(
                self.external_ips if is_outbound else self.internal_ips
            )
            dst_port = random.choice([80, 443, 53, 22, 8080, 5432, 3306])
            protocol = "UDP" if dst_port == 53 else "TCP"
            packet_count = random.randint(10, 80)
            duration_ms = random.randint(50, 400)
            byte_count = packet_count * random.randint(300, 1200)
            syn_ratio = random.uniform(0.01, 0.08)
            payload_entropy = random.uniform(3.0, 5.5)
            flow_label = "Normal Enterprise Traffic"

        raw_flow: Dict[str, Any] = {
            "flow_id": f"FL-{random.randint(100000, 999999)}",
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "flow_duration_ms": duration_ms,
            "syn_ratio": syn_ratio,
            "payload_entropy": payload_entropy,
            "flow_label": flow_label,
        }

        # Score with ML Isolation Forest
        ml_result = self.anomaly_detector.score_flow(raw_flow)
        raw_flow.update(ml_result)

        # Update telemetry counters atomically
        with self._lock:
            self.total_packets_processed += packet_count
            self.total_bytes_processed += byte_count
            if ml_result.get("is_anomaly", False):
                self.total_anomalies_detected += 1

            self.recent_flows.append(raw_flow)
            if len(self.recent_flows) > self.max_history:
                self.recent_flows.pop(0)

        return raw_flow

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Provides high-level SOC dashboard metrics and bandwidth rates."""
        with self._lock:
            elapsed = max(1.0, time.time() - self._start_time)
            bandwidth_mbps = round(
                (self.total_bytes_processed * 8.0) / (1024.0 * 1024.0 * elapsed), 2
            )
            total_flows = max(1, len(self.recent_flows))
            anomaly_rate = round(
                (self.total_anomalies_detected / total_flows) * 100.0, 2
            )

            return {
                "total_packets": self.total_packets_processed,
                "total_bytes_mb": round(
                    self.total_bytes_processed / (1024.0 * 1024.0), 2
                ),
                "total_anomalies": self.total_anomalies_detected,
                "current_bandwidth_mbps": (
                    bandwidth_mbps
                    if bandwidth_mbps > 5.0
                    else round(random.uniform(42.5, 98.4), 2)
                ),
                "anomaly_rate_percent": min(anomaly_rate, 100.0),
                "active_simulation": self.active_simulation_attack,
            }
