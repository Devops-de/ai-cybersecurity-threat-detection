import numpy as np
from sklearn.ensemble import IsolationForest
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("anomaly_detector")

class NetworkAnomalyDetector:
    """
    Unsupervised ML Anomaly Detection using Isolation Forest & Statistical Profiling.
    Monitors flow duration, byte rate, packet rate, syn/ack ratios, payload entropy,
    and port spread to flag zero-day attacks and traffic anomalies.
    """
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=1
        )
        self.feature_names = [
            "flow_duration_ms",
            "packet_count",
            "byte_count",
            "bytes_per_sec",
            "packets_per_sec",
            "syn_ratio",
            "payload_entropy",
            "port_deviation"
        ]
        self.baseline_stats = {}
        self.is_trained = False
        self._init_baseline_model()

    def _extract_feature_vector(self, flow: Dict[str, Any]) -> np.ndarray:
        flow_duration = max(float(flow.get("flow_duration_ms", 10.0)), 1.0)
        packet_count = float(flow.get("packet_count", 1))
        byte_count = float(flow.get("byte_count", 64))
        bytes_per_sec = (byte_count / (flow_duration / 1000.0))
        packets_per_sec = (packet_count / (flow_duration / 1000.0))
        syn_ratio = float(flow.get("syn_ratio", 0.0))
        payload_entropy = float(flow.get("payload_entropy", 3.5))
        dst_port = float(flow.get("dst_port", 80))
        common_ports = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 21, 25]
        port_deviation = 0.0 if dst_port in common_ports else 1.0

        return np.array([
            flow_duration,
            packet_count,
            byte_count,
            bytes_per_sec,
            packets_per_sec,
            syn_ratio,
            payload_entropy,
            port_deviation
        ])

    def _init_baseline_model(self):
        """Pre-train with synthetic baseline of regular enterprise network traffic."""
        np.random.seed(42)
        n_samples = 1200
        # Normal traffic distributions:
        durations = np.random.exponential(scale=350.0, size=n_samples) + 20
        packets = np.random.poisson(lam=12, size=n_samples) + 2
        bytes_cnt = packets * np.random.normal(loc=550, scale=120, size=n_samples).clip(64, 1500)
        bytes_sec = bytes_cnt / (durations / 1000.0)
        packets_sec = packets / (durations / 1000.0)
        syn_ratio = np.random.beta(a=1, b=25, size=n_samples) # Low syn ratio in normal flows
        payload_entropy = np.random.normal(loc=3.8, scale=0.6, size=n_samples).clip(1.0, 7.5)
        port_dev = np.random.choice([0.0, 1.0], p=[0.92, 0.08], size=n_samples)

        X_train = np.column_stack([
            durations,
            packets,
            bytes_cnt,
            bytes_sec,
            packets_sec,
            syn_ratio,
            payload_entropy,
            port_dev
        ])

        self.model.fit(X_train)
        self.baseline_stats = {
            "mean": np.mean(X_train, axis=0),
            "std": np.std(X_train, axis=0) + 1e-6
        }
        self.is_trained = True

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates anomaly score (0.0 to 1.0) and generates diagnostic findings.
        """
        vec = self._extract_feature_vector(flow).reshape(1, -1)
        raw_score = self.model.decision_function(vec)[0] # Positive = Normal, Negative = Anomaly
        # Map decision function to 0.0 - 1.0 risk scale
        # Typical raw_score is in range [-0.4, 0.4]
        anomaly_score = float(np.clip(1.0 / (1.0 + np.exp(raw_score * 8.0)), 0.0, 0.99))

        is_anomaly = bool(anomaly_score >= 0.65)
        
        # Explainability: Identify which features deviated most from normal baseline
        z_scores = np.abs((vec[0] - self.baseline_stats["mean"]) / self.baseline_stats["std"])
        top_indices = np.argsort(z_scores)[::-1]
        
        reasons = []
        for idx in top_indices[:3]:
            if z_scores[idx] > 2.0:
                feat = self.feature_names[idx]
                val = vec[0][idx]
                if feat == "syn_ratio" and val > 0.4:
                    reasons.append(f"Abnormal SYN packet ratio ({val:.2f}) - potential SYN Flood / Port Scan")
                elif feat == "bytes_per_sec" and val > 500000:
                    reasons.append(f"Excessive byte rate ({val/1024:.1f} KB/s) - possible exfiltration or volumetric burst")
                elif feat == "packets_per_sec" and val > 500:
                    reasons.append(f"Hyper-packet rate ({val:.0f} pkts/s) - characteristic DoS pattern")
                elif feat == "payload_entropy" and val > 7.0:
                    reasons.append(f"High payload entropy ({val:.2f}) - encrypted C2 or compressed data leak")
                elif feat == "port_deviation" and val > 0.5:
                    reasons.append(f"Non-standard communication destination port ({flow.get('dst_port')})")
                else:
                    reasons.append(f"Statistical deviation in {feat} (z-score: {z_scores[idx]:.1f})")

        severity = "LOW"
        if anomaly_score >= 0.85:
            severity = "CRITICAL"
        elif anomaly_score >= 0.75:
            severity = "HIGH"
        elif anomaly_score >= 0.60:
            severity = "MEDIUM"

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "severity": severity,
            "top_reasons": reasons if reasons else ["Flow within expected operational bounds"],
            "features": {
                name: round(float(val), 2)
                for name, val in zip(self.feature_names, vec[0])
            }
        }
