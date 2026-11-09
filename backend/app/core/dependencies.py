from typing import Annotated
from fastapi import Depends

from app.models.anomaly_detector import NetworkAnomalyDetector
from app.models.phishing_detector import PhishingEmailDetector
from app.models.malware_classifier import MalwareBehaviorClassifier
from app.models.ai_summarizer import IncidentSummarizer
from app.services.traffic_monitor import NetworkTrafficMonitor
from app.services.threat_intel import ThreatIntelligenceService
from app.services.alert_engine import AlertEngine
from app.core.websocket_manager import ConnectionManager

# Initialize Core AI & Security Singletons
_anomaly_detector = NetworkAnomalyDetector()
_phishing_detector = PhishingEmailDetector()
_malware_classifier = MalwareBehaviorClassifier()
_ai_summarizer = IncidentSummarizer()
_threat_intel = ThreatIntelligenceService()
_alert_engine = AlertEngine()
_traffic_monitor = NetworkTrafficMonitor(_anomaly_detector)
_ws_manager = ConnectionManager()


def get_anomaly_detector() -> NetworkAnomalyDetector:
    return _anomaly_detector


def get_phishing_detector() -> PhishingEmailDetector:
    return _phishing_detector


def get_malware_classifier() -> MalwareBehaviorClassifier:
    return _malware_classifier


def get_ai_summarizer() -> IncidentSummarizer:
    return _ai_summarizer


def get_traffic_monitor() -> NetworkTrafficMonitor:
    return _traffic_monitor


def get_threat_intel() -> ThreatIntelligenceService:
    return _threat_intel


def get_alert_engine() -> AlertEngine:
    return _alert_engine


def get_ws_manager() -> ConnectionManager:
    return _ws_manager


AnomalyDetectorDep = Annotated[NetworkAnomalyDetector, Depends(get_anomaly_detector)]
PhishingDetectorDep = Annotated[PhishingEmailDetector, Depends(get_phishing_detector)]
MalwareClassifierDep = Annotated[MalwareBehaviorClassifier, Depends(get_malware_classifier)]
AiSummarizerDep = Annotated[IncidentSummarizer, Depends(get_ai_summarizer)]
TrafficMonitorDep = Annotated[NetworkTrafficMonitor, Depends(get_traffic_monitor)]
ThreatIntelDep = Annotated[ThreatIntelligenceService, Depends(get_threat_intel)]
AlertEngineDep = Annotated[AlertEngine, Depends(get_alert_engine)]
WsManagerDep = Annotated[ConnectionManager, Depends(get_ws_manager)]
