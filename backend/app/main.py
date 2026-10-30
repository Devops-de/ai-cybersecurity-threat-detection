import asyncio
import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.models.anomaly_detector import NetworkAnomalyDetector
from app.models.phishing_detector import PhishingEmailDetector
from app.models.malware_classifier import MalwareBehaviorClassifier
from app.models.ai_summarizer import IncidentSummarizer
from app.services.traffic_monitor import NetworkTrafficMonitor
from app.services.threat_intel import ThreatIntelligenceService
from app.services.alert_engine import AlertEngine
from app.schemas import (
    EmailAnalysisRequest,
    MalwareAnalysisRequest,
    IncidentSummaryRequest,
    AiChatRequest,
    ContainmentRequest
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_soc")

# Initialize AI & ML Core Engines
anomaly_detector = NetworkAnomalyDetector()
phishing_detector = PhishingEmailDetector()
malware_classifier = MalwareBehaviorClassifier()
ai_summarizer = IncidentSummarizer()
traffic_monitor = NetworkTrafficMonitor(anomaly_detector)
threat_intel = ThreatIntelligenceService()
alert_engine = AlertEngine()

# Active WebSocket connections
connected_websockets: list[WebSocket] = []

async def traffic_generator_background_task():
    """Continuously generates network flows and broadcasts to connected clients."""
    logger.info("Starting background real-time traffic generation loop...")
    while True:
        try:
            flow = traffic_monitor.generate_flow()
            alert = alert_engine.evaluate_network_flow(flow)
            
            payload = {
                "type": "TRAFFIC_UPDATE",
                "flow": flow,
                "stats": traffic_monitor.get_aggregate_stats(),
                "alert": alert
            }

            disconnected = []
            for ws in connected_websockets:
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    disconnected.append(ws)

            for ws in disconnected:
                if ws in connected_websockets:
                    connected_websockets.remove(ws)

        except Exception as e:
            logger.error(f"Error in traffic generator loop: {e}")

        await asyncio.sleep(1.0) # 1 flow per second

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start traffic generator background task on app startup
    task = asyncio.create_task(traffic_generator_background_task())
    yield
    task.cancel()

app = FastAPI(
    title="CyberSentinel AI Threat Detection Platform",
    description="Enterprise AI-Driven Cybersecurity Threat Intelligence, Network Anomaly Detection, Phishing Detection & Malware Classification System",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- WEBSOCKET ROUTE -----------------
@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    logger.info(f"Client connected to telemetry stream. Total clients: {len(connected_websockets)}")
    try:
        while True:
            # Handle inbound commands from frontend via WS if any
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "SET_ATTACK_SIMULATION":
                attack_type = msg.get("attack_type")
                traffic_monitor.set_simulation_attack(attack_type)
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
        logger.info("Client disconnected from telemetry stream.")

# ----------------- NETWORK MONITORING -----------------
@app.get("/api/traffic/recent")
async def get_recent_traffic():
    return {
        "flows": traffic_monitor.recent_flows,
        "stats": traffic_monitor.get_aggregate_stats()
    }

@app.get("/api/traffic/stats")
async def get_traffic_stats():
    return traffic_monitor.get_aggregate_stats()

@app.post("/api/traffic/simulate-attack")
async def simulate_attack(payload: dict):
    attack_type = payload.get("attack_type")
    traffic_monitor.set_simulation_attack(attack_type)
    return {
        "status": "success",
        "current_simulation": attack_type,
        "message": f"Network traffic stream adjusted to: {attack_type or 'Normal Traffic'}"
    }

# ----------------- PHISHING DETECTION -----------------
@app.post("/api/phishing/analyze")
async def analyze_phishing_email(req: EmailAnalysisRequest):
    result = phishing_detector.analyze_email(
        sender=req.sender,
        subject=req.subject,
        body=req.body,
        headers=req.headers
    )
    # Check if high threat, register alert
    if result["is_phishing"]:
        alert_engine.alerts.insert(0, {
            "id": f"ALT-PHISH-{len(alert_engine.alerts)+100}",
            "timestamp": result.get("timestamp") or "Just Now",
            "category": "PHISHING",
            "severity": result["threat_level"],
            "title": f"Phishing Email: {req.subject[:45]}...",
            "source": req.sender,
            "target": "Corporate Inbox",
            "details": f"Phishing Score: {result['phishing_score']}. {len(result['indicators']['detected_urgency_triggers'])} urgency cues.",
            "status": "OPEN",
            "mitigation_action": "Quarantine Recommended"
        })
    return result

# ----------------- MALWARE BEHAVIOR CLASSIFICATION -----------------
@app.post("/api/malware/classify")
async def classify_malware(req: MalwareAnalysisRequest):
    result = malware_classifier.classify_behavior(
        process_name=req.process_name,
        pid=req.pid,
        api_calls=req.api_calls,
        file_events=req.file_events,
        reg_events=req.reg_events,
        net_events=req.net_events
    )
    if result["is_malicious"]:
        alert_engine.alerts.insert(0, {
            "id": f"ALT-MALW-{len(alert_engine.alerts)+200}",
            "timestamp": "Just Now",
            "category": "MALWARE",
            "severity": result["severity"],
            "title": f"Malware Execution: {result['threat_family']}",
            "source": f"{req.process_name} (PID {req.pid})",
            "target": "Host Endpoint Subsystem",
            "details": f"Confidence: {result['confidence']}. MITRE Tactics: {len(result['mitre_attack_mappings'])}.",
            "status": "OPEN",
            "mitigation_action": "EDR Host Isolation Recommended"
        })
    return result

# ----------------- AI INCIDENT SUMMARIES & COPILOT -----------------
@app.post("/api/incidents/summary")
async def generate_incident_summary(req: IncidentSummaryRequest):
    summary = ai_summarizer.generate_incident_summary(req.dict())
    return summary

@app.post("/api/incidents/copilot")
async def soc_copilot_chat(req: AiChatRequest):
    reply = ai_summarizer.chat_soc_copilot(req.message, alert_engine.get_all_alerts())
    return {"reply": reply}

# ----------------- THREAT INTEL -----------------
@app.get("/api/threat-intel/feed")
async def get_threat_intelligence_feed():
    return {
        "global_threats": threat_intel.get_global_threat_feed(),
        "active_indicators": 4
    }

@app.get("/api/threat-intel/lookup/{ip}")
async def lookup_ip_intelligence(ip: str):
    return threat_intel.lookup_ip(ip)

# ----------------- ALERTS & CONTAINMENT -----------------
@app.get("/api/alerts")
async def get_all_alerts():
    return {
        "alerts": alert_engine.get_all_alerts(),
        "total": len(alert_engine.alerts)
    }

@app.post("/api/alerts/contain")
async def execute_containment(req: ContainmentRequest):
    res = alert_engine.trigger_containment(req.alert_id, req.action_type)
    if not res["success"]:
        raise HTTPException(status_code=404, detail=res["error"])
    return res

@app.get("/api/health")
async def health_check():
    return {
        "status": "ONLINE",
        "models": {
            "anomaly_detector": "ACTIVE (Isolation Forest)",
            "phishing_detector": "ACTIVE (NLP TF-IDF + Logistic Regression)",
            "malware_classifier": "ACTIVE (Behavioral MITRE ATT&CK Engine)",
            "ai_summarizer": "ACTIVE (GenAI SOC Incident Synthesizer)"
        }
    }

# Mount static frontend production build if available
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend_static")

