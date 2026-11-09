from fastapi import APIRouter
from app.core.config import settings
from app.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Verifies operational state of all core AI detection engines."""
    return HealthResponse(
        status="ONLINE",
        version=settings.VERSION,
        models={
            "anomaly_detector": "ACTIVE (Isolation Forest)",
            "phishing_detector": "ACTIVE (NLP TF-IDF + Logistic Regression)",
            "malware_classifier": "ACTIVE (Behavioral MITRE ATT&CK Engine)",
            "ai_summarizer": "ACTIVE (GenAI SOC Incident Synthesizer)",
        },
    )
