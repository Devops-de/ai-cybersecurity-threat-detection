from fastapi import APIRouter
from app.core.dependencies import AlertEngineDep, PhishingDetectorDep
from app.schemas import EmailAnalysisRequest, EmailAnalysisResponse

router = APIRouter(prefix="/phishing", tags=["Phishing Detection"])


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_phishing_email(
    req: EmailAnalysisRequest,
    detector: PhishingDetectorDep,
    alert_engine: AlertEngineDep,
) -> EmailAnalysisResponse:
    """
    Analyzes email headers, body text, urgency cues, and URLs
    using TF-IDF NLP classification and domain verification heuristics.
    """
    result = detector.analyze_email(
        sender=req.sender,
        subject=req.subject,
        body=req.body,
        headers=req.headers,
    )

    if result.get("is_phishing"):
        indicators = result.get("indicators", {})
        urgency_count = len(indicators.get("detected_urgency_triggers", []))
        alert_engine.add_phishing_alert(
            sender=req.sender,
            subject=req.subject,
            threat_level=result["threat_level"],
            phishing_score=result["phishing_score"],
            urgency_count=urgency_count,
        )

    return EmailAnalysisResponse(**result)
