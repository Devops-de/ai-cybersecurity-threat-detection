from fastapi import APIRouter
from app.core.dependencies import AiSummarizerDep, AlertEngineDep
from app.schemas import (
    AiChatRequest,
    AiChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)

router = APIRouter(prefix="/incidents", tags=["Incident Response & Copilot"])


@router.post("/summary", response_model=IncidentSummaryResponse)
async def generate_incident_summary(
    req: IncidentSummaryRequest,
    summarizer: AiSummarizerDep,
) -> IncidentSummaryResponse:
    """
    Synthesizes raw incident telemetry into a structured executive briefing,
    MITRE kill-chain timeline, and remediation scripts.
    """
    payload = req.model_dump()
    summary = summarizer.generate_incident_summary(payload)
    return IncidentSummaryResponse(**summary)


@router.post("/copilot", response_model=AiChatResponse)
async def soc_copilot_chat(
    req: AiChatRequest,
    summarizer: AiSummarizerDep,
    alert_engine: AlertEngineDep,
) -> AiChatResponse:
    """Interactive SOC AI Assistant answering analyst queries and generating tactical playbooks."""
    reply = summarizer.chat_soc_copilot(req.message, alert_engine.get_all_alerts())
    return AiChatResponse(reply=reply)
