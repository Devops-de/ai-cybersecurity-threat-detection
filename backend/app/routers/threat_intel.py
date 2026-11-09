from fastapi import APIRouter
from app.core.dependencies import ThreatIntelDep
from app.schemas import ThreatFeedResponse, ThreatIntelItemResponse

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("/feed", response_model=ThreatFeedResponse)
async def get_threat_intelligence_feed(intel: ThreatIntelDep) -> ThreatFeedResponse:
    """Returns active global threat indicators and reputation telemetry."""
    feed = intel.get_global_threat_feed()
    return ThreatFeedResponse(
        global_threats=[ThreatIntelItemResponse(**item) for item in feed],
        active_indicators=len(feed),
    )


@router.get("/lookup/{ip}", response_model=ThreatIntelItemResponse)
async def lookup_ip_intelligence(ip: str, intel: ThreatIntelDep) -> ThreatIntelItemResponse:
    """Retrieves threat reputation, GeoIP origin, and ASN data for an IP address."""
    info = intel.lookup_ip(ip)
    return ThreatIntelItemResponse(**info)
