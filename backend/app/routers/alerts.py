from fastapi import APIRouter, HTTPException, status
from app.core.dependencies import AlertEngineDep
from app.schemas import (
    AlertResponse,
    AlertsListResponse,
    ContainmentRequest,
    ContainmentResponse,
)

router = APIRouter(prefix="/alerts", tags=["Alerts & Containment"])


@router.get("", response_model=AlertsListResponse)
async def get_all_alerts(alert_engine: AlertEngineDep) -> AlertsListResponse:
    """Returns all active, investigated, or contained security alerts."""
    all_alerts = alert_engine.get_all_alerts()
    return AlertsListResponse(
        alerts=[AlertResponse(**a) for a in all_alerts],
        total=len(all_alerts),
    )


@router.post("/contain", response_model=ContainmentResponse)
async def execute_containment(
    req: ContainmentRequest,
    alert_engine: AlertEngineDep,
) -> ContainmentResponse:
    """Triggers automated or manual host isolation and perimeter blocking."""
    res = alert_engine.trigger_containment(req.alert_id, req.action_type)
    if not res.get("success"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=res.get("error", "Alert not found"),
        )
    return ContainmentResponse(
        success=True,
        alert=AlertResponse(**res["alert"]),
    )
