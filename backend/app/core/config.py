import os
from pathlib import Path
from typing import List


class Settings:
    """Application configuration settings loaded from environment or defaults."""

    PROJECT_NAME: str = "CyberSentinel AI Threat Detection Platform"
    VERSION: str = "2.1.0"
    DESCRIPTION: str = (
        "Enterprise AI-Driven Cybersecurity Threat Intelligence, Network Anomaly Detection, "
        "Phishing Detection & Malware Classification Platform"
    )
    API_PREFIX: str = "/api"

    # Server settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # CORS
    ALLOWED_ORIGINS_RAW: str = os.getenv("CORS_ORIGINS", "*")

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        if not self.ALLOWED_ORIGINS_RAW or self.ALLOWED_ORIGINS_RAW.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS_RAW.split(",") if origin.strip()]

    # Engine parameters
    MAX_FLOW_HISTORY: int = int(os.getenv("MAX_FLOW_HISTORY", "100"))
    MAX_ALERTS: int = int(os.getenv("MAX_ALERTS", "200"))
    TRAFFIC_TICK_SECONDS: float = float(os.getenv("TRAFFIC_TICK_SECONDS", "1.0"))
    ANOMALY_CONTAMINATION: float = float(os.getenv("ANOMALY_CONTAMINATION", "0.05"))

    # Testing mode
    @property
    def TESTING(self) -> bool:
        return os.getenv("TESTING", "0").lower() in ("1", "true", "yes")

    # Static distribution path
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    STATIC_DIR: Path = BASE_DIR.parent / "frontend" / "dist"


settings = Settings()
