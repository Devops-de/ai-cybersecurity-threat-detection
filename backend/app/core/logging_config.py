import logging
import sys
from app.core.config import settings


def setup_logging() -> logging.Logger:
    """Configures structured console logging for the platform."""
    log_level = getattr(logging, settings.LOG_LEVEL, logging.INFO)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    logger = logging.getLogger("cybersentinel")
    logger.setLevel(log_level)
    return logger


logger = setup_logging()
