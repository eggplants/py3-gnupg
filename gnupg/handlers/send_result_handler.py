from __future__ import annotations

from gnupg.helper import _get_logger

from .status_handler import StatusHandler

logger = _get_logger(__name__)


class SendResultHandler(StatusHandler):
    """
    This class handles status messages during key sending.
    """

    returncode = None

    def handle_status(self, key: str, value: str) -> None:
        logger.debug("SendResult: %s: %s", key, value)
