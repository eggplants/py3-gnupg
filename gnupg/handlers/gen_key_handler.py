from __future__ import annotations

from typing import TYPE_CHECKING

from gnupg.helper import _get_logger

from .status_handler import StatusHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG

logger = _get_logger(__name__)


class GenKeyHandler(StatusHandler):
    """
    This class handles status messages during key generation.
    """

    returncode = None

    def __init__(self, gpg: GPG) -> None:
        StatusHandler.__init__(self, gpg)
        self.type = None
        self.fingerprint = ""
        self.status = None

    def __nonzero__(self) -> bool:  # pragma: no cover
        return bool(self.fingerprint)

    __bool__ = __nonzero__

    def __str__(self) -> str:  # pragma: no cover
        return self.fingerprint

    def handle_status(self, key: str, value: str) -> None:
        if key in ("WARNING", "ERROR"):  # pragma: no cover
            logger.warning("potential problem: %s: %s", key, value)
        elif key == "KEY_CREATED":
            parts = value.split()
            (self.type, self.fingerprint) = parts[:2]
            self.status = "ok"
        elif key == "KEY_NOT_CREATED":
            self.status = key.replace("_", " ").lower()
        elif key in ("PROGRESS", "GOOD_PASSPHRASE"):  # pragma: no cover
            pass
        else:  # pragma: no cover
            logger.debug("message ignored: %s, %s", key, value)
