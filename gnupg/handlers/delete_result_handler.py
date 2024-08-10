from __future__ import annotations

from typing import TYPE_CHECKING

from gnupg.helper import _get_logger

from .status_handler import StatusHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG

logger = _get_logger(__name__)


class DeleteResultHandler(StatusHandler):
    """
    This class handles status messages during key deletion.
    """

    returncode = None

    def __init__(self, gpg: GPG) -> None:
        StatusHandler.__init__(self, gpg)
        self.status = "ok"

    def __str__(self) -> str:
        return self.status

    problem_reason = {
        "1": "No such key",
        "2": "Must delete secret key first",
        "3": "Ambiguous specification",
    }

    def handle_status(self, key, value) -> None:
        if key == "DELETE_PROBLEM":  # pragma: no cover
            self.status = self.problem_reason.get(value, f"Unknown error: {value!r}")
        else:  # pragma: no cover
            logger.debug("message ignored: %s, %s", key, value)

    def __nonzero__(self):  # pragma: no cover
        return self.status == "ok"

    __bool__ = __nonzero__
