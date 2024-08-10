from __future__ import annotations

from typing import TYPE_CHECKING

from gnupg.helper import _get_logger

from .status_handler import StatusHandler
from .text_handler import TextHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG

logger = _get_logger(__name__)


class SignHandler(StatusHandler, TextHandler):
    """
    This class handles status messages during signing.
    """

    returncode = None

    def __init__(self, gpg: GPG) -> None:
        StatusHandler.__init__(self, gpg)
        self.type = None
        self.hash_algo = None
        self.fingerprint = None
        self.status = None
        self.status_detail = None
        self.key_id = None
        self.username = None

    def __nonzero__(self) -> bool:
        return self.fingerprint is not None

    __bool__ = __nonzero__

    def handle_status(self, key, value) -> None:
        if key in ("WARNING", "ERROR", "FAILURE"):  # pragma: no cover
            logger.warning("potential problem: %s: %s", key, value)
        elif key in ("KEYEXPIRED", "SIGEXPIRED"):  # pragma: no cover
            self.status = "key expired"
        elif key == "KEYREVOKED":  # pragma: no cover
            self.status = "key revoked"
        elif key == "SIG_CREATED":
            (self.type, algo, self.hash_algo, cls, self.timestamp, self.fingerprint) = value.split()
            self.status = "signature created"
        elif key == "USERID_HINT":  # pragma: no cover
            self.key_id, self.username = value.split(" ", 1)
        elif key == "BAD_PASSPHRASE":  # pragma: no cover
            self.status = "bad passphrase"
        elif key in ("INV_SGNR", "INV_RECP"):  # pragma: no cover
            # INV_RECP is returned in older versions
            if not self.status:
                self.status = "invalid signer"
            else:
                self.status = f"invalid signer: {self.status}"
            self.status_detail = _determine_invalid_recipient_or_signer(value)
        elif key in ("NEED_PASSPHRASE", "GOOD_PASSPHRASE", "BEGIN_SIGNING"):
            pass
        else:  # pragma: no cover
            logger.debug("message ignored: %s, %s", key, value)
