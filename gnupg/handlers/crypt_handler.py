from gnupg.helper import _get_logger

from .text_handler import TextHandler
from .verify_handler import VerifyHandler

logger = _get_logger(__name__)


class CryptHandler(VerifyHandler, TextHandler):
    """
    This class handles status messages during encryption and decryption.
    """

    def __init__(self, gpg) -> None:
        VerifyHandler.__init__(self, gpg)
        self.data = ""
        self.ok = False
        self.status = ""
        self.status_detail = ""
        self.key_id = None

    def __nonzero__(self):
        return bool(self.ok)

    __bool__ = __nonzero__

    def handle_status(self, key, value) -> None:
        if key in ("WARNING", "ERROR"):
            logger.warning("potential problem: %s: %s", key, value)
        elif key == "NODATA":
            if self.status not in ("decryption failed",):
                self.status = "no data was provided"
        elif key in (
            "NEED_PASSPHRASE",
            "BAD_PASSPHRASE",
            "GOOD_PASSPHRASE",
            "MISSING_PASSPHRASE",
            "KEY_NOT_CREATED",
            "NEED_PASSPHRASE_PIN",
        ):  # pragma: no cover
            self.status = key.replace("_", " ").lower()
        elif key == "DECRYPTION_FAILED":  # pragma: no cover
            if self.status != "no secret key":  # don't overwrite more useful message
                self.status = "decryption failed"
        elif key == "NEED_PASSPHRASE_SYM":
            self.status = "need symmetric passphrase"
        elif key == "BEGIN_DECRYPTION":
            if self.status != "no secret key":  # don't overwrite more useful message
                self.status = "decryption incomplete"
        elif key == "BEGIN_ENCRYPTION":
            self.status = "encryption incomplete"
        elif key == "DECRYPTION_OKAY":
            self.status = "decryption ok"
            self.ok = True
        elif key == "END_ENCRYPTION":
            self.status = "encryption ok"
            self.ok = True
        elif key == "INV_RECP":  # pragma: no cover
            if not self.status:
                self.status = "invalid recipient"
            else:
                self.status = f"invalid recipient: {self.status}"
            self.status_detail = _determine_invalid_recipient_or_signer(value)
        elif key == "KEYEXPIRED":  # pragma: no cover
            self.status = "key expired"
        elif key == "SIG_CREATED":  # pragma: no cover
            self.status = "sig created"
        elif key == "SIGEXPIRED":  # pragma: no cover
            self.status = "sig expired"
        elif key == "ENC_TO":  # pragma: no cover
            # ENC_TO <long_keyid> <keytype> <keylength>
            self.key_id = value.split(" ", 1)[0]
        elif key in (
            "USERID_HINT",
            "GOODMDC",
            "END_DECRYPTION",
            "CARDCTRL",
            "BADMDC",
            "SC_OP_FAILURE",
            "SC_OP_SUCCESS",
            "PINENTRY_LAUNCHED",
        ):
            pass
        else:
            VerifyHandler.handle_status(self, key, value)
