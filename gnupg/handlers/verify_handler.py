from __future__ import annotations

from typing import TYPE_CHECKING

from gnupg.helper import _get_logger

from .status_handler import StatusHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG

logger = _get_logger(__name__)


class VerifyHandler(StatusHandler):
    """
    This class handles status messages during signature verificaton.
    """

    TRUST_EXPIRED = 0
    TRUST_UNDEFINED = 1
    TRUST_NEVER = 2
    TRUST_MARGINAL = 3
    TRUST_FULLY = 4
    TRUST_ULTIMATE = 5

    TRUST_LEVELS = {
        "TRUST_EXPIRED": TRUST_EXPIRED,
        "TRUST_UNDEFINED": TRUST_UNDEFINED,
        "TRUST_NEVER": TRUST_NEVER,
        "TRUST_MARGINAL": TRUST_MARGINAL,
        "TRUST_FULLY": TRUST_FULLY,
        "TRUST_ULTIMATE": TRUST_ULTIMATE,
    }

    # for now, just the most common error codes. This can be expanded as and
    # when reports come in of other errors.
    GPG_SYSTEM_ERROR_CODES = {
        1: "permission denied",
        35: "file exists",
        81: "file not found",
        97: "not a directory",
    }

    GPG_ERROR_CODES = {
        11: "incorrect passphrase",
    }

    returncode = None

    def __init__(self, gpg: GPG) -> None:
        StatusHandler.__init__(self, gpg)
        self.valid = False
        self.fingerprint = self.creation_date = self.timestamp = None
        self.signature_id = self.key_id = None
        self.username = None
        self.key_id = None
        self.key_status = None
        self.status = None
        self.pubkey_fingerprint = None
        self.expire_timestamp = None
        self.sig_timestamp = None
        self.trust_text = None
        self.trust_level = None
        self.sig_info = {}
        self.problems = []

    def __nonzero__(self):  # pragma: no cover
        return self.valid

    __bool__ = __nonzero__

    def handle_status(self, key, value) -> None:

        def update_sig_info(**kwargs) -> None:
            sig_id = self.signature_id
            if sig_id:
                info = self.sig_info[sig_id]
                info.update(kwargs)
            else:
                logger.debug("Ignored due to missing sig iD: %s", kwargs)

        if key in self.TRUST_LEVELS:
            self.trust_text = key
            self.trust_level = self.TRUST_LEVELS[key]
            update_sig_info(trust_level=self.trust_level, trust_text=self.trust_text)
            # See Issue #214. Once we see this, we're done with the signature just seen.
            # Zap the signature ID, because we don't see a SIG_ID unless we have a new
            # good signature.
            self.signature_id = None
        elif key in ("WARNING", "ERROR"):  # pragma: no cover
            logger.warning("potential problem: %s: %s", key, value)
        elif key == "BADSIG":  # pragma: no cover
            self.valid = False
            self.status = "signature bad"
            self.key_id, self.username = value.split(None, 1)
            self.problems.append({"status": self.status, "keyid": self.key_id, "user": self.username})
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
        elif key == "ERRSIG":  # pragma: no cover
            self.valid = False
            parts = value.split()
            (self.key_id, algo, hash_algo, cls, self.timestamp) = parts[:5]
            # Since GnuPG 2.2.7, a fingerprint is tacked on
            if len(parts) >= 7:
                self.fingerprint = parts[6]
            self.status = "signature error"
            update_sig_info(
                keyid=self.key_id,
                timestamp=self.timestamp,
                fingerprint=self.fingerprint,
                status=self.status,
            )
            self.problems.append(
                {
                    "status": self.status,
                    "keyid": self.key_id,
                    "timestamp": self.timestamp,
                    "fingerprint": self.fingerprint,
                },
            )
        elif key == "EXPSIG":  # pragma: no cover
            self.valid = False
            self.status = "signature expired"
            self.key_id, self.username = value.split(None, 1)
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
            self.problems.append({"status": self.status, "keyid": self.key_id, "user": self.username})
        elif key == "GOODSIG":
            self.valid = True
            self.status = "signature good"
            self.key_id, self.username = value.split(None, 1)
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
        elif key == "VALIDSIG":
            parts = value.split()
            fingerprint, creation_date, sig_ts, expire_ts = parts[:4]
            (self.fingerprint, self.creation_date, self.sig_timestamp, self.expire_timestamp) = (
                fingerprint,
                creation_date,
                sig_ts,
                expire_ts,
            )
            # may be different if signature is made with a subkey
            if len(parts) >= 10:
                self.pubkey_fingerprint = parts[9]
            self.status = "signature valid"
            update_sig_info(
                fingerprint=fingerprint,
                creation_date=creation_date,
                timestamp=sig_ts,
                expiry=expire_ts,
                pubkey_fingerprint=self.pubkey_fingerprint,
                status=self.status,
            )
        elif key == "SIG_ID":
            sig_id, creation_date, timestamp = value.split()
            self.sig_info[sig_id] = {"creation_date": creation_date, "timestamp": timestamp}
            (self.signature_id, self.creation_date, self.timestamp) = (sig_id, creation_date, timestamp)
        elif key == "NO_PUBKEY":  # pragma: no cover
            self.valid = False
            self.key_id = value
            self.status = "no public key"
            self.problems.append({"status": self.status, "keyid": self.key_id})
        elif key == "NO_SECKEY":  # pragma: no cover
            self.valid = False
            self.key_id = value
            self.status = "no secret key"
            self.problems.append({"status": self.status, "keyid": self.key_id})
        elif key in ("EXPKEYSIG", "REVKEYSIG"):  # pragma: no cover
            # signed with expired or revoked key
            self.valid = False
            self.key_id = value.split()[0]
            if key == "EXPKEYSIG":
                self.key_status = "signing key has expired"
            else:
                self.key_status = "signing key was revoked"
            self.status = self.key_status
            update_sig_info(status=self.status, keyid=self.key_id)
            self.problems.append({"status": self.status, "keyid": self.key_id})
        elif key in ("UNEXPECTED", "FAILURE"):  # pragma: no cover
            self.valid = False
            if key == "UNEXPECTED":
                self.status = "unexpected data"
            else:
                # N.B. there might be other reasons. For example, if an output
                # file can't  be created - /dev/null/foo will lead to a
                # "not a directory" error, but which is not sent as a status
                # message with the [GNUPG:] prefix. Similarly if you try to
                # write to "/etc/foo" as a non-root user, a "permission denied"
                # error will be sent as a non-status message.
                message = f"error - {value}"
                operation, code = value.rsplit(" ", 1)
                if code.isdigit():
                    code = int(code) & 0xFFFFFF  # lose the error source
                    if self.gpg.error_map and code in self.gpg.error_map:
                        message = f"{operation}: {self.gpg.error_map[code]}"
                    else:
                        system_error = bool(code & 0x8000)
                        code = code & 0x7FFF
                        mapping = self.GPG_SYSTEM_ERROR_CODES if system_error else self.GPG_ERROR_CODES
                        if code in mapping:
                            message = f"{operation}: {mapping[code]}"
                if not self.status:
                    self.status = message
        elif key == "NODATA":  # pragma: no cover
            # See issue GH-191
            self.valid = False
            self.status = "signature expected but not found"
        elif key in ("DECRYPTION_INFO", "PLAINTEXT", "PLAINTEXT_LENGTH", "BEGIN_SIGNING", "KEY_CONSIDERED"):
            pass
        elif key in ("NEWSIG",):
            # Only sent in gpg2. Clear any signature ID, to be set by a following SIG_ID
            self.signature_id = None
        else:  # pragma: no cover
            logger.debug("message ignored: %r, %r", key, value)
