from __future__ import annotations

from datetime import datetime
from email.utils import parseaddr
from typing import TYPE_CHECKING

from .status_handler import StatusHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG


class AutoLocateKeyHandler(StatusHandler):
    """
    This class handles status messages during key auto-locating.
    fingerprint: str
    key_length: int
    created_at: date
    email: str
    email_real_name: str
    """

    def __init__(self, gpg: GPG) -> None:
        StatusHandler.__init__(self, gpg)
        self.fingerprint = None
        self.type = None
        self.created_at = None
        self.email = None
        self.email_real_name = None

    def handle_status(self, key: str, value: str) -> None:
        if key == "IMPORTED":
            _, email, display_name = value.split()

            self.email = email
            self.email_real_name = display_name[1:-1]
        elif key == "KEY_CONSIDERED":
            self.fingerprint = value.strip().split()[0]

    def pub(self, args: list[str]) -> None:
        """
        Internal method to handle the 'pub' status message.
        `pub` message contains the fingerprint of the public key, its type and its creation date.
        """

    def uid(self, args: list[str]) -> None:
        local_tz = datetime.now().astimezone().tzinfo
        self.created_at = datetime.fromtimestamp(int(args[5]), tz=local_tz)
        raw_email_content = args[9]
        email, real_name = parseaddr(raw_email_content)
        self.email = email
        self.email_real_name = real_name

    def sub(self, args: list[str]) -> None:
        self.key_length = int(args[2])

    def fpr(self, args: list[str]) -> None:
        # Only store the first fingerprint
        self.fingerprint = self.fingerprint or args[9]
