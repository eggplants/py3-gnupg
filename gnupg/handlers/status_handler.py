from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from gnupg.gnupg import GPG


class StatusHandler:
    """
    The base class for handling status messages from `gpg`.
    """

    def __init__(self, gpg: GPG) -> None:
        """
        Initialize an instance.

        Args:
            gpg (GPG): The :class:`GPG` instance in use.
        """
        self.gpg = gpg
        self.data: str | None = None

    def handle_status(self, key, value) -> NoReturn:
        """
        Handle status messages from the `gpg` child process. These are lines of the format

            [GNUPG:] <key> <value>

        Args:
            key (str): Identifies what the status message is.
            value (str): Identifies additional data, which differs depending on the key.
        """
        raise NotImplementedError
