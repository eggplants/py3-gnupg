from typing import NoReturn


class StatusHandler:
    """
    The base class for handling status messages from `gpg`.
    """

    def __init__(self, gpg) -> None:
        """
        Initialize an instance.

        Args:
            gpg (GPG): The :class:`GPG` instance in use.
        """
        self.gpg = gpg

    def handle_status(self, key, value) -> NoReturn:
        """
        Handle status messages from the `gpg` child process. These are lines of the format

            [GNUPG:] <key> <value>

        Args:
            key (str): Identifies what the status message is.
            value (str): Identifies additional data, which differs depending on the key.
        """
        raise NotImplementedError
