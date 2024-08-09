import re

from .helper import _set_fields
from .status_handler import StatusHandler

ESCAPE_PATTERN = re.compile(r"\\x([0-9a-f][0-9a-f])", re.IGNORECASE)
BASIC_ESCAPES = {
    r"\n": "\n",
    r"\r": "\r",
    r"\f": "\f",
    r"\v": "\v",
    r"\b": "\b",
    r"\0": "\0",
}


class SearchKeysHandler(StatusHandler, list):
    """
    This class handles status messages during key search.
    """

    # Handle pub and uid (relating the latter to the former).
    # Don't care about the rest

    UID_INDEX = 1
    FIELDS = "type keyid algo length date expires".split()
    returncode = None

    def __init__(self, gpg) -> None:
        StatusHandler.__init__(self, gpg)
        self.curkey = None
        self.fingerprints = []
        self.uids = []

    def get_fields(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        result = {}
        _set_fields(result, self.FIELDS, args)
        result["uids"] = []
        result["sigs"] = []
        return result

    def pub(self, args) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        self.curkey = curkey = self.get_fields(args)
        self.append(curkey)

    def uid(self, args) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        uid = args[self.UID_INDEX]
        uid = ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), uid)
        for k, v in BASIC_ESCAPES.items():
            uid = uid.replace(k, v)
        self.curkey["uids"].append(uid)
        self.uids.append(uid)

    def handle_status(self, key, value) -> None:  # pragma: no cover
        pass
