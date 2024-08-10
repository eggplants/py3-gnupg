from __future__ import annotations

from typing import TYPE_CHECKING

from .helper import _set_fields
from .search_keys_handler import SearchKeysHandler

if TYPE_CHECKING:
    from gnupg.gnupg import GPG


class ListKeysHandler(SearchKeysHandler):
    """
    This class handles status messages during listing keys and signatures.

    Handle pub and uid (relating the latter to the former).

    We don't care about (info from GnuPG DETAILS file):

    crt = X.509 certificate
    crs = X.509 certificate and private key available
    uat = user attribute (same as user id except for field 10).
    sig = signature
    rev = revocation signature
    pkd = public key data (special field format, see below)
    grp = reserved for gpgsm
    rvk = revocation key
    """

    UID_INDEX = 9
    FIELDS = (
        "type trust length algo keyid date expires dummy ownertrust uid sig"
        " cap issuer flag token hash curve compliance updated origin keygrip"
    ).split()

    def __init__(self, gpg: GPG) -> None:
        super().__init__(gpg)
        self.in_subkey = False
        self.key_map = {}

    def key(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        self.curkey = curkey = self.get_fields(args)
        if curkey["uid"]:  # pragma: no cover
            curkey["uids"].append(curkey["uid"])
        del curkey["uid"]
        curkey["subkeys"] = []
        self.append(curkey)
        self.in_subkey = False

    pub = sec = key

    def fpr(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        fp = args[9]
        if fp in self.key_map and self.gpg.check_fingerprint_collisions:  # pragma: no cover
            msg = f"Unexpected fingerprint collision: {fp}"
            raise ValueError(msg)
        if not self.in_subkey:
            self.curkey["fingerprint"] = fp
            self.fingerprints.append(fp)
            self.key_map[fp] = self.curkey
        else:
            self.curkey["subkeys"][-1][2] = fp
            self.key_map[fp] = self.curkey

    def grp(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        grp = args[9]
        if not self.in_subkey:
            self.curkey["keygrip"] = grp
        else:
            self.curkey["subkeys"][-1][3] = grp

    def _collect_subkey_info(
        self,
        curkey: dict[
            str,
            str | list[str] | list[list[str | None]] | dict[str, dict[str, str]] | list[tuple[str, str, str]],
        ],
        args: list[str],
    ) -> None:
        info_map = curkey.setdefault("subkey_info", {})
        info = {}
        _set_fields(info, self.FIELDS, args)
        info_map[args[4]] = info

    def sub(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # See issue #81. We create a dict with more information about
        # subkeys, but for backward compatibility reason, have to add it in
        # as a separate entry 'subkey_info'
        subkey = [args[4], args[11], None, None]  # keyid, type, fp, grp
        self.curkey["subkeys"].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True

    def ssb(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        subkey = [args[4], None, None, None]  # keyid, type, fp, grp
        self.curkey["subkeys"].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True

    def sig(self, args: list[str]) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # keyid, uid, sigclass
        self.curkey["sigs"].append((args[4], args[9], args[10]))
