from .list_keys_handler import ListKeysHandler


class ScanKeysHandler(ListKeysHandler):
    """
    This class handles status messages during scanning keys.
    """

    def sub(self, args) -> None:
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # --with-fingerprint --with-colons somehow outputs fewer colons,
        # use the last value args[-1] instead of args[11]
        subkey = [args[4], args[-1], None, None]
        self.curkey["subkeys"].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True
