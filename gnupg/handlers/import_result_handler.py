from gnupg.helper import _get_logger

from .status_handler import StatusHandler

logger = _get_logger(__name__)


class ImportResultHandler(StatusHandler):
    """
    This class handles status messages during key import.
    """

    counts = """count no_user_id imported imported_rsa unchanged n_uids n_subk n_sigs n_revoc sec_read sec_imported
            sec_dups not_imported""".split()

    returncode = None

    def __init__(self, gpg) -> None:
        StatusHandler.__init__(self, gpg)
        self.results = []
        self.fingerprints = []
        for result in self.counts:
            setattr(self, result, 0)

    def __nonzero__(self):
        return bool(not self.not_imported and self.fingerprints)

    __bool__ = __nonzero__

    ok_reason = {
        "0": "Not actually changed",
        "1": "Entirely new key",
        "2": "New user IDs",
        "4": "New signatures",
        "8": "New subkeys",
        "16": "Contains private key",
    }

    problem_reason = {
        "0": "No specific reason given",
        "1": "Invalid Certificate",
        "2": "Issuer Certificate missing",
        "3": "Certificate Chain too long",
        "4": "Error storing certificate",
    }

    def handle_status(self, key, value) -> None:
        if key in ("WARNING", "ERROR"):  # pragma: no cover
            logger.warning("potential problem: %s: %s", key, value)
        elif key in ("IMPORTED", "KEY_CONSIDERED"):
            # this duplicates info we already see in import_ok & import_problem
            pass
        elif key == "NODATA":  # pragma: no cover
            self.results.append({"fingerprint": None, "problem": "0", "text": "No valid data found"})
        elif key == "IMPORT_OK":
            reason, fingerprint = value.split()
            reasons = []
            for code, text in list(self.ok_reason.items()):
                if int(reason) | int(code) == int(reason):
                    reasons.append(text)
            reasontext = "\n".join(reasons) + "\n"
            self.results.append({"fingerprint": fingerprint, "ok": reason, "text": reasontext})
            self.fingerprints.append(fingerprint)
        elif key == "IMPORT_PROBLEM":  # pragma: no cover
            try:
                reason, fingerprint = value.split()
            except Exception:
                reason = value
                fingerprint = "<unknown>"
            self.results.append({"fingerprint": fingerprint, "problem": reason, "text": self.problem_reason[reason]})
        elif key == "IMPORT_RES":
            import_res = value.split()
            for i, count in enumerate(self.counts):
                setattr(self, count, int(import_res[i]))
        elif key == "KEYEXPIRED":  # pragma: no cover
            self.results.append({"fingerprint": None, "problem": "0", "text": "Key expired"})
        elif key == "SIGEXPIRED":  # pragma: no cover
            self.results.append({"fingerprint": None, "problem": "0", "text": "Signature expired"})
        elif key == "FAILURE":  # pragma: no cover
            self.results.append({"fingerprint": None, "problem": "0", "text": "Other failure"})
        else:  # pragma: no cover
            logger.debug("message ignored: %s, %s", key, value)

    def summary(self):
        """
        Return a summary indicating how many keys were imported and how many were not imported.
        """
        result = []
        result.append("%d imported" % self.imported)
        if self.not_imported:  # pragma: no cover
            result.append("%d not imported" % self.not_imported)
        return ", ".join(result)
