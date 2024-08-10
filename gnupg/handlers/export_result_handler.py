from __future__ import annotations

from .gen_key_handler import GenKeyHandler


class ExportResultHandler(GenKeyHandler):
    """
    This class handles status messages during key export.
    """

    # For now, just use an existing class to base it on - if needed, we
    # can override handle_status for more specific message handling.

    def handle_status(self, key, value) -> None:
        if key in ("EXPORTED", "EXPORT_RES"):
            pass
        else:
            super().handle_status(key, value)
