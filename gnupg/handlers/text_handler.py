from __future__ import annotations


class TextHandler:

    def _as_text(self) -> str:
        return self.data.decode(self.gpg.encoding, self.gpg.decode_errors)

    __str__ = _as_text
