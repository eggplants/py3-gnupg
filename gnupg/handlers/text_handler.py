class TextHandler:

    def _as_text(self):
        return self.data.decode(self.gpg.encoding, self.gpg.decode_errors)

    __str__ = _as_text
