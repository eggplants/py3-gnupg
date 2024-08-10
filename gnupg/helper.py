from __future__ import annotations

import logging
import sys
import threading
from io import BufferedReader, BufferedWriter, BytesIO, TextIOWrapper


def _get_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


logger = _get_logger(__name__)


def _make_binary_stream(s: str | bytes, encoding: str) -> BytesIO:
    if isinstance(s, str):
        s = s.encode(encoding)
    return BytesIO(s)


def _is_sequence(instance: tuple[str, str] | list[str] | str) -> bool:
    return isinstance(instance, (list, tuple, set, frozenset))


def _write_passphrase(stream: BufferedWriter, passphrase: str, encoding: str) -> None:
    passphrase = f"{passphrase}\n"
    passphrase = passphrase.encode(encoding)
    stream.write(passphrase)
    logger.debug("Wrote passphrase")


def _threaded_copy_data(
    instream: BufferedReader | BytesIO | TextIOWrapper,
    outstream: BufferedWriter,
    buffer_size: int,
) -> threading.Thread:
    def copy_data(instream, outstream, buffer_size) -> None:
        # Copy one stream to another
        assert buffer_size > 0
        sent = 0
        if hasattr(sys.stdin, "encoding"):
            enc = sys.stdin.encoding
        else:  # pragma: no cover
            enc = "ascii"
        while True:
            # See issue #39: read can fail when e.g. a text stream is provided
            # for what is actually a binary file
            try:
                data = instream.read(buffer_size)
            except Exception:  # pragma: no cover
                logger.warning("Exception occurred while reading", exc_info=1)
                break
            if not data:
                break
            sent += len(data)
            # logger.debug('sending chunk (%d): %r', sent, data[:256])
            try:
                outstream.write(data)
            except UnicodeError:  # pragma: no cover
                outstream.write(data.encode(enc))
            except Exception:  # pragma: no cover
                # Can sometimes get 'broken pipe' errors even when the data has all
                # been sent
                logger.exception("Error sending data")
                break
        try:
            outstream.close()
        except OSError:  # pragma: no cover
            logger.warning("Exception occurred while closing: ignored", exc_info=1)
        logger.debug("closed output, %d bytes sent", sent)

    assert buffer_size > 0
    wr = threading.Thread(target=copy_data, args=(instream, outstream, buffer_size))
    wr.daemon = True
    logger.debug("data copier: %r, %r, %r", wr, instream, outstream)
    wr.start()
    return wr
