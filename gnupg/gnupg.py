from __future__ import annotations

import codecs
import logging
import os
import re
import socket
import threading
from io import BufferedReader, BufferedWriter, BytesIO, TextIOWrapper
from pathlib import Path
from subprocess import PIPE, Popen
from types import MappingProxyType
from typing import TYPE_CHECKING

from .handlers import (
    AddSubkeyHandler,
    AutoLocateKeyHandler,
    CryptHandler,
    DeleteResultHandler,
    ExportResultHandler,
    GenKeyHandler,
    ImportResultHandler,
    ListKeysHandler,
    ScanKeysHandler,
    SearchKeysHandler,
    SendResultHandler,
    SignHandler,
    TrustResultHandler,
    VerifyHandler,
)
from .helper import _get_logger, _is_sequence, _make_binary_stream, _threaded_copy_data, _write_passphrase

if TYPE_CHECKING:
    from gnupg.handlers.status_handler import StatusHandler

VERSION_RE = re.compile(r"^cfg:version:(\d+(\.\d+)*)".encode("ascii"))
HEX_DIGITS_RE = re.compile(r"[0-9a-f]+$", re.IGNORECASE)
PUBLIC_KEY_RE = re.compile(r"gpg: public key is (\w+)")

STARTUPINFO = None
if os.name == "nt":  # pragma: no cover
    from subprocess import STARTF_USESHOWWINDOW, STARTUPINFO, SW_HIDE

logger = _get_logger(__name__)

# See gh-196: Logging could show sensitive data. It also produces some voluminous
# output. Hence, split into two tiers - stuff that's always logged, and stuff that's
# only logged if log_everything is True. (This is set by the test script.)
#
# For now, only debug logging of chunks falls into the optionally-logged category.
log_everything = False


class GPG:
    """
    This class provides a high-level programmatic interface for `gpg`.
    """

    error_map = None

    decode_errors = "strict"

    buffer_size = 16384  # override in instance if needed

    result_map = MappingProxyType(
        {
            "crypt": CryptHandler,
            "delete": DeleteResultHandler,
            "generate": GenKeyHandler,
            "addSubkey": AddSubkeyHandler,
            "import": ImportResultHandler,
            "send": SendResultHandler,
            "list": ListKeysHandler,
            "scan": ScanKeysHandler,
            "search": SearchKeysHandler,
            "sign": SignHandler,
            "trust": TrustResultHandler,
            "verify": VerifyHandler,
            "export": ExportResultHandler,
            "auto-locate-key": AutoLocateKeyHandler,
        },
    )
    "A map of GPG operations to result object types."

    def __init__(  # noqa: PLR0913
        self,
        *,
        gpgbinary: str = "gpg",
        gnupghome: str | None = None,
        verbose: bool = False,
        use_agent: bool = False,
        keyring: str | None = None,
        options: None = None,
        secret_keyring: None = None,
        env: None = None,
    ) -> None:
        """Initialize a GPG process wrapper.

        Args:
            gpgbinary (str): A pathname for the GPG binary to use.

            gnupghome (str): A pathname to where we can find the public and private keyrings. The default is
                             whatever `gpg` defaults to.

            keyring (str|list): The name of alternative keyring file to use, or a list of such keyring files. If
                                specified, the default keyring is not used.

            options (list): A list of additional options to pass to the GPG binary.

            secret_keyring (str|list): The name of an alternative secret keyring file to use, or a list of such
                                       keyring files.

            env (dict): A dict of environment variables to be used for the GPG subprocess.
        """
        self.gpgbinary = gpgbinary
        self.gnupghome = None if not gnupghome else Path(gnupghome)
        self.env = env
        # issue 112: fail if the specified value isn't a directory
        if self.gnupghome and not self.gnupghome.is_dir():
            msg = f"gnupghome should be a directory (it isn't): {self.gnupghome}"
            raise ValueError(msg)
        if keyring:
            # Allow passing a string or another iterable. Make it uniformly
            # a list of keyring filenames
            if isinstance(keyring, str):
                keyring = [keyring]
        self.keyring = keyring
        if secret_keyring:  # pragma: no cover
            # Allow passing a string or another iterable. Make it uniformly
            # a list of keyring filenames
            if isinstance(secret_keyring, str):
                secret_keyring = [secret_keyring]
        self.secret_keyring = secret_keyring
        self.verbose = verbose
        self.use_agent = use_agent
        if isinstance(options, str):  # pragma: no cover
            options = [options]
        self.options = options
        self.on_data = None  # or a callable - will be called with data chunks
        # Changed in 0.3.7 to use Latin-1 encoding rather than
        # locale.getpreferredencoding falling back to sys.stdin.encoding
        # falling back to utf-8, because gpg itself uses latin-1 as the default
        # encoding.
        self.encoding = "latin-1"
        if self.gnupghome and not self.gnupghome.is_dir():  # pragma: no cover
            self.gnupghome.mkdir(mode=0o700, parents=True)
        try:
            p = self._open_subprocess(["--list-config", "--with-colons"])
        except OSError:
            msg = f"Unable to run gpg ({self.gpgbinary}) - it may not be available."
            logger.exception(msg)
            raise OSError(msg)
        result = self.result_map["verify"](self)  # any result will do for this
        self._collect_output(p, result, stdin=p.stdin)
        if p.returncode != 0:  # pragma: no cover
            msg = f"Error invoking gpg: {p.returncode}: {result.stderr}"
            raise ValueError(msg)
        m = VERSION_RE.match(result.data)
        if not m:  # pragma: no cover
            self.version = None
        else:
            dot = ".".encode("ascii")
            self.version = tuple([int(s) for s in m.groups()[0].split(dot)])

        # See issue #97. It seems gpg allow duplicate keys in keyrings, so we
        # can't be too strict.
        self.check_fingerprint_collisions = False

    def make_args(self, args: list[str], passphrase: bool) -> list[str]:
        """
        Make a list of command line elements for GPG. The value of ``args``
        will be appended. The ``passphrase`` argument needs to be True if
        a passphrase will be sent to `gpg`, else False.

        Args:
            args (list[str]): A list of arguments.
            passphrase (str): The passphrase to use.
        """
        cmd = [self.gpgbinary, "--status-fd", "2", "--no-tty", "--no-verbose"]
        if "DEBUG_IPC" in os.environ:  # pragma: no cover
            cmd.extend(["--debug", "ipc"])
        if passphrase and hasattr(self, "version") and self.version >= (2, 1):
            cmd[1:1] = ["--pinentry-mode", "loopback"]
        cmd.extend(["--fixed-list-mode", "--batch", "--with-colons"])
        if self.gnupghome:
            cmd.extend(["--homedir", str(self.gnupghome)])
        if self.keyring:
            cmd.append("--no-default-keyring")
            for fn in self.keyring:
                cmd.extend(["--keyring", fn])
        if self.secret_keyring:  # pragma: no cover
            for fn in self.secret_keyring:
                cmd.extend(["--secret-keyring", fn])
        if passphrase:
            cmd.extend(["--passphrase-fd", "0"])
        if self.use_agent:  # pragma: no cover
            cmd.append("--use-agent")
        if self.options:
            cmd.extend(self.options)
        cmd.extend(args)
        return cmd

    def _open_subprocess(self, args: list[str], passphrase: bool = False) -> Popen:
        # Internal method: open a pipe to a GPG subprocess and return
        # the file objects for communicating with it.

        from subprocess import list2cmdline as debug_print

        cmd = self.make_args(args, passphrase)
        if self.verbose:  # pragma: no cover
            pass
        if not STARTUPINFO:
            si = None
        else:  # pragma: no cover
            si = STARTUPINFO()
            si.dwFlags = STARTF_USESHOWWINDOW
            si.wShowWindow = SW_HIDE
        result = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE, startupinfo=si, env=self.env)
        logger.debug("%s: %s", result.pid, debug_print(cmd))
        return result

    def _read_response(self, stream, result) -> None:
        # Internal method: reads all the stderr output from GPG, taking notice
        # only of lines that begin with the magic [GNUPG:] prefix.
        #
        # Calls methods on the response object for each valid token found,
        # with the arg being the remainder of the status line.
        lines = []
        while True:
            line = stream.readline()
            if len(line) == 0:
                break
            lines.append(line)
            line = line.rstrip()
            if self.verbose:  # pragma: no cover
                pass
            logger.debug("%s", line)
            if line[0:9] == "[GNUPG:] ":
                # Chop off the prefix
                line = line[9:]
                L = line.split(None, 1)
                keyword = L[0]
                value = L[1] if len(L) > 1 else ""
                result.handle_status(keyword, value)
        result.stderr = "".join(lines)

    def _read_data(self, stream, result, on_data=None, buffer_size=1024) -> None:
        # Read the contents of the file from GPG's stdout
        assert buffer_size > 0
        chunks = []
        while True:
            data = stream.read(buffer_size)
            if len(data) == 0:
                if on_data:
                    on_data(data)
                break
            if log_everything:
                logger.debug(f"chunk: {data[:256]!r}")
            append = True
            if on_data:
                append = on_data(data) is not False
            if append:
                chunks.append(data)
        # Join using b'' or '', as appropriate
        result.data = type(data)().join(chunks)

    def _collect_output(
        self,
        process: Popen,
        result: StatusHandler,
        writer: threading.Thread | None = None,
        stdin: BufferedWriter | None = None,
    ) -> int:
        """
        Drain the subprocesses output streams, writing the collected output to the result. If a writer thread (writing
        to the subprocess) is given, make sure it's joined before returning. If a stdin stream is given, close it
        before returning.
        """
        stderr = codecs.getreader(self.encoding)(process.stderr)
        rr = threading.Thread(target=self._read_response, args=(stderr, result))
        rr.daemon = True
        logger.debug("stderr reader: %r", rr)
        rr.start()

        stdout = process.stdout
        dr = threading.Thread(target=self._read_data, args=(stdout, result, self.on_data, self.buffer_size))
        dr.daemon = True
        logger.debug("stdout reader: %r", dr)
        dr.start()

        dr.join()
        rr.join()
        if writer is not None:
            writer.join(0.01)
        process.wait()
        result.returncode = rc = process.returncode
        if rc != 0:
            logger.warning("gpg returned a non-zero error code: %d", rc)
        if stdin is not None:
            try:
                stdin.close()
            except OSError:  # pragma: no cover
                pass
        stderr.close()
        stdout.close()
        return rc

    def is_valid_file(self, fileobj: str | bytes | BufferedReader | TextIOWrapper | BytesIO) -> bool:
        """
        A simplistic check for a file-like object.

        Args:
            fileobj (object): The object to test.
        Returns:
            bool: ``True`` if it's a file-like object, else ``False``.
        """
        return hasattr(fileobj, "read")

    def _get_fileobj(
        self,
        fileobj_or_path: str | bytes | BufferedReader | TextIOWrapper | BytesIO,
    ) -> BufferedReader | BytesIO | TextIOWrapper:
        if self.is_valid_file(fileobj_or_path):
            result = fileobj_or_path
        elif not isinstance(fileobj_or_path, str):
            msg = f"Not a valid file or path: {fileobj_or_path}"
            raise TypeError(msg)
        elif not os.path.exists(fileobj_or_path):
            msg = f"No such file: {fileobj_or_path}"
            raise ValueError(msg)
        else:
            result = open(fileobj_or_path, "rb")
        return result

    def _handle_io(
        self,
        args: list[str],
        fileobj_or_path: str | bytes | BufferedReader | TextIOWrapper | BytesIO,
        result: StatusHandler,
        passphrase: str | None = None,
        binary: bool = False,
    ) -> StatusHandler:
        "Handle a call to GPG - pass input data, collect output data"
        # Handle a basic data call - pass data to GPG, handle the output
        # including status information. Garbage In, Garbage Out :)
        fileobj = self._get_fileobj(fileobj_or_path)
        try:
            p = self._open_subprocess(args, passphrase is not None)
            if not binary:  # pragma: no cover
                stdin = codecs.getwriter(self.encoding)(p.stdin)
            else:
                stdin = p.stdin
            writer = None  # See issue #237
            if passphrase:
                _write_passphrase(stdin, passphrase, self.encoding)
            writer = _threaded_copy_data(fileobj, stdin, self.buffer_size)
            self._collect_output(p, result, writer, stdin)
            return result
        finally:
            if writer:
                writer.join(0.01)
            if fileobj is not fileobj_or_path:
                fileobj.close()

    #
    # SIGNATURE METHODS
    #

    def sign(self, message: bytes, **kwargs) -> SignHandler:
        """
        Sign a message. This method delegates most of the work to the `sign_file()` method.

        Args:
            message (str|bytes): The data to sign.
            kwargs (dict): Keyword arguments, which are passed to `sign_file()`:

                * keyid (str): The key id of the signer.

                * passphrase (str): The passphrase for the key.

                * clearsign (bool): Whether to use clear signing.

                * detach (bool): Whether to produce a detached signature.

                * binary (bool): Whether to produce a binary signature.

                * output (str): The path to write a detached signature to.

                * extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        f = _make_binary_stream(message, self.encoding)
        result = self.sign_file(f, **kwargs)
        f.close()
        return result

    def set_output_without_confirmation(self, args: list[str], output: str) -> None:
        """
        If writing to a file which exists, avoid a confirmation message by
        updating the *args* value in place to set the output path and avoid
        any cpmfirmation prompt.

        Args:
            args (list[str]): A list of arguments.
            output (str): The path to the outpur file.
        """
        if os.path.exists(output):
            # We need to avoid an overwrite confirmation message
            args.extend(["--yes"])
        args.extend(["--output", output])

    def is_valid_passphrase(self, passphrase: str) -> bool:
        """
        Confirm that the passphrase doesn't contain newline-type characters - it is passed in a pipe to `gpg`,
        and so not checking could lead to spoofing attacks by passing arbitrary text after passphrase and newline.

        Args:
            passphrase (str): The passphrase to test.

        Returns:
            bool: ``True`` if it's a valid passphrase, else ``False``.
        """
        return "\n" not in passphrase and "\r" not in passphrase and "\x00" not in passphrase

    def sign_file(
        self,
        fileobj_or_path: BufferedReader | BytesIO | str,
        keyid: str | None = None,
        passphrase: str | None = None,
        clearsign: bool = True,
        detach: bool = False,
        binary: bool = False,
        output: str | None = None,
        extra_args: None = None,
    ) -> SignHandler:
        """
        Sign data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): The file or file-like object to sign.

            keyid (str): The key id of the signer.

            passphrase (str): The passphrase for the key.

            clearsign (bool): Whether to use clear signing.

            detach (bool): Whether to produce a detached signature.

            binary (bool): Whether to produce a binary signature.

            output (str): The path to write a detached signature to.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            msg = "Invalid passphrase"
            raise ValueError(msg)
        logger.debug("sign_file: %s", fileobj_or_path)
        if binary:  # pragma: no cover
            args = ["-s"]
        else:
            args = ["-sa"]
        # You can't specify detach-sign and clearsign together: gpg ignores
        # the detach-sign in that case.
        if detach:
            args.append("--detach-sign")
        elif clearsign:
            args.append("--clearsign")
        if keyid:
            args.extend(["--default-key", keyid])
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)

        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map["sign"](self)
        # We could use _handle_io here except for the fact that if the
        # passphrase is bad, gpg bails and you can't write the message.
        fileobj = self._get_fileobj(fileobj_or_path)
        p = self._open_subprocess(args, passphrase is not None)
        try:
            stdin = p.stdin
            if passphrase:
                _write_passphrase(stdin, passphrase, self.encoding)
            writer = _threaded_copy_data(fileobj, stdin, self.buffer_size)
        except OSError:  # pragma: no cover
            logging.exception("error writing message")
            writer = None
        finally:
            if writer:
                writer.join(0.01)
            if fileobj is not fileobj_or_path:
                fileobj.close()
        self._collect_output(p, result, writer, stdin)
        return result

    def verify(self, data: bytes, **kwargs) -> VerifyHandler:
        """
        Verify the signature on the contents of the string *data*. This method delegates most of the work to
        `verify_file()`.

        Args:
            data (str|bytes): The data to verify.
            kwargs (dict): Keyword arguments, which are passed to `verify_file()`:

                * fileobj_or_path (str|file): A path to a signature, or a file-like object containing one.

                * data_filename (str): If the signature is a detached one, the path to the data that was signed.

                * close_file (bool): If a file-like object is passed in, whether to close it.

                * extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        f = _make_binary_stream(data, self.encoding)
        result = self.verify_file(f, **kwargs)
        f.close()
        return result

    def verify_file(
        self,
        fileobj_or_path: BytesIO | str,
        data_filename: str | None = None,
        close_file: bool = True,
        extra_args: None = None,
    ) -> VerifyHandler:
        """
        Verify a signature.

        Args:
            fileobj_or_path (str|file): A path to a signature, or a file-like object containing one.

            data_filename (str): If the signature is a detached one, the path to the data that was signed.

            close_file (bool): If a file-like object is passed in, whether to close it.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        logger.debug("verify_file: %r, %r", fileobj_or_path, data_filename)
        result = self.result_map["verify"](self)
        args = ["--verify"]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        if data_filename is None:
            self._handle_io(args, fileobj_or_path, result, binary=True)
        else:
            logger.debug("Handling detached verification")
            import tempfile

            fd, fn = tempfile.mkstemp(prefix="pygpg-")
            s = fileobj_or_path.read()
            if close_file:
                fileobj_or_path.close()
            logger.debug("Wrote to temp file: %r", s)
            os.write(fd, s)
            os.close(fd)
            args.append(fn)
            args.append(data_filename)
            try:
                p = self._open_subprocess(args)
                self._collect_output(p, result, stdin=p.stdin)
            finally:
                os.remove(fn)
        return result

    def verify_data(self, sig_filename: str, data: bytes, extra_args: None = None) -> VerifyHandler:
        """
        Verify the signature in sig_filename against data in memory

        Args:
            sig_filename (str): The path to a signature.

            data (str|bytes): The data to be verified.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        logger.debug("verify_data: %r, %r ...", sig_filename, data[:16])
        result = self.result_map["verify"](self)
        args = ["--verify"]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        args.extend([sig_filename, "-"])
        stream = BytesIO(data)
        self._handle_io(args, stream, result, binary=True)
        return result

    #
    # KEY MANAGEMENT
    #

    def import_keys(
        self,
        key_data: str | bytes,
        extra_args: None = None,
        passphrase: None = None,
    ) -> ImportResultHandler:
        """
        Import the key_data into our keyring.

        Args:
            key_data (str|bytes): The key data to import.

            passphrase (str): The passphrase to use.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        result = self.result_map["import"](self)
        logger.debug("import_keys: %r", key_data[:256])
        data = _make_binary_stream(key_data, self.encoding)
        args = ["--import"]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        self._handle_io(args, data, result, passphrase=passphrase, binary=True)
        logger.debug("import_keys result: %r", result.__dict__)
        data.close()
        return result

    def import_keys_file(self, key_path: str, **kwargs) -> ImportResultHandler:
        """
        Import the key data in key_path into our keyring.

        Args:
            key_path (str): A path to the key data to be imported.
        """
        with open(key_path, "rb") as f:
            return self.import_keys(f.read(), **kwargs)

    def recv_keys(self, keyserver: str, *keyids, **kwargs) -> ImportResultHandler:
        """
        Import one or more keys from a keyserver.

        Args:
            keyserver (str): The key server hostname.

            keyids (str): A list of key ids to receive.
        """
        result = self.result_map["import"](self)
        logger.debug("recv_keys: %r", keyids)
        data = _make_binary_stream("", self.encoding)
        args = ["--keyserver", keyserver]
        if "extra_args" in kwargs:  # pragma: no cover
            args.extend(kwargs["extra_args"])
        args.append("--recv-keys")
        args.extend(list(keyids))
        self._handle_io(args, data, result, binary=True)
        logger.debug("recv_keys result: %r", result.__dict__)
        data.close()
        return result

    # This function isn't exercised by tests, to avoid polluting external
    # key servers with test keys
    def send_keys(self, keyserver, *keyids, **kwargs):  # pragma: no cover
        """
        Send one or more keys to a keyserver.

        Args:
            keyserver (str): The key server hostname.

            keyids (list[str]): A list of key ids to send.
        """

        # Note: it's not practical to test this function without sending
        # arbitrary data to live keyservers.

        result = self.result_map["send"](self)
        logger.debug("send_keys: %r", keyids)
        data = _make_binary_stream("", self.encoding)
        args = ["--keyserver", keyserver]
        if "extra_args" in kwargs:
            args.extend(kwargs["extra_args"])
        args.append("--send-keys")
        args.extend(list(keyids))
        self._handle_io(args, data, result, binary=True)
        logger.debug("send_keys result: %r", result.__dict__)
        data.close()
        return result

    def delete_keys(
        self,
        fingerprints: str,
        secret: bool = False,
        passphrase: str | None = None,
        expect_passphrase: bool = True,
        exclamation_mode: bool = False,
    ) -> DeleteResultHandler:
        """
        Delete the indicated keys.

        Args:
            fingerprints (str|list[str]): The keys to delete.

            secret (bool): Whether to delete secret keys.

            passphrase (str): The passphrase to use.

            expect_passphrase (bool): Whether a passphrase is expected.

            exclamation_mode (bool): If specified, a `'!'` is appended to each fingerprint. This deletes only a subkey
                                     or an entire key, depending on what the fingerprint refers to.

        .. note:: Passphrases

           Since GnuPG 2.1, you can't delete secret keys without providing a passphrase. However, if you're expecting
           the passphrase to go to `gpg` via pinentry, you should specify expect_passphrase=False. (It's only checked
           for GnuPG >= 2.1).
        """
        if passphrase and not self.is_valid_passphrase(passphrase):  # pragma: no cover
            msg = "Invalid passphrase"
            raise ValueError(msg)
        which = "key"
        if secret:  # pragma: no cover
            if self.version >= (2, 1) and passphrase is None and expect_passphrase:
                msg = "For GnuPG >= 2.1, deleting secret keys needs a passphrase to be provided"
                raise ValueError(msg)
            which = "secret-key"
        if _is_sequence(fingerprints):  # pragma: no cover
            fingerprints = list(fingerprints)
        else:
            fingerprints = [fingerprints]

        if exclamation_mode:
            fingerprints = [f + "!" for f in fingerprints]

        args = [f"--delete-{which}"]
        if secret and self.version >= (2, 1):
            args.insert(0, "--yes")
        args.extend(fingerprints)
        result = self.result_map["delete"](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            # Need to send in a passphrase.
            f = _make_binary_stream("", self.encoding)
            try:
                self._handle_io(args, f, result, passphrase=passphrase, binary=True)
            finally:
                f.close()
        return result

    def export_keys(
        self,
        keyids: str | list[str],
        secret: bool = False,
        armor: bool = True,
        minimal: bool = False,
        passphrase: str | None = None,
        expect_passphrase: bool = True,
        output: None = None,
    ) -> str | bytes:
        """
        Export the indicated keys. A 'keyid' is anything `gpg` accepts.

        Args:
            keyids (str|list[str]): A single keyid or a list of them.

            secret (bool): Whether to export secret keys.

            armor (bool): Whether to ASCII-armor the output.

            minimal (bool): Whether to pass `--export-options export-minimal` to `gpg`.

            passphrase (str): The passphrase to use.

            expect_passphrase (bool): Whether a passphrase is expected.

            output (str): If specified, the path to write the exported key(s) to.

        .. note:: Passphrases

           Since GnuPG 2.1, you can't export secret keys without providing a passphrase. However, if you're expecting
           the passphrase to go to `gpg` via pinentry, you should specify expect_passphrase=False. (It's only checked
           for GnuPG >= 2.1).
        """
        if passphrase and not self.is_valid_passphrase(passphrase):  # pragma: no cover
            msg = "Invalid passphrase"
            raise ValueError(msg)
        which = ""
        if secret:
            which = "-secret-key"
            if self.version >= (2, 1) and passphrase is None and expect_passphrase:  # pragma: no cover
                msg = "For GnuPG >= 2.1, exporting secret keys needs a passphrase to be provided"
                raise ValueError(msg)
        keyids = list(keyids) if _is_sequence(keyids) else [keyids]
        args = [f"--export{which}"]
        if armor:
            args.append("--armor")
        if minimal:  # pragma: no cover
            args.extend(["--export-options", "export-minimal"])
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        args.extend(keyids)
        # gpg --export produces no status-fd output; stdout will be
        # empty in case of failure
        result = self.result_map["export"](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            # Need to send in a passphrase.
            f = _make_binary_stream("", self.encoding)
            try:
                self._handle_io(args, f, result, passphrase=passphrase, binary=True)
            finally:
                f.close()
        logger.debug("export_keys result[:100]: %r", result.data[:100])
        # Issue #49: Return bytes if armor not specified, else text
        result = result.data
        if armor:
            result = result.decode(self.encoding, self.decode_errors)
        return result

    def _decode_result(
        self,
        result: ListKeysHandler | ScanKeysHandler,
    ) -> ListKeysHandler | ScanKeysHandler:
        lines = result.data.decode(self.encoding, self.decode_errors).splitlines()
        valid_keywords = "pub uid sec fpr sub ssb sig grp".split()
        for line in lines:
            if self.verbose:  # pragma: no cover
                pass
            logger.debug("line: %r", line.rstrip())
            if not line:  # pragma: no cover
                break
            L = line.strip().split(":")
            if not L:  # pragma: no cover
                continue
            keyword = L[0]
            if keyword in valid_keywords:
                getattr(result, keyword)(L)
        return result

    def _get_list_output(self, p: Popen, kind: str) -> ListKeysHandler | ScanKeysHandler:
        # Get the response information
        result = self.result_map[kind](self)
        self._collect_output(p, result, stdin=p.stdin)
        return self._decode_result(result)

    def list_keys(
        self,
        secret: bool = False,
        keys: str | list[str] | None = None,
        sigs: bool = False,
    ) -> ListKeysHandler:
        """
        List the keys currently in the keyring.

        Args:
            secret (bool): Whether to list secret keys.

            keys (str|list[str]): A list of key ids to match.

            sigs (bool): Whether to include signature information.

        Returns:
            list[dict]: A list of dictionaries with key information.
        """

        which = "secret-keys" if secret else "sigs" if sigs else "keys"
        args = [f"--list-{which}", "--fingerprint", "--fingerprint"]  # get subkey FPs, too

        if self.version >= (2, 1):
            args.append("--with-keygrip")

        if keys:
            if isinstance(keys, str):
                keys = [keys]
            args.extend(keys)
        p = self._open_subprocess(args)
        return self._get_list_output(p, "list")

    def scan_keys(self, filename: str) -> ScanKeysHandler:
        """
        List details of an ascii armored or binary key file without first importing it to the local keyring.

        Args:
            filename (str): The path to the file containing the key(s).

        .. warning:: Warning:
            Care is needed. The function works on modern GnuPG by running:

                $ gpg --dry-run --import-options import-show --import filename

            On older versions, it does the *much* riskier:

                $ gpg --with-fingerprint --with-colons filename
        """
        if self.version >= (2, 1):
            args = ["--dry-run", "--import-options", "import-show", "--import"]
        else:
            logger.warning("Trying to list packets, but if the file is not a keyring, might accidentally decrypt")
            args = ["--with-fingerprint", "--with-colons", "--fixed-list-mode"]
        args.append(filename)
        p = self._open_subprocess(args)
        return self._get_list_output(p, "scan")

    def scan_keys_mem(self, key_data: str) -> ScanKeysHandler:
        """
        List details of an ascii armored or binary key without first importing it to the local keyring.

        Args:
            key_data (str|bytes): The key data to import.

        .. warning:: Warning:
            Care is needed. The function works on modern GnuPG by running:

                $ gpg --dry-run --import-options import-show --import filename

            On older versions, it does the *much* riskier:

                $ gpg --with-fingerprint --with-colons filename
        """
        result = self.result_map["scan"](self)
        logger.debug("scan_keys: %r", key_data[:256])
        data = _make_binary_stream(key_data, self.encoding)
        if self.version >= (2, 1):
            args = ["--dry-run", "--import-options", "import-show", "--import"]
        else:
            logger.warning("Trying to list packets, but if the file is not a keyring, might accidentally decrypt")
            args = ["--with-fingerprint", "--with-colons", "--fixed-list-mode"]
        self._handle_io(args, data, result, binary=True)
        logger.debug("scan_keys result: %r", result.__dict__)
        data.close()
        return self._decode_result(result)

    def search_keys(self, query, keyserver="pgp.mit.edu", extra_args=None):
        """
        search a keyserver by query (using the `--search-keys` option).

        Args:
            query(str): The query to use.

            keyserver (str): The key server hostname.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        query = query.strip()
        if HEX_DIGITS_RE.match(query):
            query = "0x" + query
        args = ["--fingerprint", "--keyserver", keyserver]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        args.extend(["--search-keys", query])
        p = self._open_subprocess(args)

        # Get the response information
        result = self.result_map["search"](self)
        self._collect_output(p, result, stdin=p.stdin)
        lines = result.data.decode(self.encoding, self.decode_errors).splitlines()
        valid_keywords = ["pub", "uid"]
        for line in lines:
            if self.verbose:  # pragma: no cover
                pass
            logger.debug("line: %r", line.rstrip())
            if not line:  # sometimes get blank lines on Windows
                continue
            L = line.strip().split(":")
            if not L:  # pragma: no cover
                continue
            keyword = L[0]
            if keyword in valid_keywords:
                getattr(result, keyword)(L)
        return result

    def auto_locate_key(self, email, mechanisms=None, **kwargs):
        """
        Auto locate a public key by `email`.

        Args:
            email (str): The email address to search for.
            mechanisms (list[str]): A list of mechanisms to use. Valid mechanisms can be found
            here https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
            under "--auto-key-locate". Default: ['wkd', 'ntds', 'ldap', 'cert', 'dane', 'local']
        """
        mechanisms = mechanisms or ["wkd", "ntds", "ldap", "cert", "dane", "local"]

        args = ["--auto-key-locate", ",".join(mechanisms), "--locate-keys", email]

        result = self.result_map["auto-locate-key"](self)

        if "extra_args" in kwargs:
            args.extend(kwargs["extra_args"])

        process = self._open_subprocess(args)
        self._collect_output(process, result, stdin=process.stdin)
        self._decode_result(result)
        return result

    def gen_key(self, input: str) -> GenKeyHandler:
        """
        Generate a key; you might use `gen_key_input()` to create the input.

        Args:
            input (str): The input to the key creation operation.
        """
        args = ["--gen-key"]
        result = self.result_map["generate"](self)
        f = _make_binary_stream(input, self.encoding)
        self._handle_io(args, f, result, binary=True)
        f.close()
        return result

    def gen_key_input(self, **kwargs) -> str:
        """
        Generate `--gen-key` input  (see `gpg` documentation in DETAILS).

        Args:
            kwargs (dict): A list of keyword arguments.
        Returns:
            str: A string suitable for passing to the `gen_key()` method.
        """

        parms = {}
        no_protection = kwargs.pop("no_protection", False)
        for key, val in list(kwargs.items()):
            key = key.replace("_", "-").title()
            if str(val).strip():  # skip empty strings
                parms[key] = val
        parms.setdefault("Key-Type", "RSA")
        if "key_curve" not in kwargs:
            parms.setdefault("Key-Length", 2048)
        parms.setdefault("Name-Real", "Autogenerated Key")
        logname = os.environ.get("LOGNAME") or os.environ.get("USERNAME") or "unspecified"
        hostname = socket.gethostname()
        parms.setdefault("Name-Email", "{}@{}".format(logname.replace(" ", "_"), hostname))
        out = "Key-Type: {}\n".format(parms.pop("Key-Type"))
        for key, val in list(parms.items()):
            out += f"{key}: {val}\n"
        if no_protection:  # pragma: no cover
            out += "%no-protection\n"
        out += "%commit\n"
        return out

        # Key-Type: RSA
        # Key-Length: 1024
        # Name-Real: ISdlink Server on %s
        # Name-Comment: Created by %s
        # Name-Email: isdlink@%s
        # Expire-Date: 0
        # %commit
        #
        #
        # Key-Type: DSA
        # Key-Length: 1024
        # Subkey-Type: ELG-E
        # Subkey-Length: 1024
        # Name-Real: Joe Tester
        # Name-Comment: with stupid passphrase
        # Name-Email: joe@foo.bar
        # Expire-Date: 0
        # Passphrase: abc
        # %pubring foo.pub
        # %secring foo.sec
        # %commit

    def add_subkey(
        self,
        master_key: str,
        master_passphrase: str | None = None,
        algorithm: str = "rsa",
        usage: str = "encrypt",
        expire: int = "-",
    ) -> AddSubkeyHandler:
        """
        Add subkeys to a master key,

        Args:
            master_key (str): The master key.

            master_passphrase (str): The passphrase for the master key.

            algorithm (str): The key algorithm to use.

            usage (str): The desired uses for the subkey.

            expire (str): The expiration date of the subkey.
        """
        if self.version[0] < 2:
            msg = "Not available in GnuPG 1.x"
            raise NotImplementedError(msg)
        if not master_key:  # pragma: no cover
            msg = "No master key fingerprint specified"
            raise ValueError(msg)

        if master_passphrase and not self.is_valid_passphrase(master_passphrase):  # pragma: no cover
            msg = "Invalid passphrase"
            raise ValueError(msg)

        args = ["--quick-add-key", master_key, algorithm, usage, str(expire)]

        result = self.result_map["addSubkey"](self)

        f = _make_binary_stream("", self.encoding)
        self._handle_io(args, f, result, passphrase=master_passphrase, binary=True)
        return result

    #
    # ENCRYPTION
    #

    def encrypt_file(
        self,
        fileobj_or_path: BytesIO | str,
        recipients: str | list[str] | tuple[str, str] | None,
        sign: str | None = None,
        always_trust: bool = False,
        passphrase: str | None = None,
        armor: bool = True,
        output: str | None = None,
        symmetric: bool | str = False,
        extra_args: list[str] | None = None,
    ) -> CryptHandler:
        """
        Encrypt data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or a file-like object containing the data to be encrypted.

            recipients (str|list): A key id of a recipient of the encrypted data, or a list of such key ids.

            sign (str): If specified, the key id of a signer to sign the encrypted data.

            always_trust (bool): Whether to always trust keys.

            passphrase (str): The passphrase to use for a signature.

            armor (bool): Whether to ASCII-armor the output.

            output (str): A path to write the encrypted output to.

            symmetric (bool): Whether to use symmetric encryption,

            extra_args (list[str]): A list of additional arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            msg = "Invalid passphrase"
            raise ValueError(msg)
        args = ["--encrypt"]
        if symmetric:
            # can't be False or None - could be True or a cipher algo value
            # such as AES256
            args = ["--symmetric"]
            if symmetric is not True:
                args.extend(["--cipher-algo", symmetric])
            # else use the default, currently CAST5
        else:
            if not recipients:
                msg = "No recipients specified with asymmetric encryption"
                raise ValueError(msg)
            if not _is_sequence(recipients):
                recipients = (recipients,)
            for recipient in recipients:
                args.extend(["--recipient", recipient])
        if armor:  # create ascii-armored output - False for binary output
            args.append("--armor")
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        if sign is True:  # pragma: no cover
            args.append("--sign")
        elif sign:  # pragma: no cover
            args.extend(["--sign", "--default-key", sign])
        if always_trust:  # pragma: no cover
            args.extend(["--trust-model", "always"])
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map["crypt"](self)
        self._handle_io(args, fileobj_or_path, result, passphrase=passphrase, binary=True)
        logger.debug("encrypt result[:100]: %r", result.data[:100])
        return result

    def encrypt(
        self,
        data: str | bytes,
        recipients: str | list[str] | tuple[str, str] | None,
        **kwargs,
    ) -> CryptHandler:
        """
        Encrypt the message contained in the string *data* for *recipients*. This method delegates most of the work to
        `encrypt_file()`.

        Args:
            data (str|bytes): The data to encrypt.

            recipients (str|list[str]): A key id of a recipient of the encrypted data, or a list of such key ids.

            kwargs (dict): Keyword arguments, which are passed to `encrypt_file()`:
                * sign (str): If specified, the key id of a signer to sign the encrypted data.

                * always_trust (bool): Whether to always trust keys.

                * passphrase (str): The passphrase to use for a signature.

                * armor (bool): Whether to ASCII-armor the output.

                * output (str): A path to write the encrypted output to.

                * symmetric (bool): Whether to use symmetric encryption,

                * extra_args (list[str]): A list of additional arguments to pass to `gpg`.
        """
        data = _make_binary_stream(data, self.encoding)
        result = self.encrypt_file(data, recipients, **kwargs)
        data.close()
        return result

    def decrypt(self, message: str, **kwargs) -> CryptHandler:
        """
        Decrypt the data in *message*. This method delegates most of the work to
        `decrypt_file()`.

        Args:
            message (str|bytes): The data to decrypt. A default key will be used for decryption.

            kwargs (dict): Keyword arguments, which are passed to `decrypt_file()`:

                * always_trust: Whether to always trust keys.

                * passphrase (str): The passphrase to use.

                * output (str): If specified, the path to write the decrypted data to.

                * extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        data = _make_binary_stream(message, self.encoding)
        result = self.decrypt_file(data, **kwargs)
        data.close()
        return result

    def decrypt_file(
        self,
        fileobj_or_path: str | bytes | BufferedReader | TextIOWrapper | BytesIO,
        always_trust: bool = False,
        passphrase: str | None = None,
        output: str | None = None,
        extra_args: None = None,
    ) -> CryptHandler:
        """
        Decrypt data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or a file-like object containing the data to be decrypted.

            always_trust: Whether to always trust keys.

            passphrase (str): The passphrase to use.

            output (str): If specified, the path to write the decrypted data to.

            extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            msg = "Invalid passphrase"
            raise ValueError(msg)
        args = ["--decrypt"]
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        if always_trust:  # pragma: no cover
            args.extend(["--trust-model", "always"])
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map["crypt"](self)
        self._handle_io(args, fileobj_or_path, result, passphrase, binary=True)
        # logger.debug('decrypt result[:100]: %r', result.data[:100])
        return result

    def get_recipients(self, message: str, **kwargs) -> list[str]:
        """Get the list of recipients for an encrypted message. This method delegates most of the work to
        `get_recipients_file()`.

        Args:
            message (str|bytes): The encrypted message.

            kwargs (dict): Keyword arguments, which are passed to `get_recipients_file()`:

                * extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        data = _make_binary_stream(message, self.encoding)
        result = self.get_recipients_file(data, **kwargs)
        data.close()
        return result

    def get_recipients_file(self, fileobj_or_path: BytesIO | str, extra_args: None = None) -> list[str]:
        """
        Get the list of recipients for an encrypted message in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or file-like object containing the encrypted data.

            extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        args = ["--decrypt", "--list-only", "-v"]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map["crypt"](self)
        self._handle_io(args, fileobj_or_path, result, binary=True)
        ids = []
        for m in PUBLIC_KEY_RE.finditer(result.stderr):
            ids.append(m.group(1))
        return ids

    def trust_keys(self, fingerprints: str | list[str], trustlevel: str) -> StatusHandler:
        """
        Set the trust level for one or more keys.

        Args:
            fingerprints (str|list[str]): A key id for which to set the trust level, or a list of such key ids.

            trustlevel (str): The trust level. This is one of the following.

                                  * ``'TRUST_EXPIRED'``
                                  * ``'TRUST_UNDEFINED'``
                                  * ``'TRUST_NEVER'``
                                  * ``'TRUST_MARGINAL'``
                                  * ``'TRUST_FULLY'``
                                  * ``'TRUST_ULTIMATE'``
        """
        levels = VerifyHandler.TRUST_LEVELS
        if trustlevel not in levels:
            poss = ", ".join(sorted(levels))
            msg = f'Invalid trust level: "{trustlevel}" (must be one of {poss})'
            raise ValueError(msg)
        trustlevel = levels[trustlevel] + 1
        import tempfile

        try:
            fd, fn = tempfile.mkstemp(prefix="pygpg-")
            if isinstance(fingerprints, str):
                fingerprints = [fingerprints]
            lines = [f"{f}:{trustlevel}:" for f in fingerprints]
            # The trailing newline is required!
            s = os.linesep.join(lines) + os.linesep
            logger.debug("writing ownertrust info: %s", s)
            os.write(fd, s.encode(self.encoding))
            os.close(fd)
            result = self.result_map["trust"](self)
            p = self._open_subprocess(["--import-ownertrust", fn])
            self._collect_output(p, result, stdin=p.stdin)
            if p.returncode != 0:
                raise ValueError("gpg returned an error - return code %d" % p.returncode)
        finally:
            Path(fn).unlink()
        return result
