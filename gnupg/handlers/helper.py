from __future__ import annotations

from types import MappingProxyType
from typing import Any

_INVALID_KEY_REASONS = MappingProxyType(
    {
        0: "no specific reason given",
        1: "not found",
        2: "ambiguous specification",
        3: "wrong key usage",
        4: "key revoked",
        5: "key expired",
        6: "no crl known",
        7: "crl too old",
        8: "policy mismatch",
        9: "not a secret key",
        10: "key not trusted",
        11: "missing certificate",
        12: "missing issuer certificate",
        13: "key disabled",
        14: "syntax error in specification",
    },
)


def _determine_invalid_recipient_or_signer(s: str) -> str:  # pragma: no cover
    parts = s.split()
    if len(parts) >= 2:  # noqa: PLR2004
        code, ident = parts[:2]
    else:
        code = parts[0]
        ident = "<no ident>"
    unexpected = f"unexpected return code {code!r}"
    try:
        key = int(code)
        result = _INVALID_KEY_REASONS.get(key, unexpected)
    except ValueError:
        result = unexpected
    return f"{result}:{ident}"


def _set_fields(target: dict[Any, Any], fieldnames: list[str], args: list[str]) -> None:
    for i, var in enumerate(fieldnames):
        if i < len(args):
            target[var] = args[i]
        else:
            target[var] = "unavailable"
