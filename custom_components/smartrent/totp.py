"""Local TOTP generation for SmartRent two-factor login.

SmartRent's 2FA is TOTP (RFC 6238), so the one-time code can be derived locally
from the shared secret instead of being typed in by a human. That is what lets
Home Assistant re-authenticate unattended after a restart or a power cut.

Keep this module free of Home Assistant imports so it stays unit-testable on its
own -- run `python3 totp.py` for the self-check.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from typing import Optional

import pyotp

# A TOTP step is 30s. A code is single-use server-side, so when a login attempt
# burns one we must wait for the next window rather than replay it.
_STEP_SECONDS = 30
_MAX_WAIT_SECONDS = _STEP_SECONDS + 5


def normalize_secret(raw: Optional[str]) -> Optional[str]:
    """Return a base32 secret usable by pyotp, or None if there is no secret.

    Authenticator apps present the seed with spaces and in mixed case, and some
    export it without the trailing '=' padding. Accept all of those shapes.
    Raises ValueError if the value is present but not valid base32.
    """
    if raw is None:
        return None
    cleaned = "".join(raw.split()).upper().replace("-", "")
    if not cleaned:
        return None
    # base64.b32decode wants the length to be a multiple of 8.
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError("TOTP secret is not valid base32") from err
    return padded


def make_totp(raw_secret: Optional[str]) -> Optional[pyotp.TOTP]:
    """Build a TOTP generator, or None when no secret is configured."""
    secret = normalize_secret(raw_secret)
    if secret is None:
        return None
    return pyotp.TOTP(secret)


async def async_fresh_code(
    totp: pyotp.TOTP,
    avoid: Optional[str] = None,
    sleep=asyncio.sleep,
) -> str:
    """Return a current TOTP code, waiting out the window if it equals `avoid`.

    SmartRent rejects a code that has already been consumed, so a retry inside
    the same 30s step has to wait for the next one. Bounded so a clock problem
    can never hang setup forever.
    """
    code = totp.now()
    if avoid is None or code != avoid:
        return code
    waited = 0
    while waited < _MAX_WAIT_SECONDS:
        await sleep(1)
        waited += 1
        code = totp.now()
        if code != avoid:
            return code
    # Give the caller the current code anyway; a rejection is better than a hang.
    return code


def _self_check() -> None:
    """Minimal assertions covering the parsing and the wait-for-next-window path."""
    # Accepts the shapes an authenticator app actually hands you.
    assert normalize_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"
    assert normalize_secret("jbswy3dp ehpk3pxp") == "JBSWY3DPEHPK3PXP"
    assert normalize_secret("JBSWY3DPEHPK3PX") == "JBSWY3DPEHPK3PX="  # padded
    assert normalize_secret(None) is None
    assert normalize_secret("   ") is None

    for bad in ("not-base32!", "18890"):
        try:
            normalize_secret(bad)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected ValueError for {bad!r}")

    totp = make_totp("JBSWY3DPEHPK3PXP")
    assert totp is not None
    code = totp.now()
    assert len(code) == 6 and code.isdigit()
    assert make_totp(None) is None

    # A code that is not the current one comes back immediately, no sleeping.
    async def _no_sleep(_):  # pragma: no cover - must never run
        raise AssertionError("should not have waited")

    assert asyncio.run(async_fresh_code(totp, avoid="000000", sleep=_no_sleep)) == code

    # When the current code IS the burned one, it waits and then returns.
    slept = []

    async def _fake_sleep(seconds):
        slept.append(seconds)
        if len(slept) == 3:
            totp.now = lambda: "999999"  # type: ignore[method-assign]

    got = asyncio.run(async_fresh_code(totp, avoid=code, sleep=_fake_sleep))
    assert got == "999999", got
    assert len(slept) == 3, slept

    print("totp.py self-check OK")


if __name__ == "__main__":
    _self_check()
