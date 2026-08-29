# SmartRent for Home Assistant — unattended TOTP authentication

A private fork of [ZacheryThomas/homeassistant-smartrent][upstream] that stops SmartRent
asking for a two-factor code every single time Home Assistant restarts.

## The problem

Upstream stores the one-time 2FA code you typed during setup and replays it verbatim on
every start. A one-time code is single-use, so SmartRent rejects it:

```
Config entry '<you>' for smartrent integration could not authenticate: Credentials expired!
Invalid auth: Token not retrieved! [{'code': 'invalid', 'description': 'Invalid code'}]
```

The config entry drops to `setup_error`, a reauth flow opens, and your locks go
`unavailable` until a human types a fresh code. Every restart, every update, every power cut.

## What this fork changes

**1. The refresh token is persisted and restored** (from upstream PR #50 by @abipalli).
`smartrent-py` skips the 2FA branch entirely when `_refresh_token` is set, so the normal
startup path never touches two-factor at all. The token rotates on every refresh and the
old one is invalidated server-side, so it is written back immediately rather than at
unload — a crash or power cut would otherwise leave an invalidated token on disk.

**2. The 2FA code is generated locally from the TOTP secret.** SmartRent's two-factor is
TOTP (RFC 6238), so the code can be derived from the shared secret. When the refresh token
is ever rejected, Home Assistant re-authenticates on its own instead of waiting for you.

**3. It works around a `smartrent-py` bug.** In `_async_refresh_token`, the
`if self._refresh_token:` branch falls back to `_async_refresh_tokens_via_email()` but
never handles the `tfa_api_token` that a 2FA account gets back — so it raises `KeyError`
on `response["access_token"]`. This fork clears the dead token and redoes a clean full
login with a freshly generated code.

Because a TOTP code is single-use, a retry inside the same 30-second window waits for the
next one rather than replaying a burned code.

## Setup

Add this repository to HACS as a custom repository (category: Integration), download it,
restart Home Assistant, then add the integration:

| Field | Value |
|---|---|
| Email | your SmartRent login |
| Password | your SmartRent password |
| 2fa Code | **leave blank** when using a secret |
| Authenticator secret key | the TOTP seed from your authenticator app |

The seed is the base32 string behind the QR code when you set up your authenticator —
spaces, lowercase and missing `=` padding are all accepted.

## Security note

The TOTP secret is stored in `.storage/core.config_entries` in plaintext, next to the
password. Anyone holding that file — or a backup of it, or the SD card — has both factors,
so for this account two-factor becomes effectively single-factor on this machine. If that
account opens a door, weigh that before using it. Leave the field blank and this fork still
gives you change 1, which removes the restart prompt on its own.

## Credit

Upstream is [ZacheryThomas/homeassistant-smartrent][upstream] (MIT); the refresh-token
persistence is [PR #50][pr50] by @abipalli. Everything here inherits that MIT license.

[upstream]: https://github.com/ZacheryThomas/homeassistant-smartrent
[pr50]: https://github.com/ZacheryThomas/homeassistant-smartrent/pull/50
