"""SmartRent integration for Home Assistant, with unattended TOTP re-authentication.

Upstream stores the one-time 2FA code the user typed and replays it on every
start, which SmartRent rejects ("Invalid code"), so every restart needs a human.
Two changes fix that:

* the rotating refresh token is persisted and restored, so the normal path never
  touches 2FA at all (this part comes from upstream PR #50); and
* when the refresh token IS rejected, the 2FA code is derived locally from the
  TOTP secret, so recovery needs no human either.
"""

import logging

from aiohttp.client_exceptions import ClientConnectorError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from smartrent import async_login
from smartrent.api import API
from smartrent.utils import InvalidAuthError

from .const import (
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_TOKEN,
    CONF_TOTP_SECRET,
    CONF_USERNAME,
    DOMAIN,
    PLATFORMS,
    STARTUP_MESSAGE,
)
from .totp import async_fresh_code, make_totp

_LOGGER: logging.Logger = logging.getLogger(__package__)


def _install_auth_hooks(hass: HomeAssistant, entry: ConfigEntry, api: API, totp) -> None:
    """Wrap the client's token refresh to supply fresh codes and persist rotations.

    Two things have to happen around every call to ``_async_refresh_token``:

    1. Persist the rotated refresh token immediately. smartrent-py rotates it on
       every refresh (websocket reconnects, retries) and the old one is
       invalidated server-side, so deferring the write to ``async_unload_entry``
       would leave a stale token on disk after a crash or power cut. This Pi has
       already lost power once, so that is not hypothetical.

    2. Recover when the refresh token is rejected. smartrent-py's own fallback is
       broken for 2FA accounts: in the ``if self._refresh_token:`` branch it
       retries via ``_async_refresh_tokens_via_email()`` but never handles the
       ``tfa_api_token`` that comes back, so it raises KeyError on
       ``response["access_token"]``. We clear the dead token and redo a clean
       full login with a freshly generated code instead.
    """
    client = api.client
    original_refresh = client._async_refresh_token

    def _persist_rotation() -> None:
        new_token = client._refresh_token
        if new_token and new_token != entry.data.get(CONF_REFRESH_TOKEN):
            # No update listener is registered for this entry, so this stores the
            # token without triggering a reload (which would recurse into setup).
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, CONF_REFRESH_TOKEN: new_token}
            )
            _LOGGER.debug("Persisted rotated refresh token")

    async def _refresh() -> None:
        if totp is not None:
            client._tfa_token = await async_fresh_code(totp)
        try:
            await original_refresh()
        except (InvalidAuthError, KeyError):
            if totp is None:
                raise
            _LOGGER.info(
                "Refresh token rejected; re-authenticating with a locally "
                "generated TOTP code"
            )
            burned = client._tfa_token
            client._refresh_token = None
            client._token_exp_time = None
            client._tfa_token = await async_fresh_code(totp, avoid=burned)
            await original_refresh()
        _persist_rotation()

    client._async_refresh_token = _refresh


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up this integration using UI."""
    if hass.data.get(DOMAIN) is None:
        hass.data.setdefault(DOMAIN, {})
        _LOGGER.info(STARTUP_MESSAGE)

    username = entry.data.get(CONF_USERNAME)
    password = entry.data.get(CONF_PASSWORD)
    stored_refresh_token = entry.data.get(CONF_REFRESH_TOKEN)

    try:
        totp = make_totp(entry.data.get(CONF_TOTP_SECRET))
    except ValueError as exception:
        raise ConfigEntryAuthFailed(
            "Stored TOTP secret is not valid base32. Please reconfigure."
        ) from exception

    # A locally generated code always beats the stale one saved at setup time.
    tfa_token = (
        await async_fresh_code(totp) if totp is not None else entry.data.get(CONF_TOKEN)
    )

    session = async_get_clientsession(hass)
    try:
        if stored_refresh_token:
            try:
                api = API(username, password, session, tfa_token=tfa_token)
                api.client._refresh_token = stored_refresh_token
                await api.async_fetch_devices()
                _LOGGER.info("Rehydrated auth using stored refresh token")
            except (InvalidAuthError, KeyError):
                _LOGGER.warning(
                    "Stored refresh token rejected. Falling back to full login."
                )
                api = await async_login(
                    username, password, session, tfa_token=tfa_token
                )
        else:
            api = await async_login(username, password, session, tfa_token=tfa_token)
    except InvalidAuthError as exception:
        raise ConfigEntryAuthFailed("Credentials expired!") from exception
    except ClientConnectorError as exception:
        raise ConfigEntryNotReady from exception
    except EOFError as exception:
        raise ConfigEntryAuthFailed("TFA not supplied. Please Reauth!") from exception

    _install_auth_hooks(hass, entry, api, totp)

    hass.data[DOMAIN][entry.entry_id] = api

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Handle removal of an entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    api: API | None = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if api:
        for device in api.get_device_list():
            device.stop_updater()

    return unloaded
