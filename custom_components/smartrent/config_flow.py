"""Config flow to configure the SmartRent integration."""

import logging
from typing import Any, Mapping, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_TOKEN, CONF_USERNAME
from homeassistant.helpers import aiohttp_client
from smartrent import async_login
from smartrent.utils import InvalidAuthError

from .const import CONF_TOTP_SECRET, DOMAIN
from .totp import make_totp

_LOGGER = logging.getLogger(__name__)

SMARTRENT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_TOKEN): str,
        vol.Optional(CONF_TOTP_SECRET): str,
    }
)


class SmartRentFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore
    """Handle a SmartRent config flow."""

    async def _show_form(self, step_id="", errors=None):
        """Show the form to the user."""
        return self.async_show_form(
            step_id=step_id, data_schema=SMARTRENT_SCHEMA, errors=errors or {}
        )

    async def _check_creds_input(
        self, user_input: Mapping[str, Any]
    ) -> Optional[dict[str, str]]:
        """Check to see if provided creds are accepted by SmartRent.

        When a TOTP secret is supplied we generate the code here rather than
        making the user type one, which is the whole point of storing the seed:
        every later login can do the same without a human.
        """
        session = aiohttp_client.async_get_clientsession(self.hass)
        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]
        tfa_token = user_input.get(CONF_TOKEN)

        try:
            totp = make_totp(user_input.get(CONF_TOTP_SECRET))
        except ValueError:
            return {CONF_TOTP_SECRET: "invalid_totp_secret"}
        if totp is not None:
            tfa_token = totp.now()

        try:
            await async_login(username, password, session, tfa_token=tfa_token)
        except InvalidAuthError as exc:
            _LOGGER.error(f"Invalid auth: {exc}")
            return {"base": "invalid_auth"}
        except EOFError as exc:
            _LOGGER.error(f"EOFError: {exc}")
            return {"base": "tfa_not_provided"}

        return {}

    async def async_step_import(self, import_config):
        """Import a config entry from configuration.yaml."""
        return await self.async_step_user(import_config)

    async def async_step_reauth(self, user_input=None):
        """Handle re-authentication."""
        if not user_input:
            _LOGGER.info("no user input. showing reauth form")
            return await self._show_form(step_id="reauth")

        if errors := await self._check_creds_input(user_input):
            return await self._show_form(step_id="reauth", errors=errors)

        if entry := await self.async_set_unique_id(self.unique_id):
            # Keep a previously stored TOTP secret when the field is left blank,
            # and drop the old refresh token so the next setup logs in cleanly.
            data = {**entry.data, **user_input}
            if not user_input.get(CONF_TOTP_SECRET):
                data.pop(CONF_TOTP_SECRET, None)
                if entry.data.get(CONF_TOTP_SECRET):
                    data[CONF_TOTP_SECRET] = entry.data[CONF_TOTP_SECRET]
            self.hass.config_entries.async_update_entry(entry, data=data)
            self.hass.async_create_task(
                self.hass.config_entries.async_reload(entry.entry_id)
            )
            return self.async_abort(reason="reauth_successful")

    async def async_step_user(self, user_input=None):
        """Handle the start of the config flow."""
        if not user_input:
            _LOGGER.info("no user input. showing user form")
            return await self._show_form(step_id="user")

        await self.async_set_unique_id(user_input[CONF_USERNAME])
        self._abort_if_unique_id_configured()

        if errors := await self._check_creds_input(user_input=user_input):
            return await self._show_form(step_id="user", errors=errors)

        _LOGGER.info("created entry!")
        return self.async_create_entry(title=user_input[CONF_USERNAME], data=user_input)
