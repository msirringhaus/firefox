/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use dbus::{
    arg::{IterAppend, RefArg, Variant},
    BusType, Connection, Error, Message,
};
use nserror::{
    nsresult, NS_ERROR_DOM_ABORT_ERR, NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_DOM_NOT_ALLOWED_ERR,
    NS_ERROR_DOM_NOT_SUPPORTED_ERR, NS_ERROR_DOM_SECURITY_ERR, NS_ERROR_DOM_WRONG_TYPE_ERR,
};
use std::collections::HashMap;

use crate::{register::RegisterResult, sign::SignResult};

pub(crate) struct DbusController {
    conn: Connection,
}

fn portal_to_nserror(e: Option<&str>) -> nsresult {
    match e {
        Some("xyz.iinuwa.credentials.AbortError") => NS_ERROR_DOM_ABORT_ERR,
        Some("xyz.iinuwa.credentials.ConstraintError") => NS_ERROR_DOM_NOT_ALLOWED_ERR,
        Some("xyz.iinuwa.credentials.InvalidStateError") => NS_ERROR_DOM_INVALID_STATE_ERR,
        Some("xyz.iinuwa.credentials.NotSupportedError") => NS_ERROR_DOM_NOT_SUPPORTED_ERR,
        Some("xyz.iinuwa.credentials.SecurityError") => NS_ERROR_DOM_SECURITY_ERR,
        Some("xyz.iinuwa.credentials.NotAllowedError") => NS_ERROR_DOM_NOT_ALLOWED_ERR,
        Some("xyz.iinuwa.credentials.TypeError") => NS_ERROR_DOM_WRONG_TYPE_ERR,
        _ => NS_ERROR_DOM_NOT_ALLOWED_ERR,
    }
}

impl DbusController {
    const SERVICE_NAME: &'static str = "xyz.iinuwa.credentialsd.Credentials";
    const PATH: &'static str = "/xyz/iinuwa/credentialsd/Credentials";
    const INTERFACE: &'static str = "xyz.iinuwa.credentialsd.Credentials1";
    const CREATE_CREDENTIAL_FUNCTION: &'static str = "CreateCredential";
    const GET_CREDENTIAL_FUNCTION: &'static str = "GetCredential";

    pub(crate) fn new() -> Result<Self, Error> {
        let conn = Connection::get_private(BusType::Session)?;
        Ok(Self { conn })
    }

    pub(crate) fn is_service_active(&self) -> bool {
        // Create a proxy for the D-Bus daemon itself.
        let proxy = self
            .conn
            .with_path("org.freedesktop.DBus", "/org/freedesktop/DBus", 5000);

        // First, check if the portal is already running, by calling the "NameHasOwner" method.
        let m = match proxy.method_call_with_args(
            &"org.freedesktop.DBus".into(),
            &"NameHasOwner".into(),
            |msg| {
                let mut i = IterAppend::new(msg);
                i.append(Self::SERVICE_NAME);
            },
        ) {
            Ok(m) => m,
            Err(e) => {
                log::info!("Failed to send NameHasOwner via D-Bus: {e:?}");
                return false;
            }
        };

        let has_owner: Option<bool> = m.get1();
        let is_running = has_owner.unwrap_or_default();

        if is_running {
            return true;
        }

        // If it's not running, check if it is activatable
        let m = match proxy.method_call_with_args(
            &"org.freedesktop.DBus".into(),
            &"ListActivatableNames".into(),
            |_| { /* Nothing to do */ },
        ) {
            Ok(m) => m,
            Err(e) => {
                log::info!("Failed to send ListActivatableNames via D-Bus: {e:?}");
                return false;
            }
        };

        let activatable_services: Option<Vec<String>> = m.get1();
        let services = activatable_services.unwrap_or_default();
        services.iter().any(|name| name == Self::SERVICE_NAME)
    }

    pub(crate) fn send_message(
        &self,
        function: &str,
        parent_window: &str,
        msg: HashMap<String, Variant<Box<dyn RefArg>>>,
    ) -> Result<Message, Error> {
        let m = Message::new_method_call(Self::SERVICE_NAME, Self::PATH, Self::INTERFACE, function)
            // I don't know why this method returns a string instead of a DBUS-Error...
            // Let's wrap it
            .map_err(|e| Error::new_custom("new_method_call", &e))?
            .append2(parent_window, msg);

        self.conn.send_with_reply_and_block(m, 300000)
    }

    pub(crate) fn send_create_credential(
        &self,
        parent_window: &str,
        msg: HashMap<String, Variant<Box<dyn RefArg>>>,
    ) -> Result<RegisterResult, nsresult> {
        let resp = self
            .send_message(Self::CREATE_CREDENTIAL_FUNCTION, parent_window, msg)
            .map_err(|e| {
                log::error!("Failed to send webauthn request via DBUS: {e:?}");
                portal_to_nserror(e.message())
            })?;
        RegisterResult::parse_from_dbus(resp).map_err(|e| {
            log::error!("Failed parse webauthn reply from XDG portal: {e:?}");
            NS_ERROR_DOM_INVALID_STATE_ERR
        })
    }

    pub(crate) fn send_get_credential(
        &self,
        parent_window: &str,
        msg: HashMap<String, Variant<Box<dyn RefArg>>>,
    ) -> Result<SignResult, nsresult> {
        let resp = self
            .send_message(Self::GET_CREDENTIAL_FUNCTION, parent_window, msg)
            .map_err(|e| {
                log::error!("Failed to send webauthn request via DBUS: {e:?}");
                portal_to_nserror(e.message())
            })?;
        SignResult::parse_from_dbus(resp).map_err(|e| {
            log::error!("Failed parse webauthn reply from XDG portal: {e:?}");
            NS_ERROR_DOM_NOT_ALLOWED_ERR
        })
    }
}
