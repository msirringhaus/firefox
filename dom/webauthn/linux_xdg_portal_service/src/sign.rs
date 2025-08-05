use base64::Engine;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD};
use dbus::arg::{ArgType, RefArg, Variant};
use dbus::Message;
use nserror::{
    nsresult, NS_ERROR_FAILURE, NS_ERROR_NOT_AVAILABLE, NS_ERROR_NOT_IMPLEMENTED, NS_OK,
};
use nsstring::{nsACString, nsAString, nsCString, nsString};
use serde_json::{Map, Value};
use std::collections::HashMap;
use thin_vec::ThinVec;
use xpcom::interfaces::{nsIWebAuthnSignPromise, nsIWebAuthnSignResult};
use xpcom::{xpcom_method, RefPtr};

// Flattened struct of this:
// let response = json!({
//     "clientDataJSON": URL_SAFE_NO_PAD.encode(self.client_data_json.as_bytes()),
//     "authenticatorData": URL_SAFE_NO_PAD.encode(&self.authenticator_data),
//     "signature": URL_SAFE_NO_PAD.encode(&self.signature),
//     "userHandle": self.user_handle.as_ref().map(|h| URL_SAFE_NO_PAD.encode(h))
// });
// let output = json!({
//     "id": id,
//     "rawId": id,
//     "authenticatorAttachment": self.attachment_modality,
//     "response": response,
//     "clientExtensionResults": self.extensions,
// });
//
#[derive(Debug, Clone)]
pub(crate) struct SignResult {
    pub(crate) credential_id: Option<Vec<u8>>,
    pub(crate) authenticator_attachment: Option<String>,
    pub(crate) client_data_json: Option<String>,
    pub(crate) authenticator_data: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
    pub(crate) user_handle: Option<Vec<u8>>,
    pub(crate) extensions: Option<SignExtensionsResult>,
}

#[derive(Debug, Clone)]
pub(crate) struct SignExtensionsResult {
    pub(crate) large_blob_value: Option<Vec<u8>>,
    pub(crate) large_blob_written: Option<bool>,
    pub(crate) prf_maybe: Option<bool>,
    pub(crate) prf_results_first: Option<Vec<u8>>,
    pub(crate) prf_results_second: Option<Vec<u8>>,
}

impl SignResult {
    pub(crate) fn parse_from_dbus(reply: Message) -> Result<Self, Box<dyn std::error::Error>> {
        // Extract the main dictionary `a{sv}` from the message.
        let mut iter = reply.iter_init();

        // dbus-rs is a bit of a mess with respect to parsing nested messages.
        // We have to iterate over the Dicts (and Dicts are Arrays with DictEntry-values)
        // and then parse first the key, and second the value, to be able to
        // re-parse the nested public_key-dict.
        let mut public_key_dict = None;
        let mut iter = iter.recurse(ArgType::Array).ok_or("Empty reply")?;
        // Loop through the key-value pairs of the main dictionary.
        while iter.arg_type() == ArgType::DictEntry {
            // To read a key-value pair, recurse into the DictEntry itself.
            let mut dict_entry_iter = iter
                .recurse(ArgType::DictEntry)
                .ok_or("Reply is not a dict")?;
            let key: String = dict_entry_iter.read()?;

            // Check the "type" field, if it is correct.
            if key == "type" {
                let mut dict_entry_iter = dict_entry_iter
                    .recurse(ArgType::Variant)
                    .ok_or("Dict value missing")?;
                let cred_type: String = dict_entry_iter.read()?;
                if cred_type != "public-key" {
                    return Err(format!("Invalid credential type: {}", cred_type).into());
                }
            } else if key == "public_key" {
                // The value is a Variant that wraps the target dictionary.
                // First, recurse into the Variant wrapper.
                let mut dict_entry_iter = dict_entry_iter
                    .recurse(ArgType::Variant)
                    .ok_or("Dict value missing")?;

                // Now the iterator is positioned at the start of the inner value.
                // We can now read the entire inner dictionary directly.
                let public_key: HashMap<String, Variant<Box<dyn RefArg>>> =
                    dict_entry_iter.read()?;

                public_key_dict = Some(public_key);
            }

            iter.next();
        }
        let public_key_dict = public_key_dict.ok_or("Missing public_key dict from response")?;

        // Extract and parse the response JSON string.
        let auth_response_str = public_key_dict
            .get("authentication_response_json")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'authentication_response_json'")?;

        let response_json: serde_json::Value = serde_json::from_str(auth_response_str)?;

        let credential_id = response_json["id"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        let authenticator_attachment = response_json["authenticatorAttachment"]
            .as_str()
            .map(String::from);

        let extensions =
            if let Some(extensions) = response_json["clientExtensionResults"].as_object() {
                // TODO
                Some(SignExtensionsResult {
                    large_blob_value: None,
                    large_blob_written: None,
                    prf_maybe: None,
                    prf_results_first: None,
                    prf_results_second: None,
                })
            } else {
                None
            };

        let client_data_json = response_json["response"]["clientDataJSON"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten()
            .map(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let authenticator_data = response_json["response"]["authenticatorData"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        let signature = response_json["response"]["signature"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        let user_handle = response_json["response"]["userHandle"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        Ok(Self {
            client_data_json,
            credential_id,
            extensions,
            authenticator_attachment,
            authenticator_data,
            signature,
            user_handle,
        })
    }
}

#[xpcom(implement(nsIWebAuthnSignResult), atomic)]
pub struct WebAuthnSignResult {
    pub result: SignResult,
}

impl WebAuthnSignResult {
    xpcom_method!(get_client_data_json => GetClientDataJSON() -> nsACString);
    fn get_client_data_json(&self) -> Result<nsCString, nsresult> {
        let Some(client_data_json) = &self.result.client_data_json else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(client_data_json.into())
    }

    xpcom_method!(get_credential_id => GetCredentialId() -> ThinVec<u8>);
    fn get_credential_id(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(credential_id) = &self.result.credential_id else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(credential_id.as_slice().into())
    }

    xpcom_method!(get_signature => GetSignature() -> ThinVec<u8>);
    fn get_signature(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(signature) = &self.result.signature else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(signature.as_slice().into())
    }

    xpcom_method!(get_authenticator_data => GetAuthenticatorData() -> ThinVec<u8>);
    fn get_authenticator_data(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(authenticator_data) = &self.result.authenticator_data else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(authenticator_data.as_slice().into())
    }

    xpcom_method!(get_user_handle => GetUserHandle() -> ThinVec<u8>);
    fn get_user_handle(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(user_handle) = &self.result.user_handle else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(user_handle.as_slice().into())
    }

    xpcom_method!(get_user_name => GetUserName() -> nsACString);
    fn get_user_name(&self) -> Result<nsCString, nsresult> {
        // xdg-portal does not send back the username, only user_handle
        // let Some(user) = &self.result.assertion.user else {
        //     return Err(NS_ERROR_NOT_AVAILABLE);
        // };
        // let Some(name) = &user.name else {
        //     return Err(NS_ERROR_NOT_AVAILABLE);
        // };
        // Ok(nsCString::from(name))
        Err(NS_ERROR_NOT_AVAILABLE)
    }

    xpcom_method!(get_authenticator_attachment => GetAuthenticatorAttachment() -> nsAString);
    fn get_authenticator_attachment(&self) -> Result<nsString, nsresult> {
        let Some(authenticator_attachment) = &self.result.authenticator_attachment else {
            return Err(NS_ERROR_FAILURE);
        };
        Ok(authenticator_attachment.into())
    }

    xpcom_method!(get_used_app_id => GetUsedAppId() -> bool);
    fn get_used_app_id(&self) -> Result<bool, nsresult> {
        // self.result.extensions.app_id.ok_or(NS_ERROR_NOT_AVAILABLE)
        Err(NS_ERROR_NOT_AVAILABLE)
    }

    xpcom_method!(set_used_app_id => SetUsedAppId(aUsedAppId: bool));
    fn set_used_app_id(&self, _used_app_id: bool) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(get_large_blob_value => GetLargeBlobValue() -> ThinVec<u8>);
    fn get_large_blob_value(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(extensions) = &self.result.extensions else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        let Some(large_blob_value) = &extensions.large_blob_value else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        Ok(large_blob_value.as_slice().into())
    }

    xpcom_method!(get_large_blob_written => GetLargeBlobWritten() -> bool);
    fn get_large_blob_written(&self) -> Result<bool, nsresult> {
        let Some(large_blob_written) = self
            .result
            .extensions
            .as_ref()
            .map(|e| e.large_blob_written)
            .flatten()
        else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(large_blob_written)
    }

    xpcom_method!(get_prf_maybe => GetPrfMaybe() -> bool);
    /// Return true if a PRF output is present, even if all attributes are absent.
    fn get_prf_maybe(&self) -> Result<bool, nsresult> {
        let Some(prf_maybe) = self
            .result
            .extensions
            .as_ref()
            .map(|e| e.prf_maybe)
            .flatten()
        else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(prf_maybe)
    }

    xpcom_method!(get_prf_results_first => GetPrfResultsFirst() -> ThinVec<u8>);
    fn get_prf_results_first(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(extensions) = &self.result.extensions else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        let Some(prf_results_first) = &extensions.prf_results_first else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        Ok(prf_results_first.as_slice().into())
    }

    xpcom_method!(get_prf_results_second => GetPrfResultsSecond() -> ThinVec<u8>);
    fn get_prf_results_second(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(extensions) = &self.result.extensions else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        let Some(prf_results_second) = &extensions.prf_results_second else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };

        Ok(prf_results_second.as_slice().into())
    }
}

// Used for conditional mediation:
// The webpage runs a get_assertion()-request, but adds mediation: 'conditional' to it.
// If this is the case, we cache the incoming request and execute it at a later point
// in time, when the user selects it, after clicking into the input-field.
#[derive(Debug, Clone)]
pub(crate) struct PendingSignArgs {
    pub(crate) origin: String,
    /// base64 encoded challenge
    pub(crate) challenge_str: String,
    pub(crate) timeout_ms: u32,
    pub(crate) rp_id: String,
    pub(crate) allow_credential_ids: Vec<Vec<u8>>,
    pub(crate) user_verification: String,
    pub(crate) extensions: Map<String, Value>,
}

#[derive(Clone)]
pub(crate) struct SignPromise(pub(crate) RefPtr<nsIWebAuthnSignPromise>);

impl SignPromise {
    pub(crate) fn resolve_or_reject(
        &self,
        result: Result<SignResult, nsresult>,
    ) -> Result<(), nsresult> {
        match result {
            Ok(result) => {
                let wrapped_result =
                    WebAuthnSignResult::allocate(InitWebAuthnSignResult { result })
                        .query_interface::<nsIWebAuthnSignResult>()
                        .ok_or(NS_ERROR_FAILURE)?;
                unsafe { self.0.Resolve(wrapped_result.coerce()) };
            }
            Err(result) => {
                unsafe { self.0.Reject(result) };
            }
        }
        Ok(())
    }
}
