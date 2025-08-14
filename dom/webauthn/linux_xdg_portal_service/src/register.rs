use base64::Engine;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD};
use dbus::arg::{ArgType, RefArg, Variant};
use dbus::Message;
use nserror::{nsresult, NS_ERROR_FAILURE, NS_ERROR_NOT_AVAILABLE, NS_OK};
use nsstring::{nsACString, nsAString, nsCString, nsString};
use std::collections::HashMap;
use thin_vec::ThinVec;
use xpcom::interfaces::{nsIWebAuthnRegisterPromise, nsIWebAuthnRegisterResult};
use xpcom::{xpcom_method, RefPtr};

#[derive(Debug, Clone)]
pub(crate) struct RegisterExtensionsResult {
    pub(crate) hmac_create_secret: Option<bool>,
    pub(crate) large_blob_supported: Option<bool>,
    pub(crate) prf_enabled: Option<bool>,
    pub(crate) prf_results_first: Option<Vec<u8>>,
    pub(crate) prf_results_second: Option<Vec<u8>>,
    pub(crate) cred_props_rk: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisterResult {
    pub(crate) client_data_json: Option<String>,
    pub(crate) transports: Option<Vec<String>>,
    pub(crate) attestation_object: Option<Vec<u8>>,
    pub(crate) credential_id: Option<Vec<u8>>,
    pub(crate) extensions: Option<RegisterExtensionsResult>,
    pub(crate) authenticator_attachment: Option<String>,
}

impl RegisterResult {
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
        let reg_response_str = public_key_dict
            .get("registration_response_json")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'registration_response_json'")?;

        let response_json: serde_json::Value = serde_json::from_str(reg_response_str)?;

        let credential_id = response_json["id"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        let authenticator_attachment = response_json["authenticatorAttachment"]
            .as_str()
            .map(String::from);

        let extensions = if let Some(extensions) =
            response_json["clientExtensionResults"].as_object()
        {
            let hmac_create_secret = extensions.get("hmacCreateSecret").and_then(|x| x.as_bool());
            let large_blob_supported = extensions.get("largeBlob").and_then(|b| {
                b.as_object()
                    .and_then(|blob| blob.get("supported").and_then(|s| s.as_bool()))
            });
            let prf_enabled = extensions.get("prf").and_then(|p| {
                p.as_object()
                    .and_then(|blob| blob.get("enabled").and_then(|s| s.as_bool()))
            });
            let prf_results_first = None; // Currently not supported by the spec, but may come in the future
            let prf_results_second = None; // Currently not supported by the spec, but may come in the future
            let cred_props_rk = extensions.get("credProps").and_then(|p| {
                p.as_object()
                    .and_then(|blob| blob.get("rk").and_then(|s| s.as_bool()))
            });
            Some(RegisterExtensionsResult {
                hmac_create_secret,
                large_blob_supported,
                prf_enabled,
                prf_results_first,
                prf_results_second,
                cred_props_rk,
            })
        } else {
            None
        };

        // Checking if the "response"-object is there, so that we don't panic below
        response_json
            .get("response")
            .ok_or("Missing 'response' from response_json")?;

        let attestation_object = response_json["response"]["attestationObject"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten();

        let client_data_json = response_json["response"]["clientDataJSON"]
            .as_str()
            .map(|x| URL_SAFE_NO_PAD.decode(x).ok())
            .flatten()
            .map(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let transports = response_json["response"]["transports"]
            .as_array()
            .map(|ts| {
                ts.iter()
                    .filter_map(|t| t.as_str())
                    .map(String::from)
                    .collect()
            });
        Ok(Self {
            client_data_json,
            transports,
            attestation_object,
            credential_id,
            extensions,
            authenticator_attachment,
        })
    }
}

#[derive(Clone)]
pub(crate) struct RegisterPromise(pub(crate) RefPtr<nsIWebAuthnRegisterPromise>);

impl RegisterPromise {
    pub(crate) fn resolve_or_reject(
        &self,
        result: Result<RegisterResult, nsresult>,
    ) -> Result<(), nsresult> {
        match result {
            Ok(result) => {
                let wrapped_result =
                    WebAuthnRegisterResult::allocate(InitWebAuthnRegisterResult { result })
                        .query_interface::<nsIWebAuthnRegisterResult>()
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

#[xpcom(implement(nsIWebAuthnRegisterResult), atomic)]
pub struct WebAuthnRegisterResult {
    // result is only borrowed mutably in `Anonymize`.
    result: RegisterResult,
}

impl WebAuthnRegisterResult {
    xpcom_method!(get_client_data_json => GetClientDataJSON() -> nsACString);
    fn get_client_data_json(&self) -> Result<nsCString, nsresult> {
        let Some(client_data_json) = &self.result.client_data_json else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(client_data_json.into())
    }

    xpcom_method!(get_attestation_object => GetAttestationObject() -> ThinVec<u8>);
    fn get_attestation_object(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(attestation_object) = &self.result.attestation_object else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(ThinVec::from(attestation_object.as_slice()))
    }

    xpcom_method!(get_credential_id => GetCredentialId() -> ThinVec<u8>);
    fn get_credential_id(&self) -> Result<ThinVec<u8>, nsresult> {
        let Some(credential_id) = &self.result.credential_id else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(credential_id.as_slice().into())
    }

    xpcom_method!(get_transports => GetTransports() -> ThinVec<nsString>);
    fn get_transports(&self) -> Result<ThinVec<nsString>, nsresult> {
        Ok(self
            .result
            .transports
            .as_ref()
            .map(|ts| ts.iter().map(|t| t.into()).collect())
            .unwrap_or_default())
    }

    xpcom_method!(get_hmac_create_secret => GetHmacCreateSecret() -> bool);
    fn get_hmac_create_secret(&self) -> Result<bool, nsresult> {
        let Some(hmac_create_secret) = self
            .result
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_create_secret)
        else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(hmac_create_secret)
    }

    xpcom_method!(get_large_blob_supported => GetLargeBlobSupported() -> bool);
    fn get_large_blob_supported(&self) -> Result<bool, nsresult> {
        let Some(large_blob_supported) = self
            .result
            .extensions
            .as_ref()
            .and_then(|e| e.large_blob_supported)
        else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(large_blob_supported)
    }

    xpcom_method!(get_prf_enabled => GetPrfEnabled() -> bool);
    fn get_prf_enabled(&self) -> Result<bool, nsresult> {
        let Some(prf_enabled) = self.result.extensions.as_ref().and_then(|e| e.prf_enabled) else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(prf_enabled)
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

    xpcom_method!(get_cred_props_rk => GetCredPropsRk() -> bool);
    fn get_cred_props_rk(&self) -> Result<bool, nsresult> {
        let Some(cred_props_rk) = self
            .result
            .extensions
            .as_ref()
            .and_then(|e| e.cred_props_rk)
        else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        Ok(cred_props_rk)
    }

    xpcom_method!(set_cred_props_rk => SetCredPropsRk(aCredPropsRk: bool));
    fn set_cred_props_rk(&self, _cred_props_rk: bool) -> Result<(), nsresult> {
        // libwebauthn set this for us already correctly
        Ok(())
    }

    xpcom_method!(get_authenticator_attachment => GetAuthenticatorAttachment() -> nsAString);
    fn get_authenticator_attachment(&self) -> Result<nsString, nsresult> {
        let Some(authenticator_attachment) = &self.result.authenticator_attachment else {
            return Err(NS_ERROR_FAILURE);
        };
        Ok(authenticator_attachment.into())
    }

    xpcom_method!(has_identifying_attestation => HasIdentifyingAttestation() -> bool);
    fn has_identifying_attestation(&self) -> Result<bool, nsresult> {
        Ok(true)
    }

    xpcom_method!(anonymize => Anonymize());
    fn anonymize(&self) -> Result<nsresult, nsresult> {
        // Currently, we don't offer anonymization
        Err(NS_ERROR_NOT_AVAILABLE)
    }
}
