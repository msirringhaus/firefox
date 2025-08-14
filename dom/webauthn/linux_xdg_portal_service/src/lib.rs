/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate xpcom;

use base64::Engine;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD};
use dbus::arg::{RefArg, Variant};
use moz_task::RunnableBuilder;
use nserror::{
    nsresult, NS_ERROR_DOM_ABORT_ERR, NS_ERROR_DOM_NOT_ALLOWED_ERR, NS_ERROR_FAILURE,
    NS_ERROR_NOT_AVAILABLE, NS_ERROR_NOT_IMPLEMENTED, NS_OK,
};
use nsstring::{nsACString, nsAString, nsCString, nsString};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use thin_vec::{thin_vec, ThinVec};
use xpcom::interfaces::{
    nsICredentialParameters, nsIWebAuthnAutoFillEntry, nsIWebAuthnRegisterArgs,
    nsIWebAuthnRegisterPromise, nsIWebAuthnService, nsIWebAuthnSignArgs, nsIWebAuthnSignPromise,
};
use xpcom::{xpcom_method, RefPtr};
mod register;
use register::RegisterPromise;
pub use register::WebAuthnRegisterResult;

mod sign;
use sign::{PendingSignArgs, SignPromise};

mod dbus_controller;
use dbus_controller::DbusController;

// fn authrs_to_nserror(e: AuthenticatorError) -> nsresult {
//     match e {
//         AuthenticatorError::CredentialExcluded => NS_ERROR_DOM_INVALID_STATE_ERR,
//         _ => NS_ERROR_DOM_NOT_ALLOWED_ERR,
//     }
// }

#[derive(Clone)]
enum TransactionPromise {
    Register(RegisterPromise),
    Sign(SignPromise),
}

impl TransactionPromise {
    fn reject(&self, err: nsresult) -> Result<(), nsresult> {
        match self {
            TransactionPromise::Register(promise) => promise.resolve_or_reject(Err(err)),
            TransactionPromise::Sign(promise) => promise.resolve_or_reject(Err(err)),
        }
    }
}

struct TransactionState {
    tid: u64,
    browsing_context_id: u64,
    pending_args: Option<PendingSignArgs>,
    promise: TransactionPromise,
}

#[xpcom(implement(nsIWebAuthnService), atomic)]
pub struct XdgPortalAuthService {
    transaction: Arc<Mutex<Option<TransactionState>>>,
}

impl XdgPortalAuthService {
    xpcom_method!(get_is_uvpaa => GetIsUVPAA() -> bool);
    fn get_is_uvpaa(&self) -> Result<bool, nsresult> {
        // For now, xdg-portal doesn't offer a platform authenticator
        Ok(false)
    }

    xpcom_method!(make_credential => MakeCredential(aTid: u64, aBrowsingContextId: u64, aArgs: *const nsIWebAuthnRegisterArgs, aPromise: *const nsIWebAuthnRegisterPromise));
    fn make_credential(
        &self,
        tid: u64,
        browsing_context_id: u64,
        args: &nsIWebAuthnRegisterArgs,
        promise: &nsIWebAuthnRegisterPromise,
    ) -> Result<(), nsresult> {
        self.reset()?;

        let promise = RegisterPromise(RefPtr::new(promise));

        let mut challenge = ThinVec::new();
        unsafe { args.GetChallenge(&mut challenge) }.to_result()?;
        let challenge_str = URL_SAFE_NO_PAD.encode(challenge);

        let mut origin = nsString::new();
        unsafe { args.GetOrigin(&mut *origin) }.to_result()?;

        let mut relying_party_id = nsString::new();
        unsafe { args.GetRpId(&mut *relying_party_id) }.to_result()?;

        let mut client_data = nsCString::new();
        unsafe { args.GetClientDataJSON(&mut *client_data) }.to_result()?;
        let client_data_json: Option<serde_json::Map<_, _>> =
            serde_json::from_str(&client_data.to_string()).ok();
        let is_cross_origin = client_data_json
            .and_then(|o| o.get("crossOrigin").and_then(|c| c.as_bool()))
            .unwrap_or_default();

        let mut timeout_ms = 0u32;
        unsafe { args.GetTimeoutMS(&mut timeout_ms) }.to_result()?;

        let mut exclude_list_ids = ThinVec::new();
        unsafe { args.GetExcludeList(&mut exclude_list_ids) }.to_result()?;
        let exclude_list: Vec<_> = exclude_list_ids
            .iter()
            .map(|id| {
                json!({
                    "id": URL_SAFE_NO_PAD.encode(&id),
                    "type": "public-key",
                })
            })
            .collect();

        let mut relying_party_name = nsString::new();
        unsafe { args.GetRpName(&mut *relying_party_name) }.to_result()?;

        let mut user_id = ThinVec::new();
        unsafe { args.GetUserId(&mut user_id) }.to_result()?;
        let user_id_str = URL_SAFE_NO_PAD.encode(user_id);

        let mut user_name = nsString::new();
        unsafe { args.GetUserName(&mut *user_name) }.to_result()?;

        let mut user_display_name = nsString::new();
        unsafe { args.GetUserDisplayName(&mut *user_display_name) }.to_result()?;

        let mut cose_algs = ThinVec::new();
        unsafe { args.GetCoseAlgs(&mut cose_algs) }.to_result()?;
        let pub_key_cred_params: Vec<_> = cose_algs
            .iter()
            .map(|alg| {
                json!({
                    "alg": alg,
                    "type": "public-key",
                })
            })
            .collect();

        let mut resident_key = nsString::new();
        unsafe { args.GetResidentKey(&mut *resident_key) }.to_result()?;

        let mut user_verification = nsString::new();
        unsafe { args.GetUserVerification(&mut *user_verification) }.to_result()?;

        let mut authenticator_attachment = nsString::new();
        if unsafe { args.GetAuthenticatorAttachment(&mut *authenticator_attachment) }
            .to_result()
            .is_ok()
        {
            // For now, xdg-portal doesn't offer a platform authenticator
            if authenticator_attachment.eq("platform") {
                return Err(NS_ERROR_NOT_AVAILABLE);
            }
        }

        let mut extensions = serde_json::Map::new();
        let mut cred_protect_policy_value = nsCString::new();
        if unsafe { args.GetCredentialProtectionPolicy(&mut *cred_protect_policy_value) }
            .to_result()
            .is_ok()
        {
            extensions.insert(
                "credentialProtectionPolicy".to_string(),
                json!(cred_protect_policy_value.to_string()),
            );
            let mut enforce_cred_protect_value = false;
            unsafe { args.GetEnforceCredentialProtectionPolicy(&mut enforce_cred_protect_value) }
                .to_result()?;
            extensions.insert(
                "enforceCredentialProtectionPolicy".to_string(),
                json!(enforce_cred_protect_value),
            );
        }

        // Not yet supported by Firefox. See bmo#1844448
        // let mut cred_blob = false;
        // unsafe { args.GetCredBlob(&mut cred_blob) }.to_result()?;

        let mut cred_props = false;
        unsafe { args.GetCredProps(&mut cred_props) }.to_result()?;
        if cred_props {
            extensions.insert("credProps".to_string(), json!(cred_props));
        }

        let mut min_pin_length = false;
        unsafe { args.GetMinPinLength(&mut min_pin_length) }.to_result()?;
        if min_pin_length {
            extensions.insert("minPinLength".to_string(), json!(min_pin_length));
        }

        // Firefox currently doesn't support largeBlob.support == "preferred", only "required"
        let mut large_blob_support_required = false;
        if unsafe { args.GetLargeBlobSupportRequired(&mut large_blob_support_required) }
            .to_result()
            .is_ok()
        {
            if large_blob_support_required {
                extensions.insert("largeBlob".to_string(), json!({"support": "required"}));
            }
        }

        let mut prf = false;
        if unsafe { args.GetPrf(&mut prf) }.to_result().is_ok() && prf {
            let mut prf_map = serde_json::Map::new();
            let mut prf_eval_first: ThinVec<u8> = ThinVec::new();
            if unsafe { args.GetPrfEvalFirst(&mut prf_eval_first) }
                .to_result()
                .is_ok()
            {
                prf_map.insert(
                    "first".to_string(),
                    json!(URL_SAFE_NO_PAD.encode(prf_eval_first)),
                );
            }

            let mut prf_eval_second: ThinVec<u8> = ThinVec::new();
            if unsafe { args.GetPrfEvalSecond(&mut prf_eval_second) }
                .to_result()
                .is_ok()
            {
                prf_map.insert(
                    "second".to_string(),
                    json!(URL_SAFE_NO_PAD.encode(prf_eval_second)),
                );
            }
            extensions.insert("prf".to_string(), json!(prf_map));
        }

        let mut maybe_hmac_create_secret = false;
        if unsafe { args.GetHmacCreateSecret(&mut maybe_hmac_create_secret) }
            .to_result()
            .is_ok()
        {
            extensions.insert(
                "hmacCreateSecret".to_string(),
                json!(maybe_hmac_create_secret),
            );
        }

        let public_key_json = json!({
            "challenge": challenge_str,
            "rp": {
                "id": relying_party_id.to_string(),
                "name": relying_party_name.to_string(),
            },
            "user": {
                "id": user_id_str,
                "name": user_name.to_string(),
                "display_name": user_display_name.to_string(),
            },
            "timeout": timeout_ms,
            "excludeCredentials": exclude_list,
            "pubKeyCredParams": pub_key_cred_params,
            "extensions": extensions,
            "authenticatorSelection": {
                "residentKey": resident_key.to_string(),
                "userVerification": user_verification.to_string(),
            },
        })
        .to_string();

        let mut guard = self.transaction.lock().unwrap();
        *guard = Some(TransactionState {
            tid,
            browsing_context_id,
            pending_args: None,
            promise: TransactionPromise::Register(promise),
        });
        drop(guard);

        let callback_transaction = self.transaction.clone();
        RunnableBuilder::new("XdgPortalService::MakeCredential::DbusSend", move || {
            // https://github.com/linux-credentials/credentialsd/blob/main/doc/api.md#credential-types
            // We need to craft a message like this:
            // req = {
            //     "type": Variant('s', "publicKey"),
            //     "origin": Variant('s', origin),
            //     "is_same_origin": Variant('b', is_same_origin),
            //     "publicKey": Variant('a{sv}', {
            //         "request_json": Variant('s', req_json)
            //     })
            // }

            // --- Build the inner dictionary for "publicKey" ---
            // This corresponds to the a{sv} value of the "publicKey" key.
            let mut public_key_dict = HashMap::<String, Variant<Box<dyn RefArg>>>::new();
            public_key_dict.insert(
                "request_json".to_string(),
                Variant(Box::new(public_key_json)),
            );

            // --- Build the main dictionary payload ---
            // This is the top-level a{sv} structure.
            let mut req = HashMap::<String, Variant<Box<dyn RefArg>>>::new();
            req.insert(
                "type".to_string(),
                Variant(Box::new("publicKey".to_string())),
            );
            req.insert("origin".to_string(), Variant(Box::new(origin.to_string())));
            req.insert(
                "is_same_origin".to_string(),
                Variant(Box::new(!is_cross_origin)),
            );
            req.insert(
                "publicKey".to_string(),
                // The inner dictionary must also be wrapped in a Variant
                Variant(Box::new(public_key_dict)),
            );

            // Create a new dbus connection and send the message
            let dbus_controller = match DbusController::new() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("Failed to create DBUS connection {e:?}");
                    return;
                }
            };
            let result = dbus_controller.send_create_credential(req);

            let mut guard = callback_transaction.lock().unwrap();
            let Some(state) = guard.as_mut() else {
                return;
            };
            if state.tid != tid {
                return;
            }
            let TransactionPromise::Register(ref promise) = state.promise else {
                return;
            };

            let _ = promise.resolve_or_reject(result); // TODO: Do correct error mapping here
            *guard = None;
        })
        .may_block(true)
        .dispatch_background_task()?;

        Ok(())
    }

    xpcom_method!(set_has_attestation_consent => SetHasAttestationConsent(aTid: u64, aHasConsent: bool));
    fn set_has_attestation_consent(&self, _tid: u64, _has_consent: bool) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(get_assertion => GetAssertion(aTid: u64, aBrowsingContextId: u64, aArgs: *const nsIWebAuthnSignArgs, aPromise: *const nsIWebAuthnSignPromise));
    fn get_assertion(
        &self,
        tid: u64,
        browsing_context_id: u64,
        args: &nsIWebAuthnSignArgs,
        promise: &nsIWebAuthnSignPromise,
    ) -> Result<(), nsresult> {
        self.reset()?;

        let promise = SignPromise(RefPtr::new(promise));

        let mut challenge = ThinVec::new();
        unsafe { args.GetChallenge(&mut challenge) }.to_result()?;
        let challenge_str = URL_SAFE_NO_PAD.encode(challenge);

        let mut origin = nsString::new();
        unsafe { args.GetOrigin(&mut *origin) }.to_result()?;

        let mut relying_party_id = nsString::new();
        unsafe { args.GetRpId(&mut *relying_party_id) }.to_result()?;

        let mut client_data = nsCString::new();
        unsafe { args.GetClientDataJSON(&mut *client_data) }.to_result()?;
        let client_data_json: Option<serde_json::Map<_, _>> =
            serde_json::from_str(&client_data.to_string()).ok();
        let is_cross_origin = client_data_json
            .and_then(|o| o.get("crossOrigin").and_then(|c| c.as_bool()))
            .unwrap_or_default();

        let mut timeout_ms = 0u32;
        unsafe { args.GetTimeoutMS(&mut timeout_ms) }.to_result()?;

        let mut allow_list_ids = ThinVec::new();
        unsafe { args.GetAllowList(&mut allow_list_ids) }.to_result()?;
        let allow_list: Vec<_> = allow_list_ids.iter().map(|id| id.to_vec()).collect();

        let mut user_verification = nsString::new();
        unsafe { args.GetUserVerification(&mut *user_verification) }.to_result()?;

        // credentialsd currently does not support the appid extension
        // https://github.com/linux-credentials/libwebauthn/issues/141
        //
        // let mut app_id = None;
        // let mut maybe_app_id = nsString::new();
        // match unsafe { args.GetAppId(&mut *maybe_app_id) }.to_result() {
        //     Ok(_) => app_id = Some(maybe_app_id.to_string()),
        //     _ => (),
        // }

        let mut extensions = serde_json::Map::new();

        let mut prf = false;
        if unsafe { args.GetPrf(&mut prf) }.to_result().is_ok() && prf {
            let mut prf_map = serde_json::Map::new();
            let mut prf_eval_map = serde_json::Map::new();
            let mut prf_eval_first: ThinVec<u8> = ThinVec::new();
            unsafe { args.GetPrfEvalFirst(&mut prf_eval_first) }.to_result()?;
            prf_eval_map.insert(
                "first".to_string(),
                json!(URL_SAFE_NO_PAD.encode(prf_eval_first)),
            );

            let mut prf_eval_second: ThinVec<u8> = ThinVec::new();
            if unsafe { args.GetPrfEvalSecond(&mut prf_eval_second) }
                .to_result()
                .is_ok()
            {
                prf_eval_map.insert(
                    "second".to_string(),
                    json!(URL_SAFE_NO_PAD.encode(prf_eval_second)),
                );
            }
            prf_map.insert("eval".to_string(), json!(prf_eval_map));

            let mut prf_eval_by_creds = serde_json::Map::new();
            let mut credential_ids: ThinVec<ThinVec<u8>> = ThinVec::new();
            let mut eval_by_cred_firsts: ThinVec<ThinVec<u8>> = ThinVec::new();
            let mut eval_by_cred_second_maybes: ThinVec<bool> = ThinVec::new();
            let mut eval_by_cred_seconds: ThinVec<ThinVec<u8>> = ThinVec::new();
            if unsafe { args.GetPrfEvalByCredentialCredentialId(&mut credential_ids) }
                .to_result()
                .is_ok()
                && !credential_ids.is_empty()
            {
                // All three functions are guaranteed to return arrays of the same length.
                // If `seconds` are missing (because they are optional), then
                // eval_by_cred_second_maybes[i] will have `false`, and eval_by_cred_seconds[i]
                // an empty array
                unsafe { args.GetPrfEvalByCredentialEvalFirst(&mut eval_by_cred_firsts) }
                    .to_result()?;
                unsafe {
                    args.GetPrfEvalByCredentialEvalSecondMaybe(&mut eval_by_cred_second_maybes)
                }
                .to_result()?;
                unsafe { args.GetPrfEvalByCredentialEvalSecond(&mut eval_by_cred_seconds) }
                    .to_result()?;

                for i in 0..credential_ids.len() {
                    let mut prf_eval_by_cred_map = serde_json::Map::new();
                    prf_eval_by_cred_map.insert(
                        "first".to_string(),
                        json!(URL_SAFE_NO_PAD.encode(&eval_by_cred_firsts[i])),
                    );

                    if eval_by_cred_second_maybes[i] {
                        prf_eval_by_cred_map.insert(
                            "second".to_string(),
                            json!(URL_SAFE_NO_PAD.encode(&eval_by_cred_seconds[i])),
                        );
                    }
                    prf_eval_by_creds.insert(
                        URL_SAFE_NO_PAD.encode(&credential_ids[i]),
                        json!(prf_eval_by_cred_map),
                    );
                }
                prf_map.insert("evalByCredential".to_string(), json!(prf_eval_by_creds));
            }
            extensions.insert("prf".to_string(), json!(prf_map));
        }

        let mut large_blob_map = serde_json::Map::new();
        let mut large_blob_read = false;
        if unsafe { args.GetLargeBlobRead(&mut large_blob_read) }
            .to_result()
            .is_ok()
        {
            large_blob_map.insert("support".to_string(), json!("required"));
        }
        let mut large_blob_write: ThinVec<u8> = ThinVec::new();
        if unsafe { args.GetLargeBlobWrite(&mut large_blob_write) }
            .to_result()
            .is_ok()
        {
            large_blob_map.insert(
                "write".to_string(),
                json!(URL_SAFE_NO_PAD.encode(&large_blob_write)),
            );
        }
        if !large_blob_map.is_empty() {
            extensions.insert("largeBlob".to_string(), json!(large_blob_map));
        }

        // https://w3c.github.io/webauthn/#prf-extension
        // "The hmac-secret extension provides two PRFs per credential: one which is used for
        // requests where user verification is performed and another for all other requests.
        // This extension [PRF] only exposes a single PRF per credential and, when implementing
        // on top of hmac-secret, that PRF MUST be the one used for when user verification is
        // performed. This overrides the UserVerificationRequirement if neccessary."
        if prf && user_verification == "discouraged" {
            user_verification = "preferred".into();
        }

        let mut conditionally_mediated = false;
        unsafe { args.GetConditionallyMediated(&mut conditionally_mediated) }.to_result()?;

        let mut guard = self.transaction.lock().unwrap();
        *guard = Some(TransactionState {
            tid,
            browsing_context_id,
            pending_args: Some(PendingSignArgs {
                origin: origin.to_string(),
                challenge_str,
                timeout_ms,
                rp_id: relying_party_id.to_string(),
                allow_credential_ids: allow_list,
                user_verification: user_verification.to_string(),
                extensions,
                is_same_origin: !is_cross_origin,
            }),
            promise: TransactionPromise::Sign(promise),
        });

        if !conditionally_mediated {
            // Immediately proceed to the modal UI flow.
            self.do_get_assertion(None, guard)
        } else {
            // Cache the request and wait for the conditional UI to request autofill entries, etc.
            Ok(())
        }
    }

    fn do_get_assertion(
        &self,
        mut selected_credential_id: Option<Vec<u8>>,
        mut guard: MutexGuard<Option<TransactionState>>,
    ) -> Result<(), nsresult> {
        let Some(state) = guard.as_mut() else {
            return Err(NS_ERROR_FAILURE);
        };
        let tid = state.tid;
        let mut pending_args = match state.pending_args.take() {
            Some(args) => args,
            None => return Err(NS_ERROR_FAILURE),
        };

        if let Some(id) = selected_credential_id.take() {
            if pending_args.allow_credential_ids.is_empty() {
                pending_args.allow_credential_ids.push(id);
            } else {
                // We need to ensure that the selected credential id
                // was in the original allow_list.
                pending_args.allow_credential_ids.retain(|i| i == &id);
                if pending_args.allow_credential_ids.is_empty() {
                    return Err(NS_ERROR_FAILURE);
                }
            }
        }

        let allow_list: Vec<_> = pending_args
            .allow_credential_ids
            .iter()
            .map(|id| {
                json!({
                    "id": URL_SAFE_NO_PAD.encode(&id),
                    "type": "public-key",
                })
            })
            .collect();

        let json_str = json!({
            "challenge": pending_args.challenge_str,
            "timeout": pending_args.timeout_ms,
            "rpId": pending_args.rp_id,
            "allowCredentials": allow_list,
            "userVerification": pending_args.user_verification,
            // "hints": [],
            "extensions": pending_args.extensions,
        })
        .to_string();

        let callback_transaction = self.transaction.clone();
        RunnableBuilder::new("XdgPortalService::GetCredential::DbusSend", move || {
            // https://github.com/linux-credentials/credentialsd/blob/main/doc/api.md#credential-types
            // We need to craft a message like this:
            // req = {
            //     "type": Variant('s', "publicKey"),
            //     "origin": Variant('s', origin),
            //     "is_same_origin": Variant('b', is_same_origin),
            //     "publicKey": Variant('a{sv}', {
            //         "request_json": Variant('s', req_json)
            //     })
            // }
            // --- Build the inner dictionary for "publicKey" ---
            // This corresponds to the a{sv} value of the "publicKey" key.
            let mut public_key_dict = HashMap::<String, Variant<Box<dyn RefArg>>>::new();
            public_key_dict.insert("request_json".to_string(), Variant(Box::new(json_str)));

            // --- Build the main dictionary payload ---
            // This is the top-level a{sv} structure.
            let mut req = HashMap::<String, Variant<Box<dyn RefArg>>>::new();
            req.insert(
                "type".to_string(),
                Variant(Box::new("publicKey".to_string())),
            );
            req.insert(
                "origin".to_string(),
                Variant(Box::new(pending_args.origin.clone())),
            );
            req.insert(
                "is_same_origin".to_string(),
                Variant(Box::new(pending_args.is_same_origin)),
            );
            req.insert(
                "publicKey".to_string(),
                // The inner dictionary must also be wrapped in a Variant
                Variant(Box::new(public_key_dict)),
            );

            // Create a new dbus connection and send the message
            let dbus_controller = match DbusController::new() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("Failed to create DBUS connection {e:?}");
                    return;
                }
            };
            let result = dbus_controller.send_get_credential(req);

            let mut guard = callback_transaction.lock().unwrap();
            let Some(state) = guard.as_mut() else {
                return;
            };
            if state.tid != tid {
                return;
            }
            let TransactionPromise::Sign(ref promise) = state.promise else {
                return;
            };
            let _ = promise.resolve_or_reject(result); // TODO: Do correct error mapping here
            *guard = None;
        })
        .may_block(true)
        .dispatch_background_task()?;
        Ok(())
    }

    xpcom_method!(has_pending_conditional_get => HasPendingConditionalGet(aBrowsingContextId: u64, aOrigin: *const nsAString) -> u64);
    fn has_pending_conditional_get(
        &self,
        browsing_context_id: u64,
        origin: &nsAString,
    ) -> Result<u64, nsresult> {
        let mut guard = self.transaction.lock().unwrap();
        let Some(state) = guard.as_mut() else {
            return Ok(0);
        };
        let Some(pending_args) = state.pending_args.as_ref() else {
            return Ok(0);
        };
        if state.browsing_context_id != browsing_context_id {
            return Ok(0);
        }
        if !pending_args.origin.eq(&origin.to_string()) {
            return Ok(0);
        }
        Ok(state.tid)
    }

    xpcom_method!(get_autofill_entries => GetAutoFillEntries(aTransactionId: u64) -> ThinVec<Option<RefPtr<nsIWebAuthnAutoFillEntry>>>);
    fn get_autofill_entries(
        &self,
        tid: u64,
    ) -> Result<ThinVec<Option<RefPtr<nsIWebAuthnAutoFillEntry>>>, nsresult> {
        let mut guard = self.transaction.lock().unwrap();
        let Some(state) = guard.as_mut() else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        if state.tid != tid {
            return Err(NS_ERROR_NOT_AVAILABLE);
        }
        let Some(_pending_args) = state.pending_args.as_ref() else {
            return Err(NS_ERROR_NOT_AVAILABLE);
        };
        // We don't currently support silent discovery for credentials via xdg portal, YET.
        return Ok(thin_vec![]);
    }

    xpcom_method!(select_autofill_entry => SelectAutoFillEntry(aTid: u64, aCredentialId: *const ThinVec<u8>));
    fn select_autofill_entry(&self, tid: u64, credential_id: &ThinVec<u8>) -> Result<(), nsresult> {
        // As we don't yet support silent discovery, this would never be called, but
        // it doesn't hurt to have it implemented already for the future
        let mut guard = self.transaction.lock().unwrap();
        let Some(state) = guard.as_mut() else {
            return Err(NS_ERROR_FAILURE);
        };
        if tid != state.tid {
            return Err(NS_ERROR_FAILURE);
        }
        self.do_get_assertion(Some(credential_id.to_vec()), guard)
    }

    xpcom_method!(resume_conditional_get => ResumeConditionalGet(aTid: u64));
    fn resume_conditional_get(&self, tid: u64) -> Result<(), nsresult> {
        let mut guard = self.transaction.lock().unwrap();
        let Some(state) = guard.as_mut() else {
            return Err(NS_ERROR_FAILURE);
        };
        if tid != state.tid {
            return Err(NS_ERROR_FAILURE);
        }
        self.do_get_assertion(None, guard)
    }

    // Clears the transaction state if tid matches the ongoing transaction ID.
    // Returns whether the tid was a match.
    fn clear_transaction(&self, tid: u64) -> bool {
        let mut guard = self.transaction.lock().unwrap();
        let Some(state) = guard.as_ref() else {
            return true; // workaround for Bug 1864526.
        };
        if state.tid != tid {
            // Ignore the cancellation request if the transaction
            // ID does not match.
            return false;
        }
        // It's possible that we haven't dispatched the request via dbus yet.
        // So reject the promise and drop the state here.
        let _ = state.promise.reject(NS_ERROR_DOM_NOT_ALLOWED_ERR);
        *guard = None;
        true
    }

    xpcom_method!(cancel => Cancel(aTransactionId: u64));
    fn cancel(&self, tid: u64) -> Result<(), nsresult> {
        self.clear_transaction(tid);
        // TODO: Cancel dbus controller
        Ok(())
    }

    xpcom_method!(reset => Reset());
    fn reset(&self) -> Result<(), nsresult> {
        {
            if let Some(state) = self.transaction.lock().unwrap().take() {
                state.promise.reject(NS_ERROR_DOM_ABORT_ERR)?;
            }
        }
        // TODO: Cancel dbus controller
        // self.dbus_controller.lock().unwrap().cancel();
        Ok(())
    }

    xpcom_method!(
        add_virtual_authenticator => AddVirtualAuthenticator(
            protocol: *const nsACString,
            transport: *const nsACString,
            has_resident_key: bool,
            has_user_verification: bool,
            is_user_consenting: bool,
            is_user_verified: bool) -> nsACString
    );
    fn add_virtual_authenticator(
        &self,
        _protocol: &nsACString,
        _transport: &nsACString,
        _has_resident_key: bool,
        _has_user_verification: bool,
        _is_user_consenting: bool,
        _is_user_verified: bool,
    ) -> Result<nsCString, nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(remove_virtual_authenticator => RemoveVirtualAuthenticator(authenticatorId: *const nsACString));
    fn remove_virtual_authenticator(&self, _authenticator_id: &nsACString) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(
        add_credential => AddCredential(
            authenticatorId: *const nsACString,
            credential_id: *const nsACString,
            is_resident_credential: bool,
            rp_id: *const nsACString,
            private_key: *const nsACString,
            user_handle: *const nsACString,
            sign_count: u32)
    );
    fn add_credential(
        &self,
        _authenticator_id: &nsACString,
        _credential_id: &nsACString,
        _is_resident_credential: bool,
        _rp_id: &nsACString,
        _private_key: &nsACString,
        _user_handle: &nsACString,
        _sign_count: u32,
    ) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(get_credentials => GetCredentials(authenticatorId: *const nsACString) -> ThinVec<Option<RefPtr<nsICredentialParameters>>>);
    fn get_credentials(
        &self,
        _authenticator_id: &nsACString,
    ) -> Result<ThinVec<Option<RefPtr<nsICredentialParameters>>>, nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(remove_credential => RemoveCredential(authenticatorId: *const nsACString, credentialId: *const nsACString));
    fn remove_credential(
        &self,
        _authenticator_id: &nsACString,
        _credential_id: &nsACString,
    ) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(remove_all_credentials => RemoveAllCredentials(authenticatorId: *const nsACString));
    fn remove_all_credentials(&self, _authenticator_id: &nsACString) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(set_user_verified => SetUserVerified(authenticatorId: *const nsACString, isUserVerified: bool));
    fn set_user_verified(
        &self,
        _authenticator_id: &nsACString,
        _is_user_verified: bool,
    ) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(listen => Listen());
    pub(crate) fn listen(&self) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(run_command => RunCommand(c_cmd: *const nsACString));
    pub fn run_command(&self, _c_cmd: &nsACString) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(pin_callback => PinCallback(aTransactionId: u64, aPin: *const nsACString));
    fn pin_callback(&self, _transaction_id: u64, _pin: &nsACString) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(selection_callback => SelectionCallback(aTransactionId: u64, aSelection: u64));
    fn selection_callback(&self, _transaction_id: u64, _selection: u64) -> Result<(), nsresult> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }
}

#[no_mangle]
pub extern "C" fn xdg_portal_auth_service_if_available(
    result: *mut *const nsIWebAuthnService,
) -> nsresult {
    // This is not send-able to other threads because it contains a raw pointer,
    // but we don't need to keep it. We can simply create a new one on the fly
    let dbus_controller = match DbusController::new() {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "Failed to create DBUS connection. Assuming XDG portal is not available. {e:?}"
            );
            return NS_ERROR_NOT_AVAILABLE;
        }
    };

    if !dbus_controller.is_service_active() {
        log::warn!("Failed to find XDG portal.");
        return NS_ERROR_NOT_AVAILABLE;
    }

    let wrapper = XdgPortalAuthService::allocate(InitXdgPortalAuthService {
        transaction: Arc::new(Mutex::new(None)),
    });

    unsafe {
        RefPtr::new(wrapper.coerce::<nsIWebAuthnService>()).forget(&mut *result);
    }
    NS_OK
}
