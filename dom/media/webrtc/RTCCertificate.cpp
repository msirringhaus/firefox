/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/RTCCertificate.h"

#include <cstdio>
#include <cstring>
#include <new>
#include <utility>

#include "ErrorList.h"
#include "MainThreadUtils.h"
#include "RTCCertService.h"
#include "cert.h"
#include "cryptohi.h"
#include "js/StructuredClone.h"
#include "js/TypeDecls.h"
#include "js/Value.h"
#include "keyhi.h"
#include "mozilla/ErrorResult.h"
#include "mozilla/OwningNonNull.h"
#include "mozilla/dom/BindingDeclarations.h"
#include "mozilla/dom/CryptoBuffer.h"
#include "mozilla/dom/KeyAlgorithmBinding.h"
#include "mozilla/dom/KeyAlgorithmProxy.h"
#include "mozilla/dom/Promise.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "mozilla/dom/RTCCertificateBinding.h"
#include "mozilla/dom/RootedDictionary.h"
#include "mozilla/dom/StructuredCloneHolder.h"
#include "mozilla/dom/UnionTypes.h"
#include "mozilla/dom/WebCryptoCommon.h"
#include "mozilla/dom/WebCryptoTask.h"
#include "mozilla/fallible.h"
#include "nsDebug.h"
#include "nsError.h"
#include "nsLiteralString.h"
#include "nsServiceManagerUtils.h"
#include "nsStringFlags.h"
#include "nsStringFwd.h"
#include "nsTLiteralString.h"
#include "pk11pub.h"
#include "plarena.h"
#include "sdp/SdpAttribute.h"
#include "secasn1.h"
#include "secasn1t.h"
#include "seccomon.h"
#include "secmodt.h"
#include "secoid.h"
#include "secoidt.h"
#include "transport/dtlsidentity.h"
#include "xpcpublic.h"

namespace mozilla::dom {

#define RTCCERTIFICATE_SC_VERSION 0x00000002

NS_IMPL_CYCLE_COLLECTION_WRAPPERCACHE(RTCCertificate, mGlobal)
NS_IMPL_CYCLE_COLLECTING_ADDREF(RTCCertificate)
NS_IMPL_CYCLE_COLLECTING_RELEASE(RTCCertificate)
NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION(RTCCertificate)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
  NS_INTERFACE_MAP_ENTRY(nsISupports)
NS_INTERFACE_MAP_END

// Note: explicit casts necessary to avoid
//       warning C4307: '*' : integral constant overflow
#define ONE_DAY                                 \
  PRTime(PR_USEC_PER_SEC) * PRTime(60)  /*sec*/ \
      * PRTime(60) /*min*/ * PRTime(24) /*hours*/
#define EXPIRATION_DEFAULT ONE_DAY* PRTime(30)
#define EXPIRATION_MAX ONE_DAY* PRTime(365) /*year*/

const size_t RTCCertificateMinRsaSize = 1024;

static PRTime ReadExpires(JSContext* aCx, const ObjectOrString& aOptions,
                          ErrorResult& aRv) {
  // This conversion might fail, but we don't really care; use the default.
  // If this isn't an object, or it doesn't coerce into the right type,
  // then we won't get the |expires| value.  Either will be caught later.
  RTCCertificateExpiration expiration;
  if (!aOptions.IsObject()) {
    return EXPIRATION_DEFAULT;
  }
  JS::Rooted<JS::Value> value(aCx, JS::ObjectValue(*aOptions.GetAsObject()));
  if (!expiration.Init(aCx, value)) {
    aRv.NoteJSContextException(aCx);
    return 0;
  }

  if (!expiration.mExpires.WasPassed()) {
    return EXPIRATION_DEFAULT;
  }
  static const uint64_t max =
      static_cast<uint64_t>(EXPIRATION_MAX / PR_USEC_PER_MSEC);
  if (expiration.mExpires.Value() > max) {
    return EXPIRATION_MAX;
  }
  return static_cast<PRTime>(expiration.mExpires.Value() * PR_USEC_PER_MSEC);
}

RTCCertificateMetadata::RTCCertificateMetadata()
    : mExpires(0),
      mSignatureAlg(SEC_OID_UNKNOWN),
      mMechanism(CKM_INVALID_MECHANISM),
      mRsaParams() {}

nsresult RTCCertificateMetadata::Init(JSContext* aCx, nsCString aOrigin,
                                      const ObjectOrString& aAlgorithm,
                                      SSLKEAType* aAuthType, ErrorResult& aRv) {
  mExpires = ReadExpires(aCx, aAlgorithm, aRv);
  if (aRv.Failed()) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  mArena = UniquePLArenaPool(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!mArena) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  // Extract algorithm name
  nsresult rv = GetAlgorithmName(aCx, aAlgorithm, mAlgName);
  NS_ENSURE_SUCCESS(rv, NS_ERROR_DOM_NOT_SUPPORTED_ERR);

  // Construct an appropriate KeyAlorithm
  if (mAlgName.EqualsLiteral(WEBCRYPTO_ALG_RSASSA_PKCS1)) {
    RootedDictionary<RsaHashedKeyGenParams> params(aCx);
    rv = Coerce(aCx, params, aAlgorithm);
    NS_ENSURE_SUCCESS(rv, NS_ERROR_DOM_SYNTAX_ERR);

    // Pull relevant info
    uint32_t modulusLength = params.mModulusLength;
    CryptoBuffer publicExponent;
    if (!publicExponent.Assign(params.mPublicExponent)) {
      return NS_ERROR_DOM_UNKNOWN_ERR;
    }

    nsString hashName;
    rv = GetAlgorithmName(aCx, params.mHash, hashName);
    NS_ENSURE_SUCCESS(rv, rv);
    if (!hashName.EqualsLiteral(WEBCRYPTO_ALG_SHA256)) {
      return NS_ERROR_DOM_NOT_SUPPORTED_ERR;
    }

    mMechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

    // Set up params struct
    mRsaParams.keySizeInBits = modulusLength;
    bool converted = publicExponent.GetBigIntValue(mRsaParams.pe);
    if (!converted) {
      return NS_ERROR_DOM_INVALID_ACCESS_ERR;
    }

    auto sz = static_cast<size_t>(mRsaParams.keySizeInBits);
    if (sz < RTCCertificateMinRsaSize) {
      return NS_ERROR_DOM_NOT_SUPPORTED_ERR;
    }

    SerializeRSAParam(&mParam, &mRsaParams);

    mSignatureAlg = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION;
    *aAuthType = ssl_kea_rsa;
  } else if (mAlgName.EqualsLiteral(WEBCRYPTO_ALG_ECDSA)) {
    RootedDictionary<EcKeyGenParams> params(aCx);
    rv = Coerce(aCx, params, aAlgorithm);
    NS_ENSURE_SUCCESS(rv, NS_ERROR_DOM_SYNTAX_ERR);

    if (!NormalizeToken(params.mNamedCurve, mNamedCurve)) {
      return NS_ERROR_DOM_NOT_SUPPORTED_ERR;
    }
    mMechanism = CKM_EC_KEY_PAIR_GEN;
    if (!SerializeECParams(&mParam,
                           CreateECParamsForCurve(mNamedCurve, mArena.get()))) {
      return NS_ERROR_DOM_NOT_SUPPORTED_ERR;
    }

    // We only support good curves in WebCrypto.
    // If that ever changes, check that a good one was chosen.
    mSignatureAlg = SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE;
    *aAuthType = ssl_kea_ecdh;
  } else {
    return NS_ERROR_DOM_NOT_SUPPORTED_ERR;
  }

  mOrigin = std::move(aOrigin);
  return NS_OK;
}

RefPtr<RTCCertificatePromise> RTCCertificateMetadata::Generate(
    RTCCertService* aCertService) {
  if (!aCertService) {
    return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE, __func__);
  }
  return aCertService->GenerateCertificate(mOrigin, mParam, mExpires,
                                           mMechanism, mSignatureAlg);
}

already_AddRefed<Promise> RTCCertificate::Generate(
    const GlobalObject& aGlobal, const ObjectOrString& aOptions,
    ErrorResult& aRv) {
  nsIGlobalObject* global = xpc::NativeGlobal(aGlobal.Get());
  RefPtr<Promise> resultPromise = Promise::Create(global, aRv);
  if (aRv.Failed()) {
    return nullptr;
  }

  nsCOMPtr<nsIPrincipal> principal = global->PrincipalOrNull();
  if (!principal) {
    aRv.Throw(NS_ERROR_FAILURE);
    return nullptr;
  }

  nsAutoCString origin;
  nsresult rv = principal->GetOrigin(origin);
  if (NS_FAILED(rv)) {
    aRv.Throw(rv);
    return nullptr;
  }

  rv = mData.Init(aGlobal.Context(), std::move(origin), aOptions, &mAuthType,
                  aRv);
  if (NS_FAILED(rv)) {
    // webrtc-pc says to throw NotSupportedError if we have passed "an
    // algorithm that the user agent cannot or will not use to generate a
    // certificate". This catches these cases.
    if (!aRv.Failed()) {
      aRv.Throw(NS_ERROR_DOM_NOT_SUPPORTED_ERR);
    }
    return nullptr;
  }

  auto* certService = RTCCertService::GetInstance();
  if (!certService) {
    aRv.Throw(NS_ERROR_NOT_IMPLEMENTED);
    return nullptr;
  }

  mData.Generate(certService)
      ->Then(
          GetCurrentSerialEventTarget(), __func__,
          [self = RefPtr<RTCCertificate>(this),
           resultPromise](UniquePtr<CertData>&& aResult) mutable {
            self->mCertificate = std::move(aResult->mCertificate);
            self->mExpires = aResult->mExpires;
            self->mCertFingerprint = aResult->mFingerprint;
            resultPromise->MaybeResolve(self);
          },
          [self = RefPtr<RTCCertificate>(this), resultPromise](
              nsresult aError) { resultPromise->MaybeReject(aError); });

  return resultPromise.forget();
}

already_AddRefed<Promise> RTCCertificate::GenerateCertificate(
    const GlobalObject& aGlobal, const ObjectOrString& aOptions,
    ErrorResult& aRv, JS::Compartment* aCompartment) {
  RefPtr<RTCCertificate> cert =
      new RTCCertificate(xpc::NativeGlobal(aGlobal.Get()));
  return cert->Generate(aGlobal, aOptions, aRv);
}

RTCCertificate::RTCCertificate(nsIGlobalObject* aGlobal) : mGlobal(aGlobal) {};

RTCCertificate::~RTCCertificate() {
  /* TODO -> how to handle clone?
    if (mCertService && mCertificate) {
      mCertService->RemoveCertificate(mCertFingerprint);
    }
  */
}

void RTCCertificate::GetFingerprints(
    nsTArray<dom::RTCDtlsFingerprint>& aFingerprintsOut) {
  // if we have a cert and haven't already built the fingerprints
  if (mCertificate && mFingerprints.Length() == 0) {
    DtlsDigest digest(DtlsIdentity::DEFAULT_HASH_ALGORITHM);
    nsresult rv = DtlsIdentity::ComputeFingerprint(mCertificate, &digest);
    if (NS_FAILED(rv)) {
      // Safe to return early here since we didn't already have fingerprints
      // and the call to DtlsIdentity::ComputeFingerprint failed.
      return;
    }
    RTCDtlsFingerprint fingerprint;
    fingerprint.mAlgorithm.Construct(NS_ConvertASCIItoUTF16(digest.algorithm_));

    std::string value =
        SdpFingerprintAttributeList::FormatFingerprint(digest.value_);
    // Sadly, the SDP fingerprint is expected to be all uppercase hex,
    // while the RTC fingerprint is expected to be all lowercase hex.
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    fingerprint.mValue.Construct(NS_ConvertASCIItoUTF16(value));

    mFingerprints.AppendElement(fingerprint);
  }

  aFingerprintsOut = mFingerprints.Clone();
}

RefPtr<DtlsIdentity> RTCCertificate::CreateDtlsIdentity() const {
  if (!mCertificate) {
    return nullptr;
  }
  RefPtr<DtlsIdentity> id = new DtlsIdentity(mCertFingerprint, mAuthType);
  return id;
}

JSObject* RTCCertificate::WrapObject(JSContext* aCx,
                                     JS::Handle<JSObject*> aGivenProto) {
  return RTCCertificate_Binding::Wrap(aCx, this, aGivenProto);
}

bool RTCCertificate::WriteCertificateFingerprint(
    JSStructuredCloneWriter* aWriter) const {
  return JS_WriteBytes(aWriter, mCertFingerprint.mHash,
                       CertFingerprint::sHashByteLen);
}

bool RTCCertificate::WriteCertificate(JSStructuredCloneWriter* aWriter) const {
  UniqueCERTCertificateList certs(CERT_CertListFromCert(mCertificate.get()));
  if (!certs || certs->len <= 0) {
    return false;
  }
  if (!JS_WriteUint32Pair(aWriter, certs->certs[0].len, 0)) {
    return false;
  }
  return JS_WriteBytes(aWriter, certs->certs[0].data, certs->certs[0].len);
}

bool RTCCertificate::WriteStructuredClone(
    JSContext* aCx, JSStructuredCloneWriter* aWriter) const {
  if (!mCertificate) {
    return false;
  }

  return JS_WriteUint32Pair(aWriter, RTCCERTIFICATE_SC_VERSION, mAuthType) &&
         JS_WriteUint32Pair(aWriter, (mExpires >> 32) & 0xffffffff,
                            mExpires & 0xffffffff) &&
         WriteCertificateFingerprint(aWriter) && WriteCertificate(aWriter);
}

bool RTCCertificate::ReadCertificateFingerprint(
    JSStructuredCloneReader* aReader) {
  if (!JS_ReadBytes(aReader, mCertFingerprint.mHash,
                    CertFingerprint::sHashByteLen)) {
    return false;
  }
  return true;
}

bool RTCCertificate::ReadCertificate(JSStructuredCloneReader* aReader) {
  CryptoBuffer cert;
  if (!ReadBuffer(aReader, cert) || cert.Length() == 0) {
    return false;
  }

  SECItem der = {siBuffer, cert.Elements(),
                 static_cast<unsigned int>(cert.Length())};
  mCertificate.reset(CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &der,
                                             nullptr, true, true));
  return !!mCertificate;
}

// static
already_AddRefed<RTCCertificate> RTCCertificate::ReadStructuredClone(
    JSContext* aCx, nsIGlobalObject* aGlobal,
    JSStructuredCloneReader* aReader) {
  if (!NS_IsMainThread()) {
    // These objects are mainthread-only.
    return nullptr;
  }
  uint32_t version, authType;
  if (!JS_ReadUint32Pair(aReader, &version, &authType) ||
      version != RTCCERTIFICATE_SC_VERSION) {
    return nullptr;
  }
  RefPtr<RTCCertificate> cert = new RTCCertificate(aGlobal);
  cert->mAuthType = static_cast<SSLKEAType>(authType);

  uint32_t high, low;
  if (!JS_ReadUint32Pair(aReader, &high, &low)) {
    return nullptr;
  }
  cert->mExpires = static_cast<PRTime>(high) << 32 | low;

  if (!cert->ReadCertificateFingerprint(aReader) ||
      !cert->ReadCertificate(aReader)) {
    return nullptr;
  }

  return cert.forget();
}

}  // namespace mozilla::dom
