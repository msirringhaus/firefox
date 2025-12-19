/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RTCCertServiceParent.h"

#include "RTCCertCache.h"
#include "mozpkix/nss_scoped_ptrs.h"
#include "nsStringFwd.h"

#define ONE_DAY                                 \
  PRTime(PR_USEC_PER_SEC) * PRTime(60)  /*sec*/ \
      * PRTime(60) /*min*/ * PRTime(24) /*hours*/
#define EXPIRATION_SLACK ONE_DAY

namespace mozilla::dom {

const size_t RTCCertificateCommonNameLength = 16;

nsresult RTCCertificateGenerator::GenerateKeys() {
  UniquePK11SlotInfo slot(PK11_GetInternalSlot());
  MOZ_ASSERT(slot.get());

  mGen.mPrivateKey = UniqueSECKEYPrivateKey(PK11_GenerateKeyPair(
      slot.get(), mMechanism, mParam, TempPtrToSetter(&mGen.mPublicKey),
      PR_FALSE, PR_TRUE, nullptr));

  if (!mGen.mPrivateKey.get() || !mGen.mPublicKey.get()) {
    return NS_ERROR_DOM_OPERATION_ERR;
  }

  return NS_OK;
}

static CERTName* GenerateRandomName(PK11SlotInfo* aSlot) {
  uint8_t randomName[RTCCertificateCommonNameLength];
  SECStatus rv =
      PK11_GenerateRandomOnSlot(aSlot, randomName, sizeof(randomName));
  if (rv != SECSuccess) {
    return nullptr;
  }

  char buf[sizeof(randomName) * 2 + 4];
  strncpy(buf, "CN=", 4);
  for (size_t i = 0; i < sizeof(randomName); ++i) {
    snprintf(&buf[i * 2 + 3], 3, "%.2x", randomName[i]);
  }
  buf[sizeof(buf) - 1] = '\0';

  return CERT_AsciiToName(buf);
}

nsresult RTCCertificateGenerator::GenerateCertificate() {
  UniquePK11SlotInfo slot(PK11_GetInternalSlot());
  MOZ_ASSERT(slot.get());

  UniqueCERTName subjectName(GenerateRandomName(slot.get()));
  if (!subjectName) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  UniqueCERTSubjectPublicKeyInfo spki(
      SECKEY_CreateSubjectPublicKeyInfo(mGen.mPublicKey.get()));
  if (!spki) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  UniqueCERTCertificateRequest certreq(
      CERT_CreateCertificateRequest(subjectName.get(), spki.get(), nullptr));
  if (!certreq) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  PRTime now = PR_Now();
  PRTime notBefore = now - EXPIRATION_SLACK;
  mGen.mExpires += now;

  UniqueCERTValidity validity(CERT_CreateValidity(notBefore, mGen.mExpires));
  if (!validity) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  unsigned long serial;
  // Note: This serial in principle could collide, but it's unlikely, and we
  // don't expect anyone to be validating certificates anyway.
  SECStatus rv = PK11_GenerateRandomOnSlot(
      slot.get(), reinterpret_cast<unsigned char*>(&serial), sizeof(serial));
  if (rv != SECSuccess) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  // NB: CERTCertificates created with CERT_CreateCertificate are not safe to
  // use with other NSS functions like CERT_DupCertificate.  The strategy
  // here is to create a tbsCertificate ("to-be-signed certificate"), encode
  // it, and sign it, resulting in a signed DER certificate that can be
  // decoded into a CERTCertificate.
  UniqueCERTCertificate tbsCertificate(CERT_CreateCertificate(
      serial, subjectName.get(), validity.get(), certreq.get()));
  if (!tbsCertificate) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  MOZ_ASSERT(mSignatureAlg != SEC_OID_UNKNOWN);
  PLArenaPool* arena = tbsCertificate->arena;

  rv = SECOID_SetAlgorithmID(arena, &tbsCertificate->signature, mSignatureAlg,
                             nullptr);
  if (rv != SECSuccess) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  // Set version to X509v3.
  *(tbsCertificate->version.data) = SEC_CERTIFICATE_VERSION_3;
  tbsCertificate->version.len = 1;

  SECItem innerDER = {siBuffer, nullptr, 0};
  if (!SEC_ASN1EncodeItem(arena, &innerDER, tbsCertificate.get(),
                          SEC_ASN1_GET(CERT_CertificateTemplate))) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  SECItem* certDer = PORT_ArenaZNew(arena, SECItem);
  if (!certDer) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  rv = SEC_DerSignData(arena, certDer, innerDER.data, innerDER.len,
                       mGen.mPrivateKey.get(), mSignatureAlg);
  if (rv != SECSuccess) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  mGen.mCertificate.reset(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), certDer, nullptr, false, true));
  if (!mGen.mCertificate) {
    return NS_ERROR_DOM_UNKNOWN_ERR;
  }

  if (PK11_HashBuf(SEC_OID_SHA256, mGen.mCertFingerprint.AsChar(),
                   certDer->data,
                   AssertedCast<int32_t>(certDer->len)) != SECSuccess) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

RefPtr<RTCCertificateGeneratorPromise> RTCCertificateGenerator::Generate(
    nsTArray<uint8_t>& aParam, PRTime aExpires, CK_MECHANISM_TYPE aMechanism,
    SECOidTag aSignatureAlg) {
  mGenPromise = MakeRefPtr<RTCCertificateGeneratorPromise::Private>(__func__);

  mGen = GeneratedCertificate();
  mGen.mExpires = aExpires;

  mMechanism = aMechanism;
  mSignatureAlg = aSignatureAlg;

  if (mMechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
    mRsaParams = DeserializeRSAParam(&aParam);
    mParam = &mRsaParams;
  } else if (mMechanism == CKM_EC_KEY_PAIR_GEN) {
    mCurveParams = DeserializeECParams(&aParam);
    mParam = mCurveParams.get();
  } else {
    mGenPromise->Reject(NS_ERROR_NOT_IMPLEMENTED, __func__);
    return mGenPromise;
  }

  // Store calling thread
  mOriginalEventTarget = GetCurrentSerialEventTarget();

  // dispatch to thread pool
  if (!EnsureNSSInitializedChromeOrContent()) {
    mGenPromise->Reject(NS_ERROR_FAILURE, __func__);
    return mGenPromise;
  }

  mCryptoResult = NS_DispatchBackgroundTask(this);
  if (NS_FAILED(mCryptoResult)) {
    mGenPromise->Reject(mCryptoResult, __func__);
    return mGenPromise;
  }

  return mGenPromise;
}

RTCCertificateGenerator::RTCCertificateGenerator()
    : CancelableRunnable("RTCCertificateGenerator") {}

RTCCertificateGenerator::~RTCCertificateGenerator() { mCurveParams = nullptr; }

void RTCCertificateGenerator::Finish() {
  MOZ_ASSERT(IsOnOriginalThread());

  if (NS_FAILED(mCryptoResult)) {
    mGenPromise->Reject(mCryptoResult, __func__);
  } else {
    mGenPromise->Resolve(std::move(mGen), __func__);
  }
  mGenPromise = nullptr;
}

NS_IMETHODIMP
RTCCertificateGenerator::Run() {
  // Run heavy crypto operations on the thread pool, off the original thread.
  if (!IsOnOriginalThread()) {
    mCryptoResult = GenerateKeys();
    if (NS_SUCCEEDED(mCryptoResult)) {
      mCryptoResult = GenerateCertificate();
    }

    // Back to the original thread, i.e. continue below.
    mOriginalEventTarget->Dispatch(this, NS_DISPATCH_NORMAL);
    return NS_OK;
  }

  Finish();
  return NS_OK;
}

nsresult RTCCertificateGenerator::Cancel() {
  MOZ_ASSERT(IsOnOriginalThread());
  mCryptoResult = NS_BINDING_ABORTED;
  Finish();
  return NS_OK;
}

RefPtr<RTCCertificatePromise> RTCCertServiceParent::GenerateCertificate(
    nsCString& aOrigin, nsTArray<uint8_t>& aParam, PRTime aExpires,
    uint32_t aMechanism, uint32_t aSignatureAlg) {
  RefPtr<RTCCertificatePromise::Private> resultPromise =
      MakeRefPtr<RTCCertificatePromise::Private>(__func__);

  RefPtr<RTCCertificateGenerator> gen = new RTCCertificateGenerator();
  gen->Generate(aParam, aExpires, aMechanism,
                static_cast<SECOidTag>(aSignatureAlg))
      ->Then(
          GetCurrentSerialEventTarget(), __func__,
          [resultPromise, aOrigin](GeneratedCertificate genCert) mutable {
            auto data = MakeUnique<CertData>(
                UniqueCERTCertificate(
                    CERT_DupCertificate(genCert.mCertificate.get())),
                genCert.mExpires, genCert.mCertFingerprint);
            RTCCertCache::CacheCert(std::move(aOrigin), std::move(genCert));
            resultPromise->Resolve(std::move(data), __func__);
          },
          [resultPromise](nsresult aError) {
            resultPromise->Reject(aError, __func__);
          });

  return resultPromise;
}

RefPtr<RTCCertificatePromise> RTCCertServiceParent::GetCertificate(
    const CertFingerprint aCertFingerprint) {
  if (GeneratedCertificate* cert = RTCCertCache::LookupCert(aCertFingerprint)) {
    auto data = MakeUnique<CertData>(
        UniqueCERTCertificate(CERT_DupCertificate(cert->mCertificate.get())),
        cert->mExpires, cert->mCertFingerprint);
    return RTCCertificatePromise::CreateAndResolve(std::move(data), __func__);
  }
  return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE, __func__);
}

mozilla::ipc::IPCResult RTCCertServiceParent::RecvGenerateCertificate(
    const nsACString& aOrigin, nsTArray<uint8_t>&& aParam,
    const PRTime& aExpires, const uint32_t& aMechanism,
    const uint32_t& aSignatureAlg, GenerateCertificateResolver&& aResolve) {
  nsCString origin(aOrigin);
  GenerateCertificate(origin, aParam, aExpires, aMechanism, aSignatureAlg)
      ->Then(
          GetCurrentSerialEventTarget(), __func__,
          [aResolve = std::move(aResolve)](
              const dom::RTCCertificatePromise::ResolveOrRejectValue& aResult) {
            if (aResult.IsResolve()) {
              aResolve(CertDataIPC(aResult.ResolveValue().get()));
            } else {
              aResolve(CertDataIPC());
            }
          });
  return IPC_OK();
}

mozilla::ipc::IPCResult RTCCertServiceParent::RecvRemoveCertificate(
    const CertFingerprint& aCertFingerprint) {
  RTCCertCache::RemoveCert(aCertFingerprint);
  return IPC_OK();
}

mozilla::ipc::IPCResult RTCCertServiceParent::RecvGetCertificate(
    const CertFingerprint& aCertFingerprint,
    GetCertificateResolver&& aResolve) {
  GetCertificate(aCertFingerprint)
      ->Then(
          GetCurrentSerialEventTarget(), __func__,
          [aResolve = std::move(aResolve)](
              const dom::RTCCertificatePromise::ResolveOrRejectValue& aResult) {
            if (aResult.IsResolve()) {
              aResolve(CertDataIPC(aResult.ResolveValue().get()));
            } else {
              aResolve(CertDataIPC());
            }
          });
  return IPC_OK();
}

}  // namespace mozilla::dom
