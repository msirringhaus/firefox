/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_CertServiceParent_h
#define mozilla_dom_CertServiceParent_h

#include "RTCCertStore.h"
#include "mozilla/dom/PRTCCertServiceTransactionParent.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsStringFwd.h"

namespace mozilla::dom {

class RTCCertServiceParent final : public PRTCCertServiceTransactionParent {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(RTCCertServiceParent);
  RTCCertServiceParent() = default;

  mozilla::ipc::IPCResult RecvGenerateCertificate(
      const nsACString& aOrigin, nsTArray<uint8_t>&& aParam,
      const PRTime& aExpires, const uint32_t& aMechanism,
      const uint32_t& aSignatureAlg, GenerateCertificateResolver&& aResolve);
  mozilla::ipc::IPCResult RecvRemoveCertificate(
      const CertFingerprint& aCertFingerprint);
  mozilla::ipc::IPCResult RecvGetCertificate(
      const CertFingerprint& aCertFingerprint,
      GetCertificateResolver&& aResolve);

  RefPtr<RTCCertificatePromise> GenerateCertificate(nsCString& aOrigin,
                                                    nsTArray<uint8_t>& aParam,
                                                    PRTime aExpires,
                                                    uint32_t aMechanism,
                                                    uint32_t aSignatureAlg);
  RefPtr<RTCCertificatePromise> GetCertificate(
      const CertFingerprint aCertFingerprint);

 private:
  ~RTCCertServiceParent() { dom::RTCCertStore::ClearExpiredCertificates(); };
};

using RTCCertificateGeneratorPromise =
    MozPromise<GeneratedCertificate, nsresult,
               /* IsExclusive = */ true>;

class RTCCertificateGenerator final : public CancelableRunnable {
 public:
  RTCCertificateGenerator();
  RefPtr<RTCCertificateGeneratorPromise> Generate(nsTArray<uint8_t>& aParam,
                                                  PRTime aExpires,
                                                  CK_MECHANISM_TYPE aMechanism,
                                                  SECOidTag aSignatureAlg);

 private:
  ~RTCCertificateGenerator();

  bool IsOnOriginalThread() {
    return !mOriginalEventTarget || mOriginalEventTarget->IsOnCurrentThread();
  }

  nsresult GenerateKeys();
  nsresult GenerateCertificate();

  NS_IMETHOD Run() override;
  nsresult Cancel() override;
  void Finish();

  GeneratedCertificate mGen;

  // Source data
  nsCString mOrigin;
  void* mParam = nullptr;
  PK11RSAGenParams mRsaParams;
  ScopedSECItem mCurveParams = nullptr;
  CK_MECHANISM_TYPE mMechanism = 0;
  SECOidTag mSignatureAlg = SEC_OID_UNKNOWN;
  nsresult mCryptoResult = NS_OK;

  RefPtr<RTCCertificateGeneratorPromise::Private> mGenPromise;
  nsCOMPtr<nsISerialEventTarget> mOriginalEventTarget;
};

}  // namespace mozilla::dom

#endif  // mozilla_dom_CertServiceTransactionParent_h
