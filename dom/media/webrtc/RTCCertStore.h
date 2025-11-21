/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_RTCCertStore_h
#define mozilla_dom_RTCCertStore_h

#include "mozilla/DataMutex.h"
#include "mozilla/dom/RTCCertServiceData.h"

namespace mozilla::dom {

struct GeneratedCertificate {
  UniqueSECKEYPublicKey mPublicKey;
  UniqueSECKEYPrivateKey mPrivateKey;
  UniqueCERTCertificate mCertificate;
  CertFingerprint mCertFingerprint;
  PRTime mExpires = 0;
};

class RTCCertStoreData {
  struct RTCCertStoreItem {
    RTCCertStoreItem(nsCString&& aOrigin, GeneratedCertificate&& aCert)
        : mOrigin(std::move(aOrigin)), mCert(std::move(aCert)) {}
    nsCString mOrigin;
    GeneratedCertificate mCert;
  };

 public:
  void Insert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  void Remove(const CertFingerprint aCertFingerprint);
  GeneratedCertificate* Get(const CertFingerprint aCertFingerprint) const;
  void Clear();
  void ClearExpiredCertificates();

 protected:
  nsTHashMap<CertFingerprintHashKey, RTCCertStoreItem> mCertStore;
  nsTHashMap<nsCStringHashKey, uint32_t> mOriginCount;
  nsTArray<CertFingerprint> mGlobalOrder;

  // Hard limits
  static const uint64_t sMaxCertsPerOrigin = 200;
  static const uint64_t sMaxGlobalCerts = 1000;
};

class RTCCertStore {
 public:
  static void StoreCert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  static GeneratedCertificate* LookupCert(
      const CertFingerprint aCertFingerprint);
  static void RemoveCert(const CertFingerprint aCertFingerprint);
  static void Clear();
  static void ClearExpiredCertificates();

 private:
  static mozilla::StaticDataMutex<RTCCertStoreData> sCertStore;
};
}  // namespace mozilla::dom

#endif  // mozilla_dom_RTCCertStore_h
