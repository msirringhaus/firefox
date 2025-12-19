/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_RTCCertCache_h
#define mozilla_dom_RTCCertCache_h

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

class RTCCertCacheData {
  struct RTCCertCacheItem {
    RTCCertCacheItem(nsCString&& mOrigin, GeneratedCertificate&& mCert)
        : mOrigin(std::move(mOrigin)), mCert(std::move(mCert)) {}
    nsCString mOrigin;
    GeneratedCertificate mCert;
  };

 public:
  bool Insert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  bool CacheLimitsReached(const nsCString& aOrigin);
  void Remove(const CertFingerprint aCertFingerprint);
  GeneratedCertificate* Get(const CertFingerprint aCertFingerprint);
  void Clear();
  void ClearExpiredCertificates();

 protected:
  nsTHashMap<CertFingerprintHashKey, RTCCertCacheItem> mCertCache;
  nsTHashMap<nsCStringHashKey, uint32_t> mOriginCount;

  // Hard limits
  static const size_t sMaxCertsPerOrigin = 200;
  static const size_t sMaxGlobalCerts = 1000;
};

class RTCCertCache {
 public:
  // Returns true on success and false, if either the per-origin
  static bool CacheCert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  static GeneratedCertificate* LookupCert(
      const CertFingerprint aCertFingerprint);
  static void RemoveCert(const CertFingerprint aCertFingerprint);
  static void Clear();
  static void ClearExpiredCertificates();
  static bool CacheLimitsReached(const nsCString& aOrigin);

 private:
  static mozilla::StaticDataMutex<RTCCertCacheData> sCertCache;
};
}  // namespace mozilla::dom

#endif  // mozilla_dom_RTCCertCache_h
