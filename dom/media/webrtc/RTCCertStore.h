/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_RTCCertStore_h
#define mozilla_dom_RTCCertStore_h

#include <cstdint>
#include "mozilla/DataMutex.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "prtime.h"

// gtest class
class TestRTCCertStoreData;

namespace mozilla::dom {

struct GeneratedCertificate {
  UniqueSECKEYPublicKey mPublicKey;
  UniqueSECKEYPrivateKey mPrivateKey;
  UniqueCERTCertificate mCertificate;
  CertFingerprint mCertFingerprint;
  PRTime mExpires = 0;
};

class SharedCertificate {
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(SharedCertificate);
  public:
    SharedCertificate(nsCString&& aOrigin, GeneratedCertificate&& aCert)
        : mOrigin(std::move(aOrigin)), mCert(std::move(aCert)), mLastTouched(PR_Now()) {}

    bool IsInUse() const {
        return mRefCnt > 1;
    }

    PRTime LastTouched() {
      return mLastTouched;
    }

    void Touch() {
      mLastTouched = PR_Now();
    }

    const GeneratedCertificate & Cert() {
      return mCert;
    }

    // ONLY FOR TESTING!
    void SetLastTouched(PRTime aTime) {
      mLastTouched = aTime;
    }

    // ONLY FOR TESTING!
    uint64_t GetRefCnt() {
      return mRefCnt;
    }

  protected:
    nsCString mOrigin; // TODO: Do we need this?
    GeneratedCertificate mCert;
    // Most of this class is read-only, but consumers need a
    // thread-safe way to update when they interact with this
    // certificate, to be able to identify idle certs and remove
    // them when doing garbage collection.
    std::atomic<PRTime> mLastTouched;
  private:
    ~SharedCertificate() = default;
};

class RTCCertStoreData {
 public:
  void Insert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  void Remove(const CertFingerprint aCertFingerprint);
  RefPtr<SharedCertificate> Get(const CertFingerprint aCertFingerprint) const;
  void Clear();
  void ClearExpiredCertificates();

 protected:
  nsTHashMap<CertFingerprintHashKey, RefPtr<SharedCertificate>> mCertStore;
  const PRTime kGracePeriod = 5 * 60 * PRTime(PR_USEC_PER_SEC); // 5 minutes
};

class RTCCertStore {
 public:
  static void StoreCert(nsCString&& aOrigin, GeneratedCertificate&& aCert);
  static RefPtr<SharedCertificate> LookupCert(
      const CertFingerprint aCertFingerprint);
  static void RemoveCert(const CertFingerprint aCertFingerprint);
  static void Clear();
  static void ClearExpiredCertificates();

 private:
  static mozilla::StaticDataMutex<RTCCertStoreData> sCertStore;
};
}  // namespace mozilla::dom

#endif  // mozilla_dom_RTCCertStore_h
