/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RTCCertStore.h"

#include "mozilla/Attributes.h"
#include "mozilla/Logging.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsHashKeys.h"
#include "nsTHashMap.h"
#include "prtime.h"

static mozilla::LazyLogModule gCertLog("RTCCertStore");

namespace mozilla::dom {

void RTCCertStoreData::Insert(nsCString&& aOrigin,
                              GeneratedCertificate&& aCert) {
  ClearExpiredCertificates();

  MOZ_LOG(
      gCertLog, mozilla::LogLevel::Info,
      ("RTCCertStore::StoreCert (Elements before insertion: %i). "
       "Inserting: %s for origin: %s\n",
       mCertStore.Count(), aCert.mCertFingerprint.Dump().get(), aOrigin.get()));
  const auto fingerprint = aCert.mCertFingerprint;
  auto sharedCert = MakeRefPtr<SharedCertificate>(std::move(aOrigin), std::move(aCert));
  mCertStore.InsertOrUpdate(fingerprint, sharedCert);
}

void RTCCertStoreData::Remove(const CertFingerprint aCertFingerprint) {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::RemoveCert (Elements before removal: %i). "
           "Removing: %s\n",
           mCertStore.Count(), aCertFingerprint.Dump().get()));
  if (auto item = mCertStore.Lookup(aCertFingerprint)) {
    if (!item.Data()->IsInUse()) {
      item.Remove();
    }
  }
}

RefPtr<SharedCertificate> RTCCertStoreData::Get(
    const CertFingerprint aCertFingerprint) const {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::LookupCert (Elements: %i). Looking up: %s\n",
           mCertStore.Count(), aCertFingerprint.Dump().get()));
  if (auto entry = mCertStore.Lookup(aCertFingerprint)) {
    return entry.Data();
  }
  return nullptr;
}

void RTCCertStoreData::Clear() {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::Clear (Elements before clearing: %i)\n",
           mCertStore.Count()));
  // TODO: Check if some are still in use?
  mCertStore.Clear();
}

void RTCCertStoreData::ClearExpiredCertificates() {
  unsigned int beforeClearing = mCertStore.Count();
  PRTime now = PR_Now();

  mCertStore.RemoveIf([this, now](auto& aIter) {
    bool isOrphaned = !aIter.Data()->IsInUse();
    // Remove certs that themselves expired
    bool isExpired = aIter.Data()->Cert().mExpires < now;
    // Remove orphan certs that have not been touched in the last grace period interval
    bool isPastGracePeriod = aIter.Data()->LastTouched() < now - RTCCertStoreData::kGracePeriod;
    return isOrphaned && (isExpired || isPastGracePeriod);
  });

  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::ClearExpiredCertificates (Elements before "
           "clearing: %i, vs. after: %i)\n",
           beforeClearing, mCertStore.Count()));
}

MOZ_RUNINIT mozilla::StaticDataMutex<RTCCertStoreData> RTCCertStore::sCertStore{
    "RTCCertStore::sCertStore"};

void RTCCertStore::StoreCert(nsCString&& aOrigin,
                             GeneratedCertificate&& aCert) {
  auto certStore = RTCCertStore::sCertStore.Lock();

  return (*certStore).Insert(std::move(aOrigin), std::move(aCert));
}

RefPtr<SharedCertificate> RTCCertStore::LookupCert(
    const CertFingerprint aCertFingerprint) {
  auto certStore = RTCCertStore::sCertStore.Lock();
  return (*certStore).Get(aCertFingerprint);
}

void RTCCertStore::RemoveCert(const CertFingerprint aCertFingerprint) {
  auto certStore = RTCCertStore::sCertStore.Lock();
  return (*certStore).Remove(aCertFingerprint);
}

void RTCCertStore::Clear() {
  auto certStore = RTCCertStore::sCertStore.Lock();
  (*certStore).Clear();
}

void RTCCertStore::ClearExpiredCertificates() {
  auto certStore = RTCCertStore::sCertStore.Lock();
  (*certStore).ClearExpiredCertificates();
}

}  // namespace mozilla::dom
