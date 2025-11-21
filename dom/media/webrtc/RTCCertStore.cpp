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
  bool globalLimitReached = mCertStore.Count() >= sMaxGlobalCerts;
  bool originLimitReached =
      mOriginCount.MaybeGet(aOrigin).valueOr(0) >= sMaxCertsPerOrigin;

  if (globalLimitReached || originLimitReached) {
    // Maybe we can get away with clearing old certs
    ClearExpiredCertificates();
  }

  // Check limits again
  globalLimitReached = mCertStore.Count() >= sMaxGlobalCerts;
  originLimitReached =
      mOriginCount.MaybeGet(aOrigin).valueOr(0) >= sMaxCertsPerOrigin;

  if (globalLimitReached) {
    // Remove the oldest cert (will also remove it from mGlobalOrder)
    Remove(mGlobalOrder[0]);
  }

  if (originLimitReached) {
    // Find and remove the oldest certificate belonging to this origin.
    for (size_t ii = 0; ii < mGlobalOrder.Length(); ++ii) {
      const CertFingerprint& fp = mGlobalOrder[ii];
      if (auto entry = mCertStore.Lookup(fp)) {
        if (entry.Data().mOrigin.Equals(aOrigin)) {
          Remove(fp);
          MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
                  ("RTCCertStore::StoreCert "
                   "Removing element: %s for origin: %s. mOriginCount = %i\n",
                   fp.Dump().get(), aOrigin.get(), mOriginCount.Get(aOrigin)));
          break;
        }
      }
    }
  }

  MOZ_LOG(
      gCertLog, mozilla::LogLevel::Info,
      ("RTCCertStore::StoreCert (Elements before insertion: %i). "
       "Inserting: %s for origin: %s\n",
       mCertStore.Count(), aCert.mCertFingerprint.Dump().get(), aOrigin.get()));
  const auto fingerprint = aCert.mCertFingerprint;
  mCertStore.WithEntryHandle(fingerprint, [&](auto&& entry) {
    if (!entry) {
      // Only increment the origin counter if this is a new entry
      mOriginCount.LookupOrInsert(aOrigin, 0)++;
      entry.Insert(RTCCertStoreItem(std::move(aOrigin), std::move(aCert)));
      mGlobalOrder.AppendElement(fingerprint);
    } else {
      // If the cert already exists, we update it.
      entry.Data() = RTCCertStoreItem(std::move(aOrigin), std::move(aCert));
      // To maintain FIFO behavior, we should move it to the back of the line.
      mGlobalOrder.RemoveElement(fingerprint);
      mGlobalOrder.AppendElement(fingerprint);
    }
  });
}

void RTCCertStoreData::Remove(const CertFingerprint aCertFingerprint) {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::RemoveCert (Elements before removal: %i). "
           "Removing: %s\n",
           mCertStore.Count(), aCertFingerprint.Dump().get()));
  if (auto item = mCertStore.Lookup(aCertFingerprint)) {
    // Before we can remove the item itself, we have to decrease
    // the origin counter associated with it
    if (auto count = mOriginCount.Lookup(item.Data().mOrigin)) {
      if (--count.Data() == 0) {
        count.Remove();
      }
    }
    mGlobalOrder.RemoveElement(aCertFingerprint);
    item.Remove();
  }
}

GeneratedCertificate* RTCCertStoreData::Get(
    const CertFingerprint aCertFingerprint) const {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::LookupCert (Elements: %i). Looking up: %s\n",
           mCertStore.Count(), aCertFingerprint.Dump().get()));
  if (auto entry = mCertStore.Lookup(aCertFingerprint)) {
    return &entry.Data().mCert;
  }
  return nullptr;
}

void RTCCertStoreData::Clear() {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertStore::Clear (Elements before clearing: %i)\n",
           mCertStore.Count()));
  mCertStore.Clear();
  mOriginCount.Clear();
  mGlobalOrder.Clear();
}

void RTCCertStoreData::ClearExpiredCertificates() {
  unsigned int beforeClearing = mCertStore.Count();
  PRTime now = PR_Now();
  mCertStore.RemoveIf([this, now](auto& aIter) {
    const RTCCertStoreItem& item = aIter.Data();

    if (item.mCert.mExpires < now) {
      // Also decrement / remove origin counter for this expired cert
      if (auto countEntry = mOriginCount.Lookup(item.mOrigin)) {
        if (--countEntry.Data() == 0) {
          countEntry.Remove();
        }
      }
      mGlobalOrder.RemoveElement(item.mCert.mCertFingerprint);
      return true;
    }
    return false;
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

GeneratedCertificate* RTCCertStore::LookupCert(
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
