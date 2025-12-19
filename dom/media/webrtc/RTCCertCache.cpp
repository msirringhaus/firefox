/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RTCCertCache.h"

#include "mozilla/Attributes.h"
#include "mozilla/Logging.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsHashKeys.h"
#include "nsTHashMap.h"
#include "prtime.h"

static mozilla::LazyLogModule gCertLog("RTCCertCache");

namespace mozilla::dom {

bool RTCCertCacheData::Insert(nsCString&& aOrigin,
                              GeneratedCertificate&& aCert) {
  if (CacheLimitsReached(aOrigin)) {
    return false;
  }

  MOZ_LOG(
      gCertLog, mozilla::LogLevel::Info,
      ("RTCCertCache::CacheCert (Elements before insertion: %i). "
       "Inserting: %s for origin: %s\n",
       mCertCache.Count(), aCert.mCertFingerprint.Dump().get(), aOrigin.get()));
  const auto fingerprint = aCert.mCertFingerprint;
  mCertCache.WithEntryHandle(fingerprint, [&](auto&& entry) {
    if (!entry) {
      // Only increment the origin counter if this is a new entry
      mOriginCount.LookupOrInsert(aOrigin, 0)++;
      entry.Insert(RTCCertCacheItem(std::move(aOrigin), std::move(aCert)));
    } else {
      entry.Data() = RTCCertCacheItem(std::move(aOrigin), std::move(aCert));
    }
  });

  return true;
}

bool RTCCertCacheData::CacheLimitsReached(const nsCString& aOrigin) {
  if (mCertCache.Count() >= RTCCertCacheData::sMaxGlobalCerts) {
    return true;
  }

  if (mOriginCount.MaybeGet(aOrigin).valueOr(0) >=
      RTCCertCacheData::sMaxCertsPerOrigin) {
    return true;
  }

  return false;
}

void RTCCertCacheData::Remove(const CertFingerprint aCertFingerprint) {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertCache::RemoveCert (Elements before removal: %i). "
           "Removing: %s\n",
           mCertCache.Count(), aCertFingerprint.Dump().get()));
  if (auto item = mCertCache.Lookup(aCertFingerprint)) {
    // Before we can remove the item itself, we have to decrease
    // the origin counter associated with it
    if (auto count = mOriginCount.Lookup(item.Data().mOrigin)) {
      if (--count.Data() == 0) {
        count.Remove();
      }
    }
    item.Remove();
  }
}

GeneratedCertificate* RTCCertCacheData::Get(
    const CertFingerprint aCertFingerprint) {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertCache::LookupCert (Elements: %i). Looking up: %s\n",
           mCertCache.Count(), aCertFingerprint.Dump().get()));
  if (auto entry = mCertCache.Lookup(aCertFingerprint)) {
    return &entry.Data().mCert;
  }
  return nullptr;
}

void RTCCertCacheData::Clear() {
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertCache::Clear (Elements before clearing: %i)\n",
           mCertCache.Count()));
  mCertCache.Clear();
  mOriginCount.Clear();
}

void RTCCertCacheData::ClearExpiredCertificates() {
  unsigned int beforeClearing = mCertCache.Count();
  PRTime now = PR_Now();
  mCertCache.RemoveIf([this, now](auto& aIter) {
    const RTCCertCacheItem& item = aIter.Data();

    if (item.mCert.mExpires < now) {
      // Also decrement / remove origin counter for this expired cert
      if (auto countEntry = mOriginCount.Lookup(item.mOrigin)) {
        if (--countEntry.Data() == 0) {
          countEntry.Remove();
        }
      }
      return true;
    }
    return false;
  });
  MOZ_LOG(gCertLog, mozilla::LogLevel::Info,
          ("RTCCertCache::ClearExpiredCertificates (Elements before "
           "clearing: %i, vs. after: %i)\n",
           beforeClearing, mCertCache.Count()));
}

MOZ_RUNINIT mozilla::StaticDataMutex<RTCCertCacheData> RTCCertCache::sCertCache{
    "RTCCertCache::sCertCache"};

bool RTCCertCache::CacheCert(nsCString&& aOrigin,
                             GeneratedCertificate&& aCert) {
  auto certCache = RTCCertCache::sCertCache.Lock();

  return (*certCache).Insert(std::move(aOrigin), std::move(aCert));
}

GeneratedCertificate* RTCCertCache::LookupCert(
    const CertFingerprint aCertFingerprint) {
  auto certCache = RTCCertCache::sCertCache.Lock();
  return (*certCache).Get(aCertFingerprint);
}

void RTCCertCache::RemoveCert(const CertFingerprint aCertFingerprint) {
  auto certCache = RTCCertCache::sCertCache.Lock();
  return (*certCache).Remove(aCertFingerprint);
}

void RTCCertCache::Clear() {
  auto certCache = RTCCertCache::sCertCache.Lock();
  (*certCache).Clear();
}

void RTCCertCache::ClearExpiredCertificates() {
  auto certCache = RTCCertCache::sCertCache.Lock();
  (*certCache).ClearExpiredCertificates();
}

bool RTCCertCache::CacheLimitsReached(const nsCString& aOrigin) {
  auto certCache = RTCCertCache::sCertCache.Lock();
  return (*certCache).CacheLimitsReached(aOrigin);
}

}  // namespace mozilla::dom
