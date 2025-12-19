#include "RTCCertCache.h"
#include "gtest/gtest.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsTArray.h"
#include "prtime.h"

using mozilla::dom::CertFingerprint;
using mozilla::dom::GeneratedCertificate;

class TestRTCCertCacheData : public mozilla::dom::RTCCertCacheData {
 public:
  const auto& GetCertCacheMap() const { return mCertCache; }

  const auto& GetOriginCountMap() const { return mOriginCount; }

  const auto& GetGlobalOrder() const { return mGlobalOrder; }

  static uint64_t MaxPerOrigin() { return sMaxCertsPerOrigin; }
  static uint64_t MaxGlobal() { return sMaxGlobalCerts; }
};

class RTCCertCacheTest : public ::testing::Test {
 protected:
  TestRTCCertCacheData mCache;

  // We don't need valid certificates for the cache logic,
  // just unique fingerprints and expiration times.
  GeneratedCertificate CreateFakeCert(uint64_t aId, PRTime aExpires) {
    GeneratedCertificate cert;
    cert.mExpires = aExpires;
    // For testing, we get enough id-space to only use the first quarter of the
    // hash-field
    cert.mCertFingerprint.mHash[0] = aId;
    return cert;
  }
};

TEST_F(RTCCertCacheTest, InsertAndRetrieve) {
  nsCString origin = "https://example.com"_ns;
  PRTime expiration_time = PR_Now() + 1000;
  auto cert = CreateFakeCert(1, expiration_time);  // Valid future cert
  CertFingerprint fp = cert.mCertFingerprint;

  mCache.Insert(std::move(origin), std::move(cert));
  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 1u);
  EXPECT_EQ(mCache.GetOriginCountMap().Get("https://example.com"_ns), 1u);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 1u);

  GeneratedCertificate* retrieved = mCache.Get(fp);
  ASSERT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved->mExpires, expiration_time);
}

TEST_F(RTCCertCacheTest, RemoveUpdatesCounts) {
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 1000);
  CertFingerprint fp = cert.mCertFingerprint;

  mCache.Insert(std::move(origin), std::move(cert));
  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 1u);

  // Remove cert again
  mCache.Remove(fp);

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 0u);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 0u);
  EXPECT_EQ(mCache.GetGlobalOrder().Length(), 0u);
}

TEST_F(RTCCertCacheTest, PerOriginLimitDoesNotAffectOthers) {
  nsCString spammer = "https://spammer.com"_ns;
  nsCString victim = "https://victim.com"_ns;
  PRTime future = PR_Now() + 100000;

  // Fill Spammer
  uint64_t id = 0;
  nsTArray<CertFingerprint> fingerprints;
  // Fill up to the limit
  for (id = 0; id < TestRTCCertCacheData::MaxPerOrigin(); ++id) {
    GeneratedCertificate cert = CreateFakeCert(id, future);
    fingerprints.AppendElement(cert.mCertFingerprint);
    mCache.Insert(nsCString(spammer), std::move(cert));
  }
  // Verify full
  EXPECT_EQ(mCache.GetOriginCountMap().Get(spammer),
            TestRTCCertCacheData::MaxPerOrigin());

  // The first fingerprint should still be in there
  EXPECT_NE(mCache.Get(fingerprints[0]), nullptr);

  // Try to insert one more
  GeneratedCertificate overflowCert = CreateFakeCert(++id, future);
  mCache.Insert(nsCString(spammer), std::move(overflowCert));
  // Count should stay at Max
  EXPECT_EQ(mCache.GetOriginCountMap().Get(spammer),
            TestRTCCertCacheData::MaxPerOrigin());
  // And the first fingerprint should now have been evicted
  EXPECT_EQ(mCache.Get(fingerprints[0]), nullptr);
  for (size_t ii = 1; ii < fingerprints.Length(); ++ii) {
    // But the others should still be accessible
    EXPECT_NE(mCache.Get(fingerprints[ii]), nullptr);
  }

  // Verify Victim Allowed
  mCache.Insert(nsCString(victim), CreateFakeCert(++id, future));
  mCache.Insert(nsCString(victim), CreateFakeCert(++id, future));
  EXPECT_EQ(mCache.GetOriginCountMap().Get(victim), 2u);
}

TEST_F(RTCCertCacheTest, GlobalLimitEnforced) {
  PRTime future = PR_Now() + 10000;

  nsTArray<CertFingerprint> fingerprints;
  for (uint64_t id = 0; id < TestRTCCertCacheData::MaxGlobal(); ++id) {
    // Switch origin every 'MaxPerOrigin()' inserts to avoid hitting origin cap
    nsPrintfCString origin("https://user%" PRIu64 ".com",
                           id / TestRTCCertCacheData::MaxPerOrigin());
    GeneratedCertificate cert = CreateFakeCert(id, future);
    fingerprints.AppendElement(cert.mCertFingerprint);
    mCache.Insert(std::move(origin), std::move(cert));
  }

  EXPECT_EQ(mCache.GetCertCacheMap().Count(),
            TestRTCCertCacheData::MaxGlobal());

  // Try inserting one more (global full)
  GeneratedCertificate overflow =
      CreateFakeCert(TestRTCCertCacheData::MaxGlobal() + 1, future);
  nsCString spammer = "https://spammer.com"_ns;
  mCache.Insert(std::move(spammer), std::move(overflow));

  // Count should stay at Max
  EXPECT_EQ(mCache.GetCertCacheMap().Count(),
            TestRTCCertCacheData::MaxGlobal());
  // And the first fingerprint should now have been evicted
  EXPECT_EQ(mCache.Get(fingerprints[0]), nullptr);
  for (size_t ii = 1; ii < fingerprints.Length(); ++ii) {
    // But the others should still be accessible
    EXPECT_NE(mCache.Get(fingerprints[ii]), nullptr);
  }
}

TEST_F(RTCCertCacheTest, ClearExpiredCertificates) {
  uint64_t id = 0;

  // Insert a bunch of certs  that expire 'now', meaning they will be expired
  // right away for different domains
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now());
    mCache.Insert(std::move(origin), std::move(cert));
    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now());
    mCache.Insert(std::move(origin), std::move(cert2));
  }

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 8u);

  // Clear expired certs
  mCache.ClearExpiredCertificates();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 0u);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 0u);
  EXPECT_EQ(mCache.GetGlobalOrder().Length(), 0u);
}

TEST_F(RTCCertCacheTest, ClearExpiredCertificatesKeepValidOnes) {
  nsCString origin = "https://example.com"_ns;

  CertFingerprint expired_one{};
  // Insert a bunch of certs  that have already expired (using different times)
  for (uint64_t id = 0; id < 10; ++id) {
    PRTime now = PR_Now() - 1;
    auto expiredCert = CreateFakeCert(id, now);
    expired_one = expiredCert.mCertFingerprint;
    mCache.Insert(nsCString(origin), std::move(expiredCert));
  }

  // Insert a valid cert
  auto validCert = CreateFakeCert(10, PR_Now() + 10000);
  CertFingerprint valid_one = validCert.mCertFingerprint;
  mCache.Insert(nsCString(origin), std::move(validCert));

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 11u);
  ASSERT_EQ(mCache.GetOriginCountMap().Get(origin), 11u);
  ASSERT_EQ(mCache.GetGlobalOrder().Length(), 11u);

  // Clear expired certs
  mCache.ClearExpiredCertificates();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 1u);
  EXPECT_EQ(mCache.GetOriginCountMap().Get(origin), 1u);
  ASSERT_EQ(mCache.GetGlobalOrder().Length(), 1u);
  EXPECT_TRUE(mCache.Get(CertFingerprint(valid_one)));
  EXPECT_FALSE(mCache.Get(CertFingerprint(expired_one)));
}

TEST_F(RTCCertCacheTest, ClearWipesEverything) {
  nsCString origin_aaa = "https://aaa.com"_ns;
  auto cert_aaa = CreateFakeCert(1, PR_Now() + 1000);
  mCache.Insert(std::move(origin_aaa), std::move(cert_aaa));
  nsCString origin_bbb = "https://bbb.com"_ns;
  auto cert_bbb = CreateFakeCert(2, PR_Now() + 1000);
  mCache.Insert(std::move(origin_bbb), std::move(cert_bbb));

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 2u);
  ASSERT_EQ(mCache.GetOriginCountMap().Count(), 2u);
  ASSERT_EQ(mCache.GetGlobalOrder().Length(), 2u);

  mCache.Clear();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 0u);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 0u);
  ASSERT_EQ(mCache.GetGlobalOrder().Length(), 0u);
}
