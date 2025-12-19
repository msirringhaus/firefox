#include "gtest/gtest.h"
#include "RTCCertCache.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "prtime.h"

using namespace mozilla::dom;

class TestRTCCertCacheData : public RTCCertCacheData {
public:
  const auto& GetCertCacheMap() const {
    return mCertCache;
  }

  const auto& GetOriginCountMap() const {
    return mOriginCount;
  }

  static size_t MaxPerOrigin() { return sMaxCertsPerOrigin; }
  static size_t MaxGlobal() { return sMaxGlobalCerts; }
};

class RTCCertCacheTest : public ::testing::Test {
protected:
  TestRTCCertCacheData mCache;

  // We don't need valid certificates for the cache logic, 
  // just unique fingerprints and expiration times.
  GeneratedCertificate CreateFakeCert(uint64_t aId, PRTime aExpires) {
    GeneratedCertificate cert;
    cert.mExpires = aExpires;
    // For testing, we get enough id-space to only use the first quarter of the hash-field
    cert.mCertFingerprint.mHash[0] = aId;
    return cert;
  }
};

TEST_F(RTCCertCacheTest, InsertAndRetrieve) {
  nsCString origin = "https://example.com"_ns;
  PRTime expiration_time = PR_Now() + 1000;
  auto cert = CreateFakeCert(1, expiration_time); // Valid future cert
  CertFingerprint fp = cert.mCertFingerprint;

  EXPECT_TRUE(mCache.Insert(std::move(origin), std::move(cert)));
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
}

TEST_F(RTCCertCacheTest, PerOriginLimitDoesNotAffectOthers) {
  nsCString spammer = "https://spammer.com"_ns;
  nsCString victim = "https://victim.com"_ns;
  PRTime future = PR_Now() + 10000;

  // Fill Spammer
  uint64_t id = 0;
  // Fill up to the limit
  for (id = 0; id < TestRTCCertCacheData::MaxPerOrigin(); ++id) {
    GeneratedCertificate cert = CreateFakeCert(id, future);  
    EXPECT_TRUE(mCache.Insert(nsCString(spammer), std::move(cert)));
  }

  // Verify full
  EXPECT_EQ(mCache.GetOriginCountMap().Get(spammer), TestRTCCertCacheData::MaxPerOrigin());

  // Try to insert one more
  GeneratedCertificate overflowCert = CreateFakeCert(++id, future);
  EXPECT_FALSE(mCache.Insert(std::move(spammer), std::move(overflowCert))) 
    << "Should return false when origin limit reached";

  // Verify Victim Allowed
  EXPECT_TRUE(mCache.Insert(nsCString(victim), CreateFakeCert(++id, future)));
  EXPECT_TRUE(mCache.Insert(nsCString(victim), CreateFakeCert(++id, future)));
  EXPECT_EQ(mCache.GetOriginCountMap().Get(victim), 2u);
}

TEST_F(RTCCertCacheTest, GlobalLimitEnforced) {
  PRTime future = PR_Now() + 10000;

  for (uint64_t id = 0; id < TestRTCCertCacheData::MaxGlobal(); ++id) {
    // Switch origin every 'MaxPerOrigin()' inserts to avoid hitting origin cap
    nsPrintfCString origin("https://user%zu.com", id / TestRTCCertCacheData::MaxPerOrigin());
    GeneratedCertificate cert = CreateFakeCert(id, future);  
    ASSERT_TRUE(mCache.Insert(std::move(origin), std::move(cert)));
  }

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), TestRTCCertCacheData::MaxGlobal());

  // Try inserting one more (global full)
  GeneratedCertificate overflow = CreateFakeCert(TestRTCCertCacheData::MaxGlobal() + 1, future);
  nsCString spammer = "https://spammer.com"_ns;
  EXPECT_FALSE(mCache.Insert(std::move(spammer), std::move(overflow)))
    << "Should return false when global limit reached";
}

TEST_F(RTCCertCacheTest, ClearExpiredCertificates) {
  uint64_t id = 0;
  
  // Insert a bunch of certs  that expire 'now', meaning they will be expired right away
  // for different domains
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now());  
    ASSERT_TRUE(mCache.Insert(std::move(origin), std::move(cert)));
    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now());  
    ASSERT_TRUE(mCache.Insert(std::move(origin), std::move(cert2)));
  }

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 8);

  // Clear expired certs
  mCache.ClearExpiredCertificates();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 0u);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 0u);
}

TEST_F(RTCCertCacheTest, ClearExpiredCertificatesKeepValidOnes) {
  nsCString origin = "https://example.com"_ns;
  
  CertFingerprint expired_one;
  // Insert a bunch of certs  that have already expired (using different times)
  for (uint64_t id = 0; id < 10; ++id) {
    PRTime now = PR_Now() - 1;
    auto expiredCert = CreateFakeCert(id, now);
    expired_one = expiredCert.mCertFingerprint;
    EXPECT_TRUE(mCache.Insert(nsCString(origin), std::move(expiredCert)));
  }

  // Insert a valid cert
  auto validCert = CreateFakeCert(10, PR_Now() + 10000);
  CertFingerprint valid_one = validCert.mCertFingerprint;
  EXPECT_TRUE(mCache.Insert(nsCString(origin), std::move(validCert)));

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 11);
  ASSERT_EQ(mCache.GetOriginCountMap().Get(origin), 11);

  // Clear expired certs
  mCache.ClearExpiredCertificates();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 1);
  EXPECT_EQ(mCache.GetOriginCountMap().Get(origin), 1);
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

  ASSERT_EQ(mCache.GetCertCacheMap().Count(), 2);
  ASSERT_EQ(mCache.GetOriginCountMap().Count(), 2);

  mCache.Clear();

  EXPECT_EQ(mCache.GetCertCacheMap().Count(), 0);
  EXPECT_EQ(mCache.GetOriginCountMap().Count(), 0);
}
