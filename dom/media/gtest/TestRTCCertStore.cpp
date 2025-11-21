#include "RTCCertStore.h"
#include "gtest/gtest.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsTArray.h"
#include "prtime.h"

using mozilla::dom::CertFingerprint;
using mozilla::dom::GeneratedCertificate;

class TestRTCCertStoreData : public mozilla::dom::RTCCertStoreData {
 public:
  const auto& GetCertStoreMap() const { return mCertStore; }

  const auto& GetOriginCountMap() const { return mOriginCount; }

  const auto& GetGlobalOrder() const { return mGlobalOrder; }

  static uint64_t MaxPerOrigin() { return sMaxCertsPerOrigin; }
  static uint64_t MaxGlobal() { return sMaxGlobalCerts; }
};

class RTCCertStoreTest : public ::testing::Test {
 protected:
  TestRTCCertStoreData mStore;

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

TEST_F(RTCCertStoreTest, InsertAndRetrieve) {
  nsCString origin = "https://example.com"_ns;
  PRTime expiration_time = PR_Now() + 1000;
  auto cert = CreateFakeCert(1, expiration_time);  // Valid future cert
  CertFingerprint fp = cert.mCertFingerprint;

  mStore.Insert(std::move(origin), std::move(cert));
  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 1u);
  EXPECT_EQ(mStore.GetOriginCountMap().Get("https://example.com"_ns), 1u);
  EXPECT_EQ(mStore.GetOriginCountMap().Count(), 1u);

  GeneratedCertificate* retrieved = mStore.Get(fp);
  ASSERT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved->mExpires, expiration_time);
}

TEST_F(RTCCertStoreTest, RemoveUpdatesCounts) {
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 1000);
  CertFingerprint fp = cert.mCertFingerprint;

  mStore.Insert(std::move(origin), std::move(cert));
  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 1u);

  // Remove cert again
  mStore.Remove(fp);

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 0u);
  EXPECT_EQ(mStore.GetOriginCountMap().Count(), 0u);
  EXPECT_EQ(mStore.GetGlobalOrder().Length(), 0u);
}

TEST_F(RTCCertStoreTest, PerOriginLimitDoesNotAffectOthers) {
  nsCString spammer = "https://spammer.com"_ns;
  nsCString victim = "https://victim.com"_ns;
  PRTime future = PR_Now() + 100000;

  // Fill Spammer
  uint64_t id = 0;
  nsTArray<CertFingerprint> fingerprints;
  // Fill up to the limit
  for (id = 0; id < TestRTCCertStoreData::MaxPerOrigin(); ++id) {
    GeneratedCertificate cert = CreateFakeCert(id, future);
    fingerprints.AppendElement(cert.mCertFingerprint);
    mStore.Insert(nsCString(spammer), std::move(cert));
  }
  // Verify full
  EXPECT_EQ(mStore.GetOriginCountMap().Get(spammer),
            TestRTCCertStoreData::MaxPerOrigin());

  // The first fingerprint should still be in there
  EXPECT_NE(mStore.Get(fingerprints[0]), nullptr);

  // Try to insert one more
  GeneratedCertificate overflowCert = CreateFakeCert(++id, future);
  mStore.Insert(nsCString(spammer), std::move(overflowCert));
  // Count should stay at Max
  EXPECT_EQ(mStore.GetOriginCountMap().Get(spammer),
            TestRTCCertStoreData::MaxPerOrigin());
  // And the first fingerprint should now have been evicted
  EXPECT_EQ(mStore.Get(fingerprints[0]), nullptr);
  for (size_t ii = 1; ii < fingerprints.Length(); ++ii) {
    // But the others should still be accessible
    EXPECT_NE(mStore.Get(fingerprints[ii]), nullptr);
  }

  // Verify Victim Allowed
  mStore.Insert(nsCString(victim), CreateFakeCert(++id, future));
  mStore.Insert(nsCString(victim), CreateFakeCert(++id, future));
  EXPECT_EQ(mStore.GetOriginCountMap().Get(victim), 2u);
}

TEST_F(RTCCertStoreTest, GlobalLimitEnforced) {
  PRTime future = PR_Now() + 10000;

  nsTArray<CertFingerprint> fingerprints;
  for (uint64_t id = 0; id < TestRTCCertStoreData::MaxGlobal(); ++id) {
    // Switch origin every 'MaxPerOrigin()' inserts to avoid hitting origin cap
    nsPrintfCString origin("https://user%" PRIu64 ".com",
                           id / TestRTCCertStoreData::MaxPerOrigin());
    GeneratedCertificate cert = CreateFakeCert(id, future);
    fingerprints.AppendElement(cert.mCertFingerprint);
    mStore.Insert(std::move(origin), std::move(cert));
  }

  EXPECT_EQ(mStore.GetCertStoreMap().Count(),
            TestRTCCertStoreData::MaxGlobal());

  // Try inserting one more (global full)
  GeneratedCertificate overflow =
      CreateFakeCert(TestRTCCertStoreData::MaxGlobal() + 1, future);
  nsCString spammer = "https://spammer.com"_ns;
  mStore.Insert(std::move(spammer), std::move(overflow));

  // Count should stay at Max
  EXPECT_EQ(mStore.GetCertStoreMap().Count(),
            TestRTCCertStoreData::MaxGlobal());
  // And the first fingerprint should now have been evicted
  EXPECT_EQ(mStore.Get(fingerprints[0]), nullptr);
  for (size_t ii = 1; ii < fingerprints.Length(); ++ii) {
    // But the others should still be accessible
    EXPECT_NE(mStore.Get(fingerprints[ii]), nullptr);
  }
}

TEST_F(RTCCertStoreTest, ClearExpiredCertificates) {
  uint64_t id = 0;

  // Insert a bunch of certs  that expire 'now', meaning they will be expired
  // right away for different domains
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now() - 1);
    mStore.Insert(std::move(origin), std::move(cert));
    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now() - 1);
    mStore.Insert(std::move(origin), std::move(cert2));
  }

  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 8u);

  // Clear expired certs
  mStore.ClearExpiredCertificates();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 0u);
  EXPECT_EQ(mStore.GetOriginCountMap().Count(), 0u);
  EXPECT_EQ(mStore.GetGlobalOrder().Length(), 0u);
}

TEST_F(RTCCertStoreTest, ClearExpiredCertificatesKeepValidOnes) {
  nsCString origin = "https://example.com"_ns;

  CertFingerprint expired_one{};
  // Insert a bunch of certs  that have already expired (using different times)
  for (uint64_t id = 0; id < 10; ++id) {
    PRTime now = PR_Now() - 1;
    auto expiredCert = CreateFakeCert(id, now);
    expired_one = expiredCert.mCertFingerprint;
    mStore.Insert(nsCString(origin), std::move(expiredCert));
  }

  // Insert a valid cert
  auto validCert = CreateFakeCert(10, PR_Now() + 10000);
  CertFingerprint valid_one = validCert.mCertFingerprint;
  mStore.Insert(nsCString(origin), std::move(validCert));

  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 11u);
  ASSERT_EQ(mStore.GetOriginCountMap().Get(origin), 11u);
  ASSERT_EQ(mStore.GetGlobalOrder().Length(), 11u);

  // Clear expired certs
  mStore.ClearExpiredCertificates();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 1u);
  EXPECT_EQ(mStore.GetOriginCountMap().Get(origin), 1u);
  ASSERT_EQ(mStore.GetGlobalOrder().Length(), 1u);
  EXPECT_TRUE(mStore.Get(CertFingerprint(valid_one)));
  EXPECT_FALSE(mStore.Get(CertFingerprint(expired_one)));
}

TEST_F(RTCCertStoreTest, ClearWipesEverything) {
  nsCString origin_aaa = "https://aaa.com"_ns;
  auto cert_aaa = CreateFakeCert(1, PR_Now() + 1000);
  mStore.Insert(std::move(origin_aaa), std::move(cert_aaa));
  nsCString origin_bbb = "https://bbb.com"_ns;
  auto cert_bbb = CreateFakeCert(2, PR_Now() + 1000);
  mStore.Insert(std::move(origin_bbb), std::move(cert_bbb));

  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 2u);
  ASSERT_EQ(mStore.GetOriginCountMap().Count(), 2u);
  ASSERT_EQ(mStore.GetGlobalOrder().Length(), 2u);

  mStore.Clear();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 0u);
  EXPECT_EQ(mStore.GetOriginCountMap().Count(), 0u);
  ASSERT_EQ(mStore.GetGlobalOrder().Length(), 0u);
}
