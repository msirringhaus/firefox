#include <vector>
#include "RTCCertStore.h"
#include "gtest/gtest.h"
#include "mozilla/dom/RTCCertServiceData.h"
#include "nsTArray.h"
#include "prtime.h"

using mozilla::dom::CertFingerprint;
using mozilla::dom::GeneratedCertificate;
using mozilla::dom::SharedCertificate;

class TestRTCCertStoreData : public mozilla::dom::RTCCertStoreData {
public:
  const auto& GetCertStoreMap() const { return mCertStore; }
  // Accessor to check existence without holding a RefPtr (which would skew the test)
  bool Contains(const CertFingerprint& aFp) const {
    return mCertStore.Contains(aFp);
  }
  
  // Expose the constant for the test math
  PRTime GracePeriod() const { return kGracePeriod; }
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

TEST_F(RTCCertStoreTest, StoreAndRetrieve) {
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 1000);
  CertFingerprint fp = cert.mCertFingerprint;

  mStore.Insert(std::move(origin), std::move(cert));

  EXPECT_TRUE(mStore.Contains(fp));
  
  RefPtr<SharedCertificate> retrieved = mStore.Get(fp);
  ASSERT_TRUE(retrieved);
  
  EXPECT_TRUE(retrieved->IsInUse());
}

TEST_F(RTCCertStoreTest, GC_KeepsActiveCertificates) {
  // Scenario: A cert is past the grace period, but in use.
  // It shouldn't be deleted on running GC.

  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));

  RefPtr<SharedCertificate> shared = mStore.Get(fp);
  ASSERT_TRUE(shared);
  ASSERT_TRUE(shared->IsInUse());

  // Simulate last touched to be 10 minutes passed
  shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));

  // Run GC
  mStore.ClearExpiredCertificates();

  EXPECT_TRUE(mStore.Contains(fp));
  EXPECT_EQ(shared->GetRefCnt(), 2u); 
}

TEST_F(RTCCertStoreTest, GC_RemovesOldFloatingCertificates) {
  // Scenario: A cert is past the grace period and not in use.
  // It should be deleted during a GC-cycle.
  nsCString origin = "https://example.com"_ns;

  auto cert = CreateFakeCert(1, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));

  {
    // Temporarily get ref to manipulate time
    RefPtr<SharedCertificate> shared = mStore.Get(fp);
    // Make it OLD
    shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
    
    // Drop the reference.
  }

  mStore.ClearExpiredCertificates();

  EXPECT_FALSE(mStore.Contains(fp));
}

TEST_F(RTCCertStoreTest, GC_KeepsYoungFloatingCertificates) {
  // Scenario: A cert is within the grace period and not in use.
  // It should be kept (e.g., generated, but ActivateTransport not called yet).

  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));

  mStore.ClearExpiredCertificates();

  EXPECT_TRUE(mStore.Contains(fp));
}

TEST_F(RTCCertStoreTest, Touch_ResetsGracePeriod) {
  // Scenario: Cert is old, but we Touch() it. It should be kept.
  
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));

  RefPtr<SharedCertificate> shared = mStore.Get(fp);
  
  shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
  
  shared->Touch();
  
  shared = nullptr;

  mStore.ClearExpiredCertificates();

  EXPECT_TRUE(mStore.Contains(fp));
}

TEST_F(RTCCertStoreTest, Expiration_ActuallyExpired) {
  // Scenario: A cert is within the grace period, but the certificate itself 
  // has expired (mExpires < Now).
  // It should be deleted regardless of grace period.

  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() - 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  
  mStore.Insert(std::move(origin), std::move(cert));

  // Run GC
  mStore.ClearExpiredCertificates();

  // Verify it is gone because mCert.mExpires passed
  EXPECT_FALSE(mStore.Contains(fp));
}

TEST_F(RTCCertStoreTest, ClearWipesEverything) {
  nsCString origin_aaa = "https://aaa.com"_ns;
  auto cert_aaa = CreateFakeCert(1, PR_Now() + 1000);
  mStore.Insert(std::move(origin_aaa), std::move(cert_aaa));
  nsCString origin_bbb = "https://bbb.com"_ns;
  auto cert_bbb = CreateFakeCert(2, PR_Now() + 1000);
  mStore.Insert(std::move(origin_bbb), std::move(cert_bbb));

  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 2u);

  mStore.Clear();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 0u);
}

TEST_F(RTCCertStoreTest, ClearMultipleExpiredCertificatesOnInsert) {
  uint64_t id = 0;

  // Insert a bunch of certs  that expire 'now' or are past grace period,
  // meaning they will be expired right away for different domains on the
  // next Insert-call
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now() - 1);
    mStore.Insert(std::move(origin), std::move(cert));
    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now() + 1000);
    CertFingerprint fp = cert2.mCertFingerprint;
    mStore.Insert(std::move(origin), std::move(cert2));
    RefPtr<SharedCertificate> shared = mStore.Get(fp);
    shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
  }

  // Insert a valid cert
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(1, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));

  // More expired certs
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii+10);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now() + 1000);
    CertFingerprint fp = cert.mCertFingerprint;
    mStore.Insert(std::move(origin), std::move(cert));
    RefPtr<SharedCertificate> shared = mStore.Get(fp);
    shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
    shared = nullptr;

    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now() - 1);
    mStore.Insert(std::move(origin), std::move(cert2));
  }

  // The valid one and the last inserted cert should be there
  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 2u);

  // Clear expired certs
  mStore.ClearExpiredCertificates();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 1u);

  EXPECT_TRUE(mStore.Contains(fp));
}

TEST_F(RTCCertStoreTest, ClearMultipleExpiredCertificatesAtOnce) {
  uint64_t id = 0;

  std::vector<RefPtr<SharedCertificate>> certs;
  // Insert a bunch of certs  that expire 'now' or are past grace period,
  // meaning they will be expired right away for different domains
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now() - 1);
    CertFingerprint fp = cert.mCertFingerprint;
    mStore.Insert(std::move(origin), std::move(cert));
    certs.push_back(mStore.Get(fp));

    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now() + 1000);
    mStore.Insert(std::move(origin), std::move(cert2));
    RefPtr<SharedCertificate> shared = mStore.Get(cert2.mCertFingerprint);
    shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
    certs.push_back(shared);
  }

  // Insert a valid cert
  nsCString origin = "https://example.com"_ns;
  auto cert = CreateFakeCert(id++, PR_Now() + 10000);
  CertFingerprint fp = cert.mCertFingerprint;
  mStore.Insert(std::move(origin), std::move(cert));
  RefPtr<SharedCertificate> shared = mStore.Get(fp);
  certs.push_back(shared);

  // More expired certs
  for (int ii = 0; ii < 4; ++ii) {
    nsPrintfCString origin("https://user%i.com", ii);
    GeneratedCertificate cert = CreateFakeCert(id++, PR_Now() - 1);
    CertFingerprint fp = cert.mCertFingerprint;
    mStore.Insert(std::move(origin), std::move(cert));
    certs.push_back(mStore.Get(fp));

    GeneratedCertificate cert2 = CreateFakeCert(id++, PR_Now() + 1000);
    mStore.Insert(std::move(origin), std::move(cert2));
    RefPtr<SharedCertificate> shared = mStore.Get(cert2.mCertFingerprint);
    shared->SetLastTouched(PR_Now() - (mStore.GracePeriod() * 2));
    certs.push_back(shared);
  }

  certs.clear();

  ASSERT_EQ(mStore.GetCertStoreMap().Count(), 17u);

  // Clear expired certs
  mStore.ClearExpiredCertificates();

  EXPECT_EQ(mStore.GetCertStoreMap().Count(), 1u);

  EXPECT_TRUE(mStore.Contains(fp));
}
