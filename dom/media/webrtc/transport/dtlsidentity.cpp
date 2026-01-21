/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "dtlsidentity.h"

#include "cert.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "mozilla/Sprintf.h"
#include "mozilla/dom/RTCCertStore.h"
#include "mozpkix/nss_scoped_ptrs.h"
#include "nsError.h"
#include "pk11pub.h"
#include "secerr.h"
#include "sechash.h"
#include "sslerr.h"

namespace mozilla {

nsTArray<uint8_t> DtlsIdentity::GetCertFingerprint() {
  return cert_fingerprint_;
}

/* static */
RefPtr<DtlsIdentity> DtlsIdentity::FromCertFingerprint(
    const nsTArray<uint8_t>& certFingerprint, SSLKEAType authType) {
  return new DtlsIdentity(dom::CertFingerprint(certFingerprint), authType);
}

RefPtr<DtlsIdentity> DtlsIdentity::Generate() {
  UniquePK11SlotInfo slot(PK11_GetInternalSlot());
  if (!slot) {
    return nullptr;
  }

  uint8_t random_name[16];

  SECStatus rv =
      PK11_GenerateRandomOnSlot(slot.get(), random_name, sizeof(random_name));
  if (rv != SECSuccess) return nullptr;

  std::string name;
  char chunk[3];
  for (unsigned char r_name : random_name) {
    SprintfLiteral(chunk, "%.2x", r_name);
    name += chunk;
  }

  std::string subject_name_string = "CN=" + name;
  UniqueCERTName subject_name(CERT_AsciiToName(subject_name_string.c_str()));
  if (!subject_name) {
    return nullptr;
  }

  unsigned char paramBuf[12];  // OIDs are small
  SECItem ecdsaParams = {siBuffer, paramBuf, sizeof(paramBuf)};
  SECOidData* oidData = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP256R1);
  if (!oidData || (oidData->oid.len > (sizeof(paramBuf) - 2))) {
    return nullptr;
  }
  ecdsaParams.data[0] = SEC_ASN1_OBJECT_ID;
  ecdsaParams.data[1] = oidData->oid.len;
  memcpy(ecdsaParams.data + 2, oidData->oid.data, oidData->oid.len);
  ecdsaParams.len = oidData->oid.len + 2;

  SECKEYPublicKey* pubkey;
  UniqueSECKEYPrivateKey private_key(
      PK11_GenerateKeyPair(slot.get(), CKM_EC_KEY_PAIR_GEN, &ecdsaParams,
                           &pubkey, PR_FALSE, PR_TRUE, nullptr));
  if (private_key == nullptr) return nullptr;
  UniqueSECKEYPublicKey public_key(pubkey);
  pubkey = nullptr;

  UniqueCERTSubjectPublicKeyInfo spki(
      SECKEY_CreateSubjectPublicKeyInfo(public_key.get()));
  if (!spki) {
    return nullptr;
  }

  UniqueCERTCertificateRequest certreq(
      CERT_CreateCertificateRequest(subject_name.get(), spki.get(), nullptr));
  if (!certreq) {
    return nullptr;
  }

  // From 1 day before todayto 30 days after.
  // This is a sort of arbitrary range designed to be valid
  // now with some slack in case the other side expects
  // some before expiry.
  //
  // Note: explicit casts necessary to avoid
  //       warning C4307: '*' : integral constant overflow
  static const PRTime oneDay = PRTime(PR_USEC_PER_SEC) * PRTime(60)  // sec
                               * PRTime(60)                          // min
                               * PRTime(24);                         // hours
  PRTime now = PR_Now();
  PRTime notBefore = now - oneDay;
  PRTime notAfter = now + (PRTime(30) * oneDay);

  UniqueCERTValidity validity(CERT_CreateValidity(notBefore, notAfter));
  if (!validity) {
    return nullptr;
  }

  unsigned long serial;
  // Note: This serial in principle could collide, but it's unlikely
  rv = PK11_GenerateRandomOnSlot(
      slot.get(), reinterpret_cast<unsigned char*>(&serial), sizeof(serial));
  if (rv != SECSuccess) {
    return nullptr;
  }

  // NB: CERTCertificates created with CERT_CreateCertificate are not safe to
  // use with other NSS functions like CERT_DupCertificate.
  // The strategy here is to create a tbsCertificate ("to-be-signed
  // certificate"), encode it, and sign it, resulting in a signed DER
  // certificate that can be decoded into a CERTCertificate.
  UniqueCERTCertificate tbsCertificate(CERT_CreateCertificate(
      serial, subject_name.get(), validity.get(), certreq.get()));
  if (!tbsCertificate) {
    return nullptr;
  }

  PLArenaPool* arena = tbsCertificate->arena;

  rv = SECOID_SetAlgorithmID(arena, &tbsCertificate->signature,
                             SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE, nullptr);
  if (rv != SECSuccess) return nullptr;

  // Set version to X509v3.
  *(tbsCertificate->version.data) = SEC_CERTIFICATE_VERSION_3;
  tbsCertificate->version.len = 1;

  SECItem innerDER;
  innerDER.len = 0;
  innerDER.data = nullptr;

  if (!SEC_ASN1EncodeItem(arena, &innerDER, tbsCertificate.get(),
                          SEC_ASN1_GET(CERT_CertificateTemplate))) {
    return nullptr;
  }

  SECItem* certDer = PORT_ArenaZNew(arena, SECItem);
  if (!certDer) {
    return nullptr;
  }

  rv = SEC_DerSignData(arena, certDer, innerDER.data, innerDER.len,
                       private_key.get(),
                       SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE);
  if (rv != SECSuccess) {
    return nullptr;
  }

  UniqueCERTCertificate certificate(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), certDer, nullptr, false, true));

  return new DtlsIdentity(std::move(private_key), std::move(certificate),
                          ssl_kea_ecdh);
}

constexpr nsLiteralCString DtlsIdentity::DEFAULT_HASH_ALGORITHM;

nsresult DtlsIdentity::ComputeFingerprint(DtlsDigest* digest) {
  const UniqueCERTCertificate& c = cert();
  MOZ_ASSERT(c);

  return ComputeFingerprint(c, digest);
}

nsresult DtlsIdentity::ComputeFingerprint(const UniqueCERTCertificate& cert,
                                          DtlsDigest* digest) {
  MOZ_ASSERT(cert);

  HASH_HashType ht;

  if (digest->algorithm_ == "sha-1") {
    ht = HASH_AlgSHA1;
  } else if (digest->algorithm_ == "sha-224") {
    ht = HASH_AlgSHA224;
  } else if (digest->algorithm_ == "sha-256") {
    ht = HASH_AlgSHA256;
  } else if (digest->algorithm_ == "sha-384") {
    ht = HASH_AlgSHA384;
  } else if (digest->algorithm_ == "sha-512") {
    ht = HASH_AlgSHA512;
  } else {
    return NS_ERROR_INVALID_ARG;
  }

  const SECHashObject* ho = HASH_GetHashObject(ht);
  MOZ_ASSERT(ho);
  if (!ho) {
    return NS_ERROR_INVALID_ARG;
  }

  MOZ_ASSERT(ho->length >= 20);  // Double check
  digest->value_.resize(ho->length);

  SECStatus rv = HASH_HashBuf(ho->type, digest->value_.data(),
                              cert->derCert.data, cert->derCert.len);
  if (rv != SECSuccess) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

const UniqueCERTCertificate& DtlsIdentity::cert() {
  if (!cert_) {
    RefPtr<dom::SharedCertificate> genCert =
        dom::RTCCertStore::LookupCert(cert_fingerprint_);
    if (genCert) {
      cert_ = UniqueCERTCertificate(
          CERT_DupCertificate(genCert->Cert().mCertificate.get()));
    }
  }
  return cert_;
}

const UniqueSECKEYPrivateKey& DtlsIdentity::privkey() {
  if (!private_key_) {
    RefPtr<dom::SharedCertificate> genCert =
        dom::RTCCertStore::LookupCert(cert_fingerprint_);
    if (genCert) {
      private_key_ = UniqueSECKEYPrivateKey(
          SECKEY_CopyPrivateKey(genCert->Cert().mPrivateKey.get()));
    }
  }
  return private_key_;
}

}  // namespace mozilla
