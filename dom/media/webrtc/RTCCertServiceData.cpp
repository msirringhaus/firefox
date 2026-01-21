/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RTCCertServiceData.h"

#include "RTCCertStore.h"
#include "cert.h"
#include "mozpkix/nss_scoped_ptrs.h"
#include "sslerr.h"

namespace mozilla::dom {

CertFingerprint::CertFingerprint(const nsTArray<uint8_t>& aCertFingerprint) {
  MOZ_ASSERT(aCertFingerprint.Length() == sHashByteLen);
  memcpy(mHash, const_cast<uint8_t*>(aCertFingerprint.Elements()),
         static_cast<unsigned int>(aCertFingerprint.Length()));
}

CertFingerprint::operator nsTArray<uint8_t>() const {
  nsTArray<uint8_t> ret;
  ret.AppendElements(reinterpret_cast<const unsigned char*>(mHash),
                     sHashByteLen);
  return ret;
}

nsCString CertFingerprint::Dump() const {
  nsAutoCString hexString;
  for (size_t idx = 0; idx < sHashByteLen; ++idx) {
    hexString.AppendPrintf("%02x",
                           reinterpret_cast<const unsigned char*>(mHash)[idx]);
  }
  return hexString;
}

CertDataIPC::CertDataIPC(const CertData* aCertData) {
  mExpires = aCertData->mExpires;
  mCertificate.AppendElements(aCertData->mCertificate->derCert.data,
                              aCertData->mCertificate->derCert.len);
  mFingerprint = aCertData->mFingerprint;
}

CertData::CertData(const CertDataIPC* aCertDataIPC) {
  SECItem certDer = {
      siBuffer, const_cast<uint8_t*>(aCertDataIPC->mCertificate.Elements()),
      static_cast<unsigned int>(aCertDataIPC->mCertificate.Length())};
  UniqueCERTCertificate cert(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), &certDer, nullptr, true, true));
  mCertificate = std::move(cert);
  mExpires = aCertDataIPC->mExpires;
  mFingerprint = CertFingerprint(aCertDataIPC->mFingerprint);
}

CertData::CertData(const GeneratedCertificate &aCertData) {
  mCertificate =
      UniqueCERTCertificate(CERT_DupCertificate(aCertData.mCertificate.get()));
  mExpires = aCertData.mExpires;
  mFingerprint = aCertData.mCertFingerprint;
}

void SerializeRSAParam(nsTArray<uint8_t>* aParams,
                       PK11RSAGenParams* aRsaParams) {
  aParams->AppendElements(reinterpret_cast<uint8_t*>(aRsaParams),
                          sizeof(*aRsaParams));
}

PK11RSAGenParams DeserializeRSAParam(nsTArray<uint8_t>* aParams) {
  MOZ_ASSERT(aParams->Length() <= sizeof(PK11RSAGenParams));
  return *(reinterpret_cast<PK11RSAGenParams*>(aParams->Elements()));
}

bool SerializeECParams(nsTArray<uint8_t>* aParams, SECItem* aECParams) {
  if (!aECParams) {
    return false;
  }
  aParams->AppendElements(reinterpret_cast<uint8_t*>(aECParams->data),
                          aECParams->len);
  return true;
}

ScopedSECItem DeserializeECParams(nsTArray<uint8_t>* aParams) {
  ScopedSECItem ret(::SECITEM_AllocItem(nullptr, nullptr, 0));
  SECItem it = {siBuffer, reinterpret_cast<uint8_t*>(aParams->Elements()),
                static_cast<unsigned int>(aParams->Length())};
  if (::SECITEM_CopyItem(nullptr, ret.get(), &it) != SECSuccess) {
    return nullptr;
  }
  return ret;
}

}  // namespace mozilla::dom
