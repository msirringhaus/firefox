/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_RTCCertServiceGlobal_h_
#define mozilla_dom_RTCCertServiceGlobal_h_

#include "ScopedNSSTypes.h"
#include "ipc/IPCMessageUtilsSpecializations.h"
#include "mozilla/MozPromise.h"
#include "mozpkix/nss_scoped_ptrs.h"

namespace mozilla {
namespace dom {

struct GeneratedCertificate;

struct CertFingerprint {
  CertFingerprint() = default;
  explicit CertFingerprint(const nsTArray<uint8_t>& aCertFingerprint);
  operator nsTArray<uint8_t>() const;
  unsigned char* AsChar() { return reinterpret_cast<unsigned char*>(mHash); }
  bool operator==(const CertFingerprint& aOther) const {
    return mHash[0] == aOther.mHash[0] && mHash[1] == aOther.mHash[1] &&
           mHash[2] == aOther.mHash[2] && mHash[3] == aOther.mHash[3];
  }
  nsCString Dump() const;

 public:
  const static size_t sHashByteLen = 32;
  uint64_t mHash[4];
};

class CertFingerprintHashKey : public PLDHashEntryHdr {
 public:
  using KeyType = const CertFingerprint&;
  using KeyTypePointer = const CertFingerprint*;

  explicit CertFingerprintHashKey(KeyTypePointer aKey) : mValue(*aKey) {}
  CertFingerprintHashKey(const CertFingerprintHashKey& aToCopy)
      : mValue(aToCopy.mValue) {}
  ~CertFingerprintHashKey() = default;

  KeyType GetKey() const { return mValue; }
  bool KeyEquals(KeyTypePointer aKey) const { return *aKey == mValue; }

  static KeyTypePointer KeyToPointer(KeyType aKey) { return &aKey; }
  static PLDHashNumber HashKey(KeyTypePointer aKey) {
    return HashBytes(aKey->mHash, sizeof(uint64_t) * 4);
  }
  enum { ALLOW_MEMMOVE = true };

 private:
  const CertFingerprint mValue;
};

struct CertData;
struct CertDataIPC {
  CertDataIPC() = default;
  explicit CertDataIPC(const CertData* aCertData);

 public:
  nsTArray<uint8_t> mFingerprint;
  nsTArray<uint8_t> mCertificate;
  PRTime mExpires;
};

struct CertData {
  CertData(UniqueCERTCertificate aCertificate, PRTime aExpires,
           CertFingerprint aFingerprint)
      : mCertificate(std::move(aCertificate)),
        mExpires(aExpires),
        mFingerprint(std::move(aFingerprint)) {}
  explicit CertData(const CertDataIPC* aCertDataIPC);
  explicit CertData(const GeneratedCertificate& aCertData);

  // Don't copy CertData
  CertData(const CertData&) = delete;
  CertData& operator=(const CertData&) = delete;

 public:
  UniqueCERTCertificate mCertificate;
  PRTime mExpires;
  CertFingerprint mFingerprint;
};

using RTCCertificatePromise =
    MozPromise<UniquePtr<CertData>, nsresult, /* IsExclusive = */ true>;

void SerializeRSAParam(nsTArray<uint8_t>* aParams,
                       PK11RSAGenParams* aRsaParams);
PK11RSAGenParams DeserializeRSAParam(nsTArray<uint8_t>* aParams);

bool SerializeECParams(nsTArray<uint8_t>* aParams, SECItem* aECParams);
ScopedSECItem DeserializeECParams(nsTArray<uint8_t>* aParams);
}  // namespace dom
}  // namespace mozilla

namespace IPC {
template <>
struct ParamTraits<mozilla::dom::CertFingerprint> {
  static void Write(IPC::MessageWriter* aWriter,
                    const mozilla::dom::CertFingerprint& aVar) {
    WriteParam(aWriter, aVar.mHash[0]);
    WriteParam(aWriter, aVar.mHash[1]);
    WriteParam(aWriter, aVar.mHash[2]);
    WriteParam(aWriter, aVar.mHash[3]);
  }
  static bool Read(IPC::MessageReader* aReader,
                   mozilla::dom::CertFingerprint* aVar) {
    if (!ReadParam(aReader, aVar->mHash) ||
        !ReadParam(aReader, aVar->mHash + 1) ||
        !ReadParam(aReader, aVar->mHash + 2) ||
        !ReadParam(aReader, aVar->mHash + 3)) {
      return false;
    }
    return true;
  }
};

template <>
struct ParamTraits<mozilla::dom::CertDataIPC> {
  static void Write(IPC::MessageWriter* aWriter,
                    const mozilla::dom::CertDataIPC& aVar) {
    ParamTraits<nsTArray<uint8_t>>::Write(aWriter, aVar.mCertificate);
    WriteParam(aWriter, aVar.mExpires);
    ParamTraits<nsTArray<uint8_t>>::Write(aWriter, aVar.mFingerprint);
  }
  static bool Read(IPC::MessageReader* aReader,
                   mozilla::dom::CertDataIPC* aVar) {
    if (!ParamTraits<nsTArray<uint8_t>>::Read(aReader, &aVar->mCertificate) ||
        !ReadParam(aReader, &aVar->mExpires) ||
        !ParamTraits<nsTArray<uint8_t>>::Read(aReader, &aVar->mFingerprint)) {
      return false;
    }
    return true;
  }
};
}  // namespace IPC

#endif  // mozilla_dom_RTCCertServiceGlobal_h_
