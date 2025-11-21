/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_RTCCertService_h_
#define mozilla_dom_RTCCertService_h_

#include "mozilla/RefPtr.h"
#include "mozilla/dom/PRTCCertServiceTransactionChild.h"

namespace mozilla::dom {

class RTCCertServiceTransactionChild : public PRTCCertServiceTransactionChild {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(RTCCertServiceTransactionChild);

 private:
  ~RTCCertServiceTransactionChild() = default;
};

class RTCCertService {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(RTCCertService);
  virtual void Initialize() = 0;
  virtual RefPtr<RTCCertificatePromise> GenerateCertificate(
      nsCString& aOrigin, nsTArray<uint8_t>& aParam, PRTime aExpires,
      uint32_t aMechanism, uint32_t aSignatureAlg) = 0;
  virtual void RemoveCertificate(
      const mozilla::dom::CertFingerprint aCertFingerprint) = 0;
  virtual RefPtr<RTCCertificatePromise> GetCertificate(
      const CertFingerprint aCertFingerprint) = 0;

  static RTCCertService* GetInstance();

 protected:
  virtual ~RTCCertService() = default;
  RTCCertService() = default;
};

class RTCCertServiceIPC : public RTCCertService {
 public:
  RTCCertServiceIPC() = default;
  void Initialize();
  RefPtr<RTCCertificatePromise> GenerateCertificate(nsCString& aOrigin,
                                                    nsTArray<uint8_t>& aParam,
                                                    PRTime aExpires,
                                                    uint32_t aMechanism,
                                                    uint32_t aSignatureAlg);
  void RemoveCertificate(const mozilla::dom::CertFingerprint aCertFingerprint);
  RefPtr<RTCCertificatePromise> GetCertificate(
      const CertFingerprint aCertFingerprint);

 private:
  virtual ~RTCCertServiceIPC() = default;

  RefPtr<RTCCertServiceTransactionChild> mChild;

  // |mChild| can only be initted asynchronously, |mInitPromise| resolves
  // when that happens. The |Then| calls make it convenient to dispatch API
  // calls to main, which is a bonus.
  // Init promise is not exclusive; this lets us call |Then| on it for every
  // API call we get, instead of creating another promise each time.
  using InitPromise = MozPromise<bool, nsCString, false>;
  RefPtr<InitPromise> mInitPromise;
};

class RTCCertServiceLocal : public RTCCertService {
 public:
  RTCCertServiceLocal() = default;
  void Initialize();
  RefPtr<RTCCertificatePromise> GenerateCertificate(nsCString& aOrigin,
                                                    nsTArray<uint8_t>& aParam,
                                                    PRTime aExpires,
                                                    uint32_t aMechanism,
                                                    uint32_t aSignatureAlg);
  void RemoveCertificate(const mozilla::dom::CertFingerprint aCertFingerprint);
  RefPtr<RTCCertificatePromise> GetCertificate(
      const CertFingerprint aCertFingerprint);

 private:
  virtual ~RTCCertServiceLocal();
};

}  // namespace mozilla::dom

#endif  // mozilla_dom_CertServiceChild_h
