/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "RTCCertService.h"

#include "RTCCertCache.h"
#include "RTCCertServiceParent.h"
#include "mozilla/ClearOnShutdown.h"
#include "mozilla/StaticPrefs_network.h"
#include "mozilla/dom/RTCCertCache.h"
#include "mozilla/ipc/Endpoint.h"
#include "mozilla/net/SocketProcessBridgeChild.h"
#include "nsStringFwd.h"

namespace mozilla::dom {

static StaticRefPtr<RTCCertService> gCertService;

RTCCertService* RTCCertService::GetInstance() {
  if (gCertService) {
    return gCertService;
  }

  if (XRE_IsContentProcess() && StaticPrefs::network_process_enabled()) {
    gCertService = new RTCCertServiceIPC();
  } else {
    gCertService = new RTCCertServiceLocal();
  }

  if (gCertService) {
    gCertService->Initialize();
    ClearOnShutdown(&gCertService);
  }
  return gCertService;
}

void RTCCertServiceIPC::Initialize() {
  using EndpointPromise =
      MozPromise<mozilla::ipc::Endpoint<PRTCCertServiceTransactionChild>,
                 nsCString, true>;
  mInitPromise =
      net::SocketProcessBridgeChild::GetSocketProcessBridge()
          ->Then(
              GetCurrentSerialEventTarget(), __func__,
              [](const RefPtr<net::SocketProcessBridgeChild>& aBridge) {
                mozilla::ipc::Endpoint<PRTCCertServiceTransactionParent>
                    parentEndpoint;
                mozilla::ipc::Endpoint<PRTCCertServiceTransactionChild>
                    childEndpoint;

                mozilla::dom::PRTCCertServiceTransaction::CreateEndpoints(
                    &parentEndpoint, &childEndpoint);

                if (!aBridge || !aBridge->SendInitRTCCertServiceTransaction(
                                    std::move(parentEndpoint))) {
                  NS_WARNING(
                      "RTCCertService async init failed! Webrtc "
                      "networking "
                      "will not work!");
                  return EndpointPromise::CreateAndReject(
                      nsCString("SendInitRTCCertServiceTransaction failed!"),
                      __func__);
                }
                return EndpointPromise::CreateAndResolve(
                    std::move(childEndpoint), __func__);
              },
              [](const nsCString& aError) {
                return EndpointPromise::CreateAndReject(aError, __func__);
              })
          ->Then(
              GetCurrentSerialEventTarget(), __func__,
              [this, self = RefPtr<RTCCertServiceIPC>(this)](
                  mozilla::ipc::Endpoint<PRTCCertServiceTransactionChild>&&
                      aEndpoint) {
                RefPtr<RTCCertServiceTransactionChild> child =
                    new RTCCertServiceTransactionChild();
                aEndpoint.Bind(child);
                mChild = child;

                return InitPromise::CreateAndResolve(true, __func__);
              },
              [=](const nsCString& aError) {
                NS_WARNING(
                    "RTCCertService async init failed! Webrtc "
                    "networking "
                    "will not work!");
                return InitPromise::CreateAndReject(aError, __func__);
              });
}

RefPtr<RTCCertificatePromise> RTCCertServiceIPC::GenerateCertificate(
    nsCString& aOrigin, nsTArray<uint8_t>& aParam, PRTime aExpires,
    uint32_t aMechanism, uint32_t aSignatureAlg) {
  return mInitPromise->Then(
      GetCurrentSerialEventTarget(), __func__,
      [self = RefPtr<RTCCertServiceIPC>(this), this, param = aParam.Clone(),
       aOrigin, aExpires, aMechanism, aSignatureAlg](bool /* dummy */) {
        if (!mChild) {
          return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE,
                                                        __func__);
        }
        RefPtr<RTCCertificatePromise> promise =
            mChild
                ->SendGenerateCertificate(aOrigin, param, aExpires, aMechanism,
                                          aSignatureAlg)
                ->Then(
                    GetCurrentSerialEventTarget(), __func__,
                    [](const CertDataIPC& aCertDataIPC) {
                      return RTCCertificatePromise::CreateAndResolve(
                          MakeUnique<CertData>(&aCertDataIPC), __func__);
                    },
                    [](mozilla::ipc::ResponseRejectReason aReason) {
                      return RTCCertificatePromise::CreateAndReject(
                          NS_ERROR_FAILURE, __func__);
                    });
        return promise;
      },
      [](const nsCString& aError) {
        return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE,
                                                      __func__);
      });
}

void RTCCertServiceIPC::RemoveCertificate(
    const mozilla::dom::CertFingerprint aCertFingerprint) {
  mInitPromise->Then(
      GetCurrentSerialEventTarget(), __func__,
      [self = RefPtr<RTCCertServiceIPC>(this), this,
       aCertFingerprint](bool /* dummy */) {
        if (mChild) {
          mChild->SendRemoveCertificate(aCertFingerprint);
        }
      },
      [](const nsCString& aError) {});
}

RefPtr<RTCCertificatePromise> RTCCertServiceIPC::GetCertificate(
    const CertFingerprint aCertFingerprint) {
  return mInitPromise->Then(
      GetCurrentSerialEventTarget(), __func__,
      [self = RefPtr<RTCCertServiceIPC>(this), this,
       aCertFingerprint](bool /* dummy */) {
        if (!mChild) {
          return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE,
                                                        __func__);
        }
        RefPtr<RTCCertificatePromise> promise =
            mChild->SendGetCertificate(aCertFingerprint)
                ->Then(
                    GetCurrentSerialEventTarget(), __func__,
                    [](const CertDataIPC& aCertDataIPC) {
                      return RTCCertificatePromise::CreateAndResolve(
                          MakeUnique<CertData>(&aCertDataIPC), __func__);
                    },

                    [](mozilla::ipc::ResponseRejectReason aReason) {
                      return RTCCertificatePromise::CreateAndReject(
                          NS_ERROR_FAILURE, __func__);
                    });
        return promise;
      },
      [](const nsCString& aError) {
        return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE,
                                                      __func__);
      });
}

void RTCCertServiceLocal::Initialize() {
  // no-op
}

RefPtr<RTCCertificatePromise> RTCCertServiceLocal::GenerateCertificate(
    nsCString& aOrigin, nsTArray<uint8_t>& aParam, PRTime aExpires,
    uint32_t aMechanism, uint32_t aSignatureAlg) {
  // First clear all certs that may have expired already to make room for a new
  // cert
  RTCCertCache::ClearExpiredCertificates();

  // Check if this origin is allowed to cache more certs.
  // Note, this is not a guarantee the insert will work,
  // as this is not an atomic operation and the actual
  // insertion could still fail. We check here first, to
  // avoid running the costly GenerateCertificate() first
  // in a hypothetical DoS-scenario.
  if (RTCCertCache::CacheLimitsReached(aOrigin)) {
    return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE, __func__);
  }

  RefPtr<RTCCertificateGenerator> gen = new RTCCertificateGenerator();
  RefPtr<RTCCertificatePromise> promise =
      gen->Generate(aParam, aExpires, aMechanism,
                    static_cast<SECOidTag>(aSignatureAlg))
          ->Then(
              GetCurrentSerialEventTarget(), __func__,
              [aOrigin](GeneratedCertificate genCert) mutable {
                auto data = MakeUnique<CertData>(
                    UniqueCERTCertificate(
                        CERT_DupCertificate(genCert.mCertificate.get())),
                    genCert.mExpires, genCert.mCertFingerprint);
                if (RTCCertCache::CacheCert(std::move(aOrigin),
                                            std::move(genCert))) {
                  return RTCCertificatePromise::CreateAndResolve(
                      std::move(data), __func__);
                } else {
                  return RTCCertificatePromise::CreateAndReject(
                      NS_ERROR_FAILURE, __func__);
                }
              },
              [](const nsresult& aError) {
                return RTCCertificatePromise::CreateAndReject(aError, __func__);
              });
  return promise;
}

void RTCCertServiceLocal::RemoveCertificate(
    const mozilla::dom::CertFingerprint aCertFingerprint) {
  RTCCertCache::RemoveCert(aCertFingerprint);
}

RefPtr<RTCCertificatePromise> RTCCertServiceLocal::GetCertificate(
    const CertFingerprint aCertFingerprint) {
  GeneratedCertificate* certData = RTCCertCache::LookupCert(aCertFingerprint);
  if (certData) {
    return RTCCertificatePromise::CreateAndResolve(
        MakeUnique<CertData>(certData), __func__);
  } else {
    return RTCCertificatePromise::CreateAndReject(NS_ERROR_FAILURE, __func__);
  }
}

RTCCertServiceLocal::~RTCCertServiceLocal() { RTCCertCache::Clear(); };

}  // namespace mozilla::dom
