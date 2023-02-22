#include <map>
#include <random>
#include <string>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509v3.h"

#include "unified_attestation/ua_trusted.h"

#include "trusted/trusted_cert.h"

namespace kubetee {
namespace trusted {

constexpr int kCertVersion = 2;
constexpr unsigned kSecondsInDay = 24 * 60 * 60;
const std::map<std::string, std::string> kSubjectMap = {
    {"C", "CN"},  {"ST", "ZJ"},   {"L", "HZ"},
    {"O", "TEE"}, {"OU", "AECS"}, {"CN", "aecs.trusted.com"},
};

TeeErrorCode X509Certificate::BioToString(const UniqueBio& bio,
                                          std::string* out) {
  int size = BIO_pending(bio.get());
  if (size < 0) {
    ELOG_ERROR("BIO_pending failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  out->resize(size);
  if (BIO_read(bio.get(), &(*out)[0], size) != size) {
    ELOG_ERROR("Read bio failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  return TEE_SUCCESS;
}

TeeErrorCode X509Certificate::AddExtension(X509* cert, int nid, char* value) {
  X509V3_CTX ctx;
  // This sets the 'context' of the extensions.
  // No configuration database
  X509V3_set_ctx_nodb(&ctx);
  // self signed
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  X509_EXTENSION* ex = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
  if (ex == nullptr) {
    ELOG_ERROR("AddExtension: X509V3_EXT_nconf_nid failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return TEE_SUCCESS;
}

TeeErrorCode X509Certificate::CreateSslCredentials(
    kubetee::SslCredentialsOptions* cred) {
  // 1. Create key pair.
  UniqueBigNum exp(BN_new(), BN_free);
  if (!BN_set_word(exp.get(), RSA_F4)) {
    ELOG_ERROR("BN_set_word failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  UniqueRsa rsa(RSA_new(), RSA_free);
  if (!RSA_generate_key_ex(rsa.get(), bit_length_, exp.get(), nullptr)) {
    ELOG_ERROR("Fail to generate rsa key pair");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }

  // 2. Assign to EVP_PKEY.
  UniquePkey evp_pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
  if (!EVP_PKEY_assign_RSA(evp_pkey.get(), rsa.get())) {
    ELOG_ERROR("Cannot assign rsa");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  } else {
    // Ownership transferred to EVP. Let us release ownership from rsa.
    rsa.release();
  }

  // 3. Generate X509 Certificate.
  UniqueX509 x509(X509_new(), ::X509_free);
  // 3.1 v3 & serial number
  // - V3
  X509_set_version(x509.get(), kCertVersion);
  // - random serial number
  std::random_device rd;
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), rd());
  // 3.2 valid range
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), days_ * kSecondsInDay);
  // 3.3 fill rsa public key
  X509_set_pubkey(x509.get(), evp_pkey.get());
  X509_NAME* name = X509_get_subject_name(x509.get());
  // 3.4 set subject fields.
  for (auto it = kSubjectMap.begin(); it != kSubjectMap.end(); it++) {
    if (!X509_NAME_add_entry_by_txt(
            name, it->first.c_str(), MBSTRING_ASC,
            RCAST(const unsigned char*, it->second.c_str()), -1, -1, 0)) {
      ELOG_ERROR("Fail to set x509 subject fields");
      return TEE_ERROR_CRYPTO_CERT_CREATE;
    }
  }
  // 3.5 self-signed: issuer name == name.
  X509_set_issuer_name(x509.get(), name);
  TEE_CHECK_RETURN(
      AddExtension(x509.get(), NID_basic_constraints, CCAST(char*, "CA:TRUE")));
  TEE_CHECK_RETURN(AddExtension(x509.get(), NID_subject_key_identifier,
                                CCAST(char*, "hash")));
  // 3.6 Do self signing with sha256-rsa.
  if (!X509_sign(x509.get(), evp_pkey.get(), EVP_sha256())) {
    ELOG_ERROR("Fail to do self-signing");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }

  // 4. Write as string.
  UniqueBio pkey_bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!PEM_write_bio_PrivateKey(pkey_bio.get(), evp_pkey.get(), nullptr,
                                nullptr, 0, nullptr, nullptr)) {
    ELOG_ERROR("PEM_write_bio_PrivateKey failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  UniqueBio cert_bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!PEM_write_bio_X509(cert_bio.get(), x509.get())) {
    ELOG_ERROR("PEM_write_bio_X509 failed");
    return TEE_ERROR_CRYPTO_CERT_CREATE;
  }
  TEE_CHECK_RETURN(BioToString(pkey_bio, cred->mutable_private_key()));
  TEE_CHECK_RETURN(BioToString(cert_bio, cred->mutable_cert_chain()));
  cred->set_root_cert(cred->cert_chain());
  return TEE_SUCCESS;
}

}  // namespace trusted
}  // namespace kubetee
