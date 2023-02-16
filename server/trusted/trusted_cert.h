#ifndef SERVER_TRUSTED_TRUSTED_CERT_H_
#define SERVER_TRUSTED_TRUSTED_CERT_H_

#include <memory>
#include <string>

#include "openssl/x509v3.h"

#include "unified_attestation/ua_trusted.h"

// Typedefs for memory management
using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;
using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;
using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniqueBigNum = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

namespace kubetee {
namespace trusted {

class X509Certificate {
 public:
  X509Certificate(const unsigned int bit_length, const unsigned int days)
      : bit_length_(bit_length), days_(days) {}

  /// @brief Generate certificates and private key
  ///
  /// Generate certificates and private key as TLS credentials
  ///
  /// @param cred, output to return the created credentials options
  ///
  /// @return TEE_SUCCESS on success
  TeeErrorCode CreateSslCredentials(kubetee::SslCredentialsOptions* cred);

 private:
  TeeErrorCode BioToString(const UniqueBio& bio, std::string* out);
  TeeErrorCode AddExtension(X509* cert, int nid, char* value);

  unsigned int bit_length_;
  unsigned int days_;
};

}  // namespace trusted
}  // namespace kubetee

#endif  // SERVER_TRUSTED_TRUSTED_CERT_H_
