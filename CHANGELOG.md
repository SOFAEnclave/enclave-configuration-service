# v2.0.0

## New Features

N/A

## Bug Fixes

Fix the sync issue because user_data mismatch (with different nonce)

## Breaking Changes

N/A


# v2.0.beta

## New Features

- Based on the new TEE connectivity version of Unified Attestation.
- Support RSA "bitlength" and "pkcs_type" params in secret policy file.
- Support the initialized data when create secret, for example, import the old RSA key pair other than create the new key pair in enclave.
- Support "readonly" attribute in secret policy file. The value "true" means both the secret spec and data cannot be changed after the secret is crreated.
- Support "share" attribute in secret policy file. The value "public" means the secret public key can be exported. Anyway, private key will never be exported.

## Bug Fixes

- N/A

## Breaking Changes

- The AECS server remote attestation report is changed, and also the enclave client should also use the TEE connectivity version of Unified Attestation libraries to work with this version of AECS server.
- All the proto files are changed to use "proto3" protocol.
- Merged libua_unetwork.so, libua_ugeneration.so, libua_uverification.so into libual_u.so  (in occlum this is libual.so)
- Merged libtprotobuf.so, libua_tgeneration.so, libua_tverification.so into libual_t.so


# v1.3

The last version before this change log is created.
