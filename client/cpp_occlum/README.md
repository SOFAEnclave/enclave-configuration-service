# Actions for Occlum test

## Make sure the code is new and complete

```
git submodule update --init --recursive
```

## Create and enter the occlum container instance

```
./deployment/dockerenv.sh --init --occlum
./deployment/dockerenv.sh --exec --occlum
```

## Prepare dependencies in occlum container

```
cd client/cpp_occlum
./occlum_build_prepare.sh
```

## Build the aecs client library and test app

```
cd client/cpp_occlum
./occlum_build_aecs_client.sh
```

## Run the test app in occlum

Set the PCCS in occlum container (Not in occlum image, becuase it's used when occlum call ocall function)

```
# cat /etc/sgx_default_qcnl.conf
# PCCS server address
PCCS_URL=https://<pccs-address>:8081/sgx/certification/v3/
# To accept insecure HTTPS cert, set this option to FALSE
USE_SECURE_CERT=FALSE
```

Set the PCCS for UAL inside occlum image by environment variable

```
export UA_ENV_PCCS_URL=https://<pccs-address>:8081/sgx/certification/v3/
```

Finally, run aecs_client_get_secret application in occlum for test

```
cd client/cpp_occlum
./occlum_run_aecs_client.sh
```
