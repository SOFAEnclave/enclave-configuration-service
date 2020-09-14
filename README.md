# AECS

Attestation based Enclave Configuration service


## Introduction to KubeTEE AECS
KubeTEE AECS is based on KubeTEE Trusted Function Framework, and provide the
secret generation, management, storage and dispatch service to TEE applications.
After bidirectional authentication based on remote attestation between AECS and
all TEE-based application service, each service enclave instance will get the secrets
from AECS server, and use the secrets for later data encryption or decryption.

![AECS](docs/aecs.jpg)


## Quick Start

## Update sub-modules

If it's the first time you build the project after clone the source code,
please update the sub-modules like the this.

```
$ git submodule update --init --recursive
```

### Build Project in Docker Environment

```
./deployment/dockerbuild.sh
```

## Create the Docker Image


Please set the enclave SPID and IAS access key in the configuration file "deployment/conf/kubetee.json" before create image.
You can apply the IAS access key and SPID from [here](https://api.portal.trustedservices.intel.com/EPID-attestation)

And you also need to generate the test certificates like this (for development and test only, should use formal certificates in product environment):

```
./deployment/generate_certs_and_kubeconfig.sh
```

Then create the image with test certificates and configurations.

```
./deployment/create_image.sh
```

### To Start the AECS server

```
./deployment/run_image.sh ./aecs_server
```

### Manage the Enclave Service

```
# Save the AECS identity key into storage for backup for the first time to start the aecs server
# For the second time start the aecs server, this provision action will reload the identity key.
./deployment/run_image.sh ./aecsadmin --config /etc/kubetee/aecs_admin_test.kubeconfig --action provision --hostname localtest

# Create a enclave service named "service1" and list it
./deployment/run_image.sh ./aecsadmin --config /etc/kubetee/aecs_admin_test.kubeconfig --action register --service service1 --pubkey /etc/certs/service_public.pem
./deployment/run_image.sh ./aecsadmin --config /etc/kubetee/aecs_admin_test.kubeconfig --action list
```

### Manage the Enclave Service Secrets

```
# Create three test secrets for service1 and list all of them
./deployment/run_image.sh ./serviceadmin --config /etc/kubetee/service_admin_test.kubeconfig --action create --policy /etc/kubetee/service_secret_policy.yaml
./deployment/run_image.sh ./serviceadmin --config /etc/kubetee/service_admin_test.kubeconfig --action list
```

## Contributing

KubeTEE AECS is not final stable at this moment. There will be some improvements or new feature updates later.
Anyone is also welcome to provide any form of contribution, please see CONTRIBUTING.md for details.

For any security vulnerabilities or other problems, please contact us by [email](mailto:SOFAEnclaveSecurity@list.alibaba-inc.com).


## License
KubeTEE AECS is released by Ant Group under Apache 2.0 License and also used some other opensource code.
See the license information [here](LICENSE) for detail.
