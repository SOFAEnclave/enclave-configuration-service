#!/usr/bin/env bash

# For exit when fail to copy files
set -e

OCCLUM_LIBC="gnu"   # gnu|musl

THISDIR="$(dirname $(readlink -f $0))"
ACTIONS="${1:-all}"
LOGLEVEL="${2}"
echo "Actions: $ACTIONS"
echo "Log level: $LOGLEVEL"

SERVICE_NAME="service1"
SECRET_RSA_NAME="secret-my-keypair"
SECRET_AES_NAME="secret-my-aes256-key"

BUILD_OUTDIR="$THISDIR/build/out"
OCCLUM_INSTANCE_DIR="$THISDIR/occlum-instance"
if [ "$OCCLUM_LIBC" == "gnu" ] ; then
  OCCLUM_INSTALL_LIBDIR="/opt/occlum/toolchains/gcc/x86_64-linux-gnu/lib"
  OCCLUM_INSTALL_LIB64DIR="/opt/occlum/toolchains/gcc/x86_64-linux-gnu/lib64"
else
  OCCLUM_INSTALL_LIBDIR="/usr/local/occlum/x86_64-linux-musl/lib"
fi
OCCLUM_IMAGE_LIBDIR="$OCCLUM_INSTANCE_DIR/image/lib"
OCCLUM_IMAGE_BINDIR="$OCCLUM_INSTANCE_DIR/image/bin"

# 1. Init Occlum Workspace
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "init" ] ; then
  rm -rf $OCCLUM_INSTANCE_DIR && \
  mkdir -p $OCCLUM_INSTANCE_DIR && \
  cd $OCCLUM_INSTANCE_DIR && occlum init || exit 1
fi

# 2. Copy files into Occlum Workspace and Build
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "build" ] ; then
  cd $OCCLUM_INSTANCE_DIR

  # Prepare files by copy_bom tool
  OCCLUM_LOG_LEVEL=info \
  /opt/occlum/build/bin/copy_bom \
      --include-dir /opt/occlum/etc/template \
      --file ${THISDIR}/bom_aecs_client_${OCCLUM_LIBC}.yaml \
      --root ./image

  # workaround, to be fixed by future Occlum release
  cp /lib/x86_64-linux-gnu/libcrypt.so.1 image/opt/occlum/glibc/lib/

  new_json="$(jq '.env.default += ["LD_LIBRARY_PATH=/opt/occlum/glibc/lib"]' Occlum.json)" && \
  echo "${new_json}" > Occlum.json

  # Add PCCS env
  if [ -n "$UA_ENV_PCCS_URL" ] ; then
    new_json="$(jq .env.default+=[\"UA_ENV_PCCS_URL=$UA_ENV_PCCS_URL\"] Occlum.json)" && \
    echo "${new_json}" > Occlum.json
    echo "{\"pccs_url\":\"$UA_ENV_PCCS_URL\", \"use_secure_cert\":false}" > /etc/sgx_default_qcnl.conf
  fi

  occlum build   # Occlum in debug mode
fi

# 3. Run application
if [ "$ACTIONS" == "all" -o "$ACTIONS" == "run" ] ; then
  cd $OCCLUM_INSTANCE_DIR && \
  OCCLUM_LOG_LEVEL=$LOGLEVEL occlum run /bin/aecs_client_get_secret \
      localhost:19527 \
      $SERVICE_NAME \
      $SECRET_RSA_NAME \
      nonce_1 \
      saved_secret_rsa_keypair && \
  OCCLUM_LOG_LEVEL=$LOGLEVEL occlum run /bin/aecs_client_get_secret \
      localhost:19527 \
      $SERVICE_NAME \
      $SECRET_AES_NAME \
      nonce_2 \
      saved_secret_aes_256 && \
  OCCLUM_LOG_LEVEL=$LOGLEVEL occlum run /bin/aecs_client_get_secret \
      localhost:19527 \
      $SERVICE_NAME \
      $SECRET_RSA_NAME \
      nonce_3 \
      saved_secret_rsa_public \
      --public
fi
