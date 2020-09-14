#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"
DOCKERFILE="${1:-${THISDIR}/dockerfile/Dockerfile}"
IMAGENAME="${2:-kubetee-aecs-service:1.0}"
#IMAGETAG="$(date +%F-%H%M%S)"

if [ ! -f "$DOCKERFILE" ] ; then
    echo "Usage: $0 <path-to-dockerfile>"
    exit 1
fi

cd $THISDIR
BUILDOUTDIR="$THISDIR/buildout"
echo "Copy release files to $BUILDOUTDIR" && \
mkdir -p $BUILDOUTDIR && \
rm -rf $BUILDOUTDIR/* && \
cp -r ../build/out/* $BUILDOUTDIR && \
rm -rf $BUILDOUTDIR/libaecs_enclave.so
rm -rf $BUILDOUTDIR/*.a
rm -rf $BUILDOUTDIR/{parse,read,sandbox}
ls $BUILDOUTDIR

# Use the start_aesmd.sh file in TFF repo
cp $THISDIR/../tff/deployment/bin/start_aesm.sh $THISDIR/bin

if [ -e "$BUILDOUTDIR/aecs_enclave.signed.so" ] ; then
    echo "IMAGE: $IMAGENAME"
    sudo docker build -f ${DOCKERFILE} -t ${IMAGENAME} . && \
    sudo docker images | grep "${IMAGENAME%:*}"
else
  echo "There is no signed enclave named aecs_enclave.signed.so"
  echo "Please build the repository and sign the enclaves firstly!"
  exit 1
fi
