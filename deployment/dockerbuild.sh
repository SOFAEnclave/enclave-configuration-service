#!/usr/bin/env bash

SCRIPTNAME="$(basename $0)"
THISDIR="$(dirname $(readlink -f $0))"
BUILDDIR="$(pwd)"

# Check the build directory
if [ ! -e "$BUILDDIR/build.sh" ] ; then
    if [ -e "$THISDIR/build.sh" ] ; then
        BUILDDIR=$THISDIR
    else
        echo "Cannot find build script in current directory"
        exit 1
    fi
fi

# Print extra build options
BUILDOPT="$@"
echo "Build options: $BUILDOPT"

REPONAME="$(basename $BUILDDIR)"
IMAGE=antkubetee/kubetee-dev-sgx:2.0-ubuntu20.04-sgx2.17.1
CONTAINERNAME="kubetee-build-$REPONAME"

echo "Build directory: $BUILDDIR"
cd $BUILDDIR || exit 1
sudo rm -rf ./build/*
sudo docker run -t --rm \
    --privileged \
    --name $CONTAINERNAME \
    --net=host \
    -v $BUILDDIR:/root/$REPONAME \
    -w /root/$REPONAME \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    $IMAGE \
    bash -c "./build.sh --mode SIM --build Debug $BUILDOPT" || exit 1
