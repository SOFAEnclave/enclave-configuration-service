#!/usr/bin/env bash

SCRIPTNAME="$(basename $0)"
THISDIR="$(dirname $(readlink -f $0))"

IMAGE="antkubetee/kubetee-aecs-test:2.0"
CONTAINERNAME="kubetee-aecs-service-$$"
if [ -z "$IMAGE" ] ; then
    echo "Usage: $SCRIPTNAME <image:tag> [container-name]"
    exit 1
fi

# If Ctrl+C the container will not be removed
# Register the handler to do clean up here.
clean_up() {
    echo "Canceled and clean up ..."
    sudo docker ps -a | grep -q $CONTAINERNAME && \
    sudo docker rm -f $CONTAINERNAME
}
trap clean_up SIGINT SIGQUIT SIGTERM

# Start the application in container
sudo docker run -it --rm \
    --name $CONTAINERNAME \
    --privileged \
    --net=host \
    --env LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64/ \
    -v $THISDIR/storage:/root/storage \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    $IMAGE "$@"
