#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"

IMAGE="antkubetee/kubetee-aecs-test:2.0"
CONTAINERNAME="kubetee-aecs-service-test"

check_aecs_image() {
    if sudo docker images | grep "antkubetee\/kubetee-aecs-test[\ ]*2.0" ; then
        echo "The aecs v2.0 test image is already existing!"
    else
        echo "Pulling aecs v2.0 test image ..."
        sudo docker pull antkubetee/kubetee-aecs-test:2.0 
    fi
}

start_aecs_server() {
    # Run aecs_server in background
    # Have not remove storage directory here to save history secrets
    echo "Create the aecs test container ..."
    sudo docker run -td \
        --name $CONTAINERNAME \
        --privileged \
        --net=host \
        --cap-add=SYS_PTRACE \
        --security-opt seccomp=unconfined \
        --env LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64/ \
        -v $THISDIR/storage:/root/storage \
        $IMAGE "./aecs_server"

    echo "Waiting for aecs start ..."
    sleep 3
}

stop_aecs_test() {
    echo "Destroy the aecs test container ..."
    sudo docker rm -f $CONTAINERNAME
}

do_aecs_provison() {
    # Provison
    $THISDIR/run_image.sh ./aecsadmin \
        --config /etc/kubetee/aecs_admin_test.kubeconfig \
        --action provision \
        --hostname localtest
}

register_aecs_test_service() {
    # Create the test service
    $THISDIR/run_image.sh ./aecsadmin \
        --config /etc/kubetee/aecs_admin_test.kubeconfig \
        --action register \
        --service service1 \
        --pubkey /etc/certs/service_admin_public.pem
    $THISDIR/run_image.sh ./aecsadmin \
        --config /etc/kubetee/aecs_admin_test.kubeconfig \
        --action list
}

create_aecs_test_secrets() {
    # Create the test secrets for test service
    $THISDIR/run_image.sh ./serviceadmin \
        --config /etc/kubetee/service_admin_test.kubeconfig \
        --action create \
        --policy /etc/kubetee/service_secret_policy.yaml
    $THISDIR/run_image.sh ./serviceadmin \
        --config /etc/kubetee/service_admin_test.kubeconfig \
        --action list
}

start_aecs_test() {
    check_aecs_image && \
    start_aecs_server && \
    do_aecs_provison && \
    register_aecs_test_service && \
    create_aecs_test_secrets
}

case $1 in
    start) start_aecs_test ;;
    stop)  stop_aecs_test ;;
    *) echo "Usage: $0 [start|stop]"
esac
