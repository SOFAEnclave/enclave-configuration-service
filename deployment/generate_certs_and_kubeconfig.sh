#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"
CATOOL="${THISDIR}/gencert"

AECSINSTANCEDIR="$THISDIR/aecs_instance"
INSTANCEDIR=${1:-"$THISDIR/aecs_instance"}
FORCE_REPLACE="NO"
IS_SM_MODE="NO"

# File parameter check
check_file_exist() {
    [ -f "$2" ] && return 0
    echo "Invlaid $1 file: $2" && return 1
}

# Replace the key or cert item in kubeconfig
replace_kubeconfig_key_cert() {
    local conf="$1"
    local name="$2"
    local value="$(cat $3 | base64 -w0)"

    echo "Replacing [$name] in kubeconfig file $conf ..."
    sed -i -e "s/${name}:.*$/${name}:\ ${value}/g" $conf && return 0

    echo "Fail to replace [$name] in kubeconfig file $conf"
    return 1
}

# Replace the key or cert item in json config file
replace_jsonconf_key_cert() {
    local conf="$1"
    local name="$2"
    local value="$(cat $3 | base64 -w0)"

    echo "Replacing [$name] in JSON config file $conf ..."

    # middle line with ',' at the end of line
    sed -i -e "s/\"${name}\":.*$/\"${name}\":\ \"${value}\",/g" $conf && return 0

    # However, still failed because of some other problems
    echo "Fail to replace [$name] in JSON config file $conf"
    return 1
}

# Generate the gRPC TLS CA and client/server keys and certificates
generate_tls_certificates() {
    local outdir="$1"
    if [ -e "$outdir/ca.crt" -a "$FORCE_REPLACE" != "YES" ] ; then
        echo "Certificates exist here: $outdir"
    else
        echo "Generating all the TLS certificates ..."
        mkdir -p $outdir
        [ -n "$outdir" ] && rm -rf $outdir/*
        $CATOOL genall $outdir
        chmod a+r $outdir/*
    fi
}

# Generate the PKCS1 private and public key
generate_asymmetric_keypair() {
    local prefix="$1"

    if [ -e "${prefix}private.pem" -a "$FORCE_REPLACE" != "YES" ] ; then
        echo "PKCS1 RSA key pair exist here: ${prefix}*.pem"
    else
        echo "Generating new key pair: $prefix/{private.pem,public.pem} ..."
        mkdir -p $(dirname $1) && \
        if [ "$IS_SM_MODE" == "YES" ] ; then
            # generate sm2 keypair
            openssl ecparam -name SM2 -genkey -noout -out ${prefix}private.pem
            openssl ec -in ${prefix}private.pem -pubout -out ${prefix}public.pem	
        else
            # generate pkcs1 rsa keypair
            openssl genrsa -out ${prefix}private.pem 2048 && \
            openssl rsa -in ${prefix}private.pem -pubout -out ${prefix}public.pem -RSAPublicKey_out
        fi
    fi
}

# Update the identity key and TLS key/certificate in kubeconfig
update_admin_kubeconfig() {
    local conf="$1"
    local ikey="$2"
    local key="$3"
    local cert="$4"
    local cacert="$5"

    # Check all the input parameters
    check_file_exist "kubeconfig" $conf || return 1
    check_file_exist "identityKey" $ikey || return 1
    check_file_exist "clientKey" $key || return 1
    check_file_exist "clientCert" $cert || return 1
    check_file_exist "clientCA" $cacert || return 1

    # Update the identity key and client TLS key/cert
    replace_kubeconfig_key_cert "$conf" "identityKey" "$ikey"
    replace_kubeconfig_key_cert "$conf" "clientKey" "$key"
    replace_kubeconfig_key_cert "$conf" "clientCert" "$cert"
    replace_kubeconfig_key_cert "$conf" "clientCA" "$cacert"
}

generate_all_certs_and_kubeconfig_files() {
    local CONFDIR=$INSTANCEDIR/etc/kubetee
    local CERTDIR=$INSTANCEDIR/etc/certs

    echo "==== Generate certficates and keys into ${INSTANCEDIR} ..."
    generate_tls_certificates "$CERTDIR" && \
    generate_asymmetric_keypair "$CERTDIR/aecs_admin_" && \
    generate_asymmetric_keypair "$CERTDIR/service_admin_" && \
    update_admin_kubeconfig \
        $CONFDIR/aecs_admin_test.kubeconfig \
        $CERTDIR/aecs_admin_private.pem \
        $CERTDIR/aecs_admin.key \
        $CERTDIR/aecs_admin.crt \
        $CERTDIR/ca.crt && \
    update_admin_kubeconfig \
        $CONFDIR/service_admin_test.kubeconfig \
        $CERTDIR/service_admin_private.pem \
        $CERTDIR/service_admin.key \
        $CERTDIR/service_admin.crt \
        $CERTDIR/ca.crt && \
    replace_jsonconf_key_cert \
        $CONFDIR/aecs_server.json \
        "aecs_admin_pubkey" \
        $CERTDIR/aecs_admin_public.pem
}

prepare_aecs_instance() {
    [ -d "$INSTANCEDIR" ] && return 0

    mkdir -p $INSTANCEDIR/bin
    cp $THISDIR/bin/*.sh $INSTANCEDIR/bin
    mkdir -p $INSTANCEDIR/etc/kubetee
    cp $THISDIR/conf/* $INSTANCEDIR/etc/kubetee/
    cp $THISDIR/../third_party/unified_attestation/deployment/conf/* $INSTANCEDIR/etc/kubetee/
    mkdir -p $INSTANCEDIR/etc/certs
    cp ./certs/* $INSTANCEDIR/etc/certs
}

# Check the arguments in given order
#
# Force to replace certs and key pairs if provide "--replace"
if [ "$1" == "--replace" ] ; then
    FORCE_REPLACE="YES"
    shift
fi
# Generate SM keypair
if [ "$1" == "--sm" ] ; then
    IS_SM_MODE="YES"
    shift
fi

# Start to execute
prepare_aecs_instance
generate_all_certs_and_kubeconfig_files
