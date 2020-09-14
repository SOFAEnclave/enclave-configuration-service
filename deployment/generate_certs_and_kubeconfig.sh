#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"
CATOOL="${THISDIR}/../tff/tools/gencert"


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

    echo "Replace [$name] in kubeconfig file $conf"
    sed -i -e "s/${name}:.*$/${name}:\ ${value}/g" $conf && return 0

    echo "Fail to replace [$name] in kubeconfig file $conf"
    return 1
}

# Replace the key or cert item in json config file
replace_jsonconf_key_cert() {
    local conf="$1"
    local name="$2"
    local value="$(cat $3 | base64 -w0)"

    echo "Replace [$name] in JSON config file $conf"

    # middle line with ',' at the end of line
    sed -i -e "s/\"${name}\":.*$/\"${name}\":\ \"${value}\",/g" $conf && return 0

    # However, still failed because of some other problems
    echo "Fail to replace [$name] in JSON config file $conf"
    return 1
}

# Generate the gRPC TLS CA and client/server keys and certificates
generate_tls_certificates() {
    local outdir="$1"
    $CATOOL gentest $outdir
}

# Generate the PKCS1 private and public key
generate_pkcs1_rsa_keypair() {
    local prefix="$1"
    openssl genrsa -out ${prefix}private.pem 2048
    openssl rsa -in ${prefix}private.pem -pubout -out ${prefix}public.pem -RSAPublicKey_out
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
    generate_tls_certificates "$THISDIR/certs" && \
    generate_pkcs1_rsa_keypair "$THISDIR/certs/admin_" && \
    generate_pkcs1_rsa_keypair "$THISDIR/certs/service_" && \
    update_admin_kubeconfig \
        $THISDIR/conf/aecs_admin_test.kubeconfig \
        $THISDIR/certs/admin_private.pem \
        $THISDIR/certs/test1.key \
        $THISDIR/certs/test1.crt \
        $THISDIR/certs/ca.crt && \
    update_admin_kubeconfig \
        $THISDIR/conf/service_admin_test.kubeconfig \
        $THISDIR/certs/service_private.pem \
        $THISDIR/certs/test2.key \
        $THISDIR/certs/test2.crt \
        $THISDIR/certs/ca.crt && \
    replace_jsonconf_key_cert \
        $THISDIR/conf/aecs_server.json \
        "aecs_admin_pubkey" \
        $THISDIR/certs/admin_public.pem
}

# Start to execute
generate_all_certs_and_kubeconfig_files
