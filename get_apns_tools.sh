#!/bin/bash

set -e

APNS_TOOLS_REPO=https://github.com/SilentCircle/apns_tools.git

die() {
    echo $* >&2
    exit 1
}

upstream_changed() {
    remote_commit=$(git rev-parse 'FETCH_HEAD^{commit}')
    local_commit=$(git rev-parse 'refs/heads/master^{commit}')
    test $local_commit != $remote_commit
}

get_tools() {
    mkdir -p tools
    pushd tools > /dev/null 2>&1

    if [[ -d apns_tools ]]; then
        cd apns_tools
        git checkout -q master
        git fetch -q origin master
        if upstream_changed; then
            git merge --ff FETCH_HEAD
            upstream_did_change=true
        else
            upstream_did_change=false
        fi
    else
        upstream_did_change=true
        git clone ${APNS_TOOLS_REPO}
        cd apns_tools
        git checkout -q master
    fi

    popd > /dev/null 2>&1
    $upstream_did_change
}

generate_new_certs() {
    local rc=0

    pushd tools/apns_tools > /dev/null 2>&1
    ./fake_apple_certs.sh
    rc=$?
    popd > /dev/null 2>&1
    return $rc
}

copy_cert_data() {
    CA_DIR=tools/apns_tools/CA
    CERTS_DIR=./certs

    [[ -d ${CA_DIR} ]] || die "Expected ${CA_DIR} to exist"

    mkdir -p ${CERTS_DIR}
    chmod -R a+w ${CERTS_DIR}
    find ${CERTS_DIR} -name '*.pem' -delete

    cp ${CA_DIR}/*.pem ${CERTS_DIR}/

    for dir in $CA_DIR ${CA_DIR}/WWDRCA ${CA_DIR}/ISTCA2G1; do
        cp $dir/{certs,private}/*.pem ${CERTS_DIR}/
    done
    chmod -R a+r ${CERTS_DIR}
}

if get_tools; then
    generate_new_certs || die "Error generating new certs"
fi

copy_cert_data

