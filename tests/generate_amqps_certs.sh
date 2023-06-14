#!/bin/bash

set -euo pipefail

function perform {
    echo "$ $1"
    eval $1
}

if [[ ! -d tls-gen ]]; then
    perform "git clone https://github.com/rabbitmq/tls-gen.git"
fi

perform "BASE_DIR=\"$(pwd)\""
perform "CERTS_DIR=\"${BASE_DIR}/amqps_certs\""
perform "cd tls-gen/basic"
perform "make"
perform "mkdir -p \"${CERTS_DIR}\""
perform "cd result"
perform "cp ca_certificate.pem \"${CERTS_DIR}/ca_cert.pem\""
perform "cp client_*_certificate.pem \"${CERTS_DIR}/client_cert.pem\""
perform "cp client_*_key.pem \"${CERTS_DIR}/client_key.pem\""
perform "cp server_*_certificate.pem \"${CERTS_DIR}/server_cert.pem\""
perform "cp server_*_key.pem \"${CERTS_DIR}/server_key.pem\""
perform "chmod a+r \"${CERTS_DIR}/client_key.pem\""
perform "chmod a+r \"${CERTS_DIR}/server_key.pem\""
perform "cd \"${BASE_DIR}\""
