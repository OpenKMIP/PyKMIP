#!/bin/bash

set -e
set -x

if [[ "${RUN_INTEGRATION_TESTS}" == "1" ]]; then
    sudo mkdir -p /etc/pykmip/certs
    sudo mkdir -p /etc/pykmip/policies
    cd /etc/pykmip/certs
    sudo openssl req -x509 -subj "/CN=test" -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    cd -
    sudo cp ./.travis/pykmip.conf /etc/pykmip/pykmip.conf
    sudo cp ./.travis/server.conf /etc/pykmip/server.conf
    sudo cp ./.travis/policy.json /etc/pykmip/policies/policy.json
    sudo mkdir /var/log/pykmip
    sudo chmod 777 /var/log/pykmip
    python ./bin/run_server.py &
    tox -e integration -- --config client
else
    tox
fi
