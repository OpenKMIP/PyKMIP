#!/bin/bash

set -e
set -x

pkill -f run_server.py || true
sleep 1

if [[ "${RUN_INTEGRATION_TESTS}" == "1" ]]; then
    sudo mkdir -p /etc/pykmip/certs
    sudo mkdir -p /etc/pykmip/policies
    cd /etc/pykmip/certs
    sudo openssl req -x509 -subj "/CN=test" -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    cd -
    sudo cp ./.travis/pykmip.conf /etc/pykmip/pykmip.conf
    sudo cp ./.travis/server.conf /etc/pykmip/server.conf
    sudo cp ./.travis/policy.json /etc/pykmip/policies/policy.json
    sudo mkdir -p /var/log/pykmip
    sudo chmod 777 /var/log/pykmip
    sudo chmod -R 777 /etc/pykmip/
    python3 ./bin/run_server.py &
    tox -e integration -- --config client
elif [[ "${RUN_INTEGRATION_TESTS}" == "2" ]]; then
    # Set up the SLUGS instance
    cp -r ./.travis/functional/slugs /tmp/
    slugs -c /tmp/slugs/slugs.conf &

    # Set up the PyKMIP server
    cp -r ./.travis/functional/pykmip /tmp/
    python3 ./bin/create_certificates.py
    mv *.pem /tmp/pykmip/certs/
    sudo mkdir -p /var/log/pykmip
    sudo chmod 777 /var/log/pykmip
    pykmip-server -f /tmp/pykmip/server.conf -l /tmp/pykmip/server.log &

    # Run the functional tests
    tox -e functional -- --config-file /tmp/pykmip/client.conf
else
    tox
fi
