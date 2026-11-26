#!/bin/sh
# Writes throwaway TLS files for the TLS container tests into /certs (the
# `tls-certs` service of compose.test.yml mounts docker/test-certs there).
#
# TEST-ONLY. The keys are made on the test machine, are never committed
# (.gitignore) and protect nothing.
#
#   ca.pem         the CA of the test servers
#   server.pem     signed by ca.pem, for the host name `localhost` only
#   server.key     its key, readable by the database users of the containers
#   other-ca.pem   a CA that signed nothing: the "wrong CA" of the tests
set -eu
cd /certs
if [ -f ca.pem ] && [ -f server.pem ] && [ -f server.key ] && [ -f other-ca.pem ]; then
    exit 0
fi

ca() { # ca <name> <common name>
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
        -subj "/CN=$2" -keyout "$1.key" -out "$1.pem" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
}
ca ca "rivet test CA"
ca other-ca "rivet wrong test CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -CA ca.pem -CAkey ca.key -subj "/CN=localhost" -keyout server.key -out server.pem \
    -addext "subjectAltName=DNS:localhost" -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth"
# The CA keys are not needed again: a new run makes new files.
rm ca.key other-ca.key
chmod 644 ./*.pem server.key
echo "wrote the test TLS files"
