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
#   other-ca.pem   the "wrong CA" of the tests: it signed only other-client.pem
#   client-ca.pem  the CA that the test servers trust for client certificates
#   client.pem     signed by client-ca.pem, for the user `rivet_cert`; key client.key
#   other-client.pem  signed by other-ca.pem, also for `rivet_cert`; key other-client.key
set -eu
cd /certs
done=yes
for file in ca.pem server.pem server.key other-ca.pem client-ca.pem client.pem client.key \
    other-client.pem other-client.key; do
    [ -f "$file" ] || done=no
done
if [ "$done" = yes ]; then
    exit 0
fi

ca() { # ca <name> <common name>
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
        -subj "/CN=$2" -keyout "$1.key" -out "$1.pem" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
}
ca ca "rivet test CA"
ca other-ca "rivet wrong test CA"
ca client-ca "rivet test client CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -CA ca.pem -CAkey ca.key -subj "/CN=localhost" -keyout server.key -out server.pem \
    -addext "subjectAltName=DNS:localhost" -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth"
client() { # client <name> <CA name>
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
        -CA "$2.pem" -CAkey "$2.key" -subj "/CN=rivet_cert" -keyout "$1.key" -out "$1.pem" \
        -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=clientAuth"
}
client client client-ca
client other-client other-ca
# The CA keys are not needed again: a new run makes new files.
rm ca.key other-ca.key client-ca.key
chmod 644 ./*.pem ./*.key
echo "wrote the test TLS files"
