#!/bin/sh
# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Test material of the TLS tests (task X1). It is generated with the openssl command: one test root, a
# rogue root, and the certificates the tests need. The keys of the roots are kept in a temporary directory
# and removed at the end: only the certificates, the leaf keys and the revocation list are kept here, and
# they are for the tests only.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir certs
: > index.txt
echo 1000 > serial
echo 01 > crlnumber

cat > ca.cnf <<'CNF'
[ ca ]
default_ca = test_ca
[ test_ca ]
dir = .
database = index.txt
new_certs_dir = certs
serial = serial
crlnumber = crlnumber
default_md = sha256
default_crl_days = 36500
default_days = 3650
policy = policy_any
unique_subject = no
copy_extensions = none
[ policy_any ]
commonName = supplied
[ server_ext ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
[ client_ext ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
CNF

# A root: a key, a self-signed certificate, and a database for the issued certificates.
root() {
    name=$1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$name.key" -out "$name.pem" -days 36500 -subj "/CN=$name" \
        -addext "basicConstraints=critical,CA:true" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    mkdir -p "$name.db/certs"
    : > "$name.db/index.txt"
    echo 1000 > "$name.db/serial"
    echo 01 > "$name.db/crlnumber"
    sed "s#^dir = \.#dir = $name.db#; s#test_ca#$name#" ca.cnf > "$name.cnf"
}

# A leaf certificate of a root: a key, a request, and the certificate signed by the root.
# $3 is the extension section, $4 and $5 the start and end of the validity (optional).
leaf() {
    root=$1
    name=$2
    ext=$3
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" 2>/dev/null
    if [ $# -ge 5 ]; then
        openssl ca -batch -config "$root.cnf" -name "$root" -cert "$root.pem" -keyfile "$root.key" \
            -in "$name.csr" -out "$name.pem" -extensions "$ext" -startdate "$4" -enddate "$5" \
            -notext 2>/dev/null
    else
        openssl ca -batch -config "$root.cnf" -name "$root" -cert "$root.pem" -keyfile "$root.key" \
            -in "$name.csr" -out "$name.pem" -extensions "$ext" -notext 2>/dev/null
    fi
}

root igs-root
root igs-rogue
leaf igs-root server server_ext
leaf igs-root client client_ext
leaf igs-rogue rogue client_ext
leaf igs-root expired client_ext 20200101000000Z 20200102000000Z
leaf igs-root revoked client_ext
openssl ca -batch -config igs-root.cnf -name igs-root -cert igs-root.pem -keyfile igs-root.key \
    -revoke revoked.pem 2>/dev/null
openssl ca -config igs-root.cnf -name igs-root -cert igs-root.pem -keyfile igs-root.key \
    -gencrl -out crl.pem 2>/dev/null

cp igs-root.pem "$here/root.pem"
cp igs-rogue.pem "$here/rogue-root.pem"
cp crl.pem "$here/crl.pem"
for name in server client rogue expired revoked; do
    cp "$name.pem" "$here/$name.pem"
    cp "$name.key" "$here/$name.key"
done
echo "fixtures written to $here (the roots' keys were discarded)"
