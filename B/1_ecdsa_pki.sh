#!/usr/bin/env bash
# COMPUTER B: classical ECDSA P-256 baseline root -> intermediate -> signing leaf.
set -euo pipefail
source "$(dirname "$0")/../common/env.sh"
D="$PKI/ecdsa"; mkdir -p "$D"; cd "$D"
echo "[B] OpenSSL: $("$OSSL" version)   host: $(hostname)"
gen() { "$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

gen root.key
"$OSSL" req -new -x509 -sha256 -key root.key -out root.pem -days $DAYS \
  -subj "/O=CS6530/CN=CS6530 ECDSA P-256 Root" -set_serial 0x2001 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

gen inter.key
"$OSSL" req -new -sha256 -key inter.key -out inter.csr -subj "/O=CS6530/CN=CS6530 ECDSA P-256 Intermediate"
"$OSSL" x509 -req -sha256 -in inter.csr -CA root.pem -CAkey root.key -set_serial 0x2002 \
  -days $DAYS -extfile "$EXT" -extensions v3_inter -out inter.pem

gen leaf.key
"$OSSL" req -new -sha256 -key leaf.key -out leaf.csr -subj "/O=CS6530/CN=ecdsa-signer-B"
"$OSSL" x509 -req -sha256 -in leaf.csr -CA inter.pem -CAkey inter.key -set_serial 0x2003 \
  -days $DAYS -extfile "$EXT" -extensions v3_leaf -out leaf.pem

for c in root inter leaf; do der $c.pem; done
chmod 600 *.key
echo; echo "== ECDSA root fingerprint =="; fp root.pem
"$OSSL" verify -no-CApath -no-CAstore -CAfile root.pem -untrusted inter.pem leaf.pem
