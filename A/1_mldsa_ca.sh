#!/usr/bin/env bash
# COMPUTER A: build ML-DSA-44 root -> intermediate -> server-A leaf.
set -euo pipefail
source "$(dirname "$0")/../common/env.sh"
D="$PKI/mldsa"; mkdir -p "$D"; cd "$D"
echo "[A] OpenSSL: $("$OSSL" version)   host: $(hostname)"

# Root (self-signed)
"$OSSL" genpkey -algorithm ML-DSA-44 -out root.key
"$OSSL" req -new -x509 -key root.key -out root.pem -days $DAYS \
  -subj "/O=CS6530/CN=CS6530 ML-DSA-44 Root" -set_serial 0x1001 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# Intermediate (signed by root)
"$OSSL" genpkey -algorithm ML-DSA-44 -out inter.key
"$OSSL" req -new -key inter.key -out inter.csr -subj "/O=CS6530/CN=CS6530 ML-DSA-44 Intermediate"
"$OSSL" x509 -req -in inter.csr -CA root.pem -CAkey root.key -set_serial 0x1002 \
  -days $DAYS -extfile "$EXT" -extensions v3_inter -out inter.pem

# Leaf server-A (signed by intermediate)
"$OSSL" genpkey -algorithm ML-DSA-44 -out a_leaf.key
"$OSSL" req -new -key a_leaf.key -out a_leaf.csr -subj "/O=CS6530/CN=server-A"
"$OSSL" x509 -req -in a_leaf.csr -CA inter.pem -CAkey inter.key -set_serial 0x1003 \
  -days $DAYS -extfile "$EXT" -extensions v3_leaf -out a_leaf.pem

for c in root inter a_leaf; do der $c.pem; done
chmod 600 *.key
echo; echo "== ML-DSA root fingerprint (check out-of-band with B) =="; fp root.pem
"$OSSL" verify -no-CApath -no-CAstore -CAfile root.pem -untrusted inter.pem a_leaf.pem
echo "Give B these PUBLIC files: root.pem inter.pem   (never the .key files)"
