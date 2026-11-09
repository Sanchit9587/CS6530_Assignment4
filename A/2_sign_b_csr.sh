#!/usr/bin/env bash
# COMPUTER A: issue client-B's ML-DSA leaf from B's CSR.   usage: ./2_sign_b_csr.sh path/to/b_leaf.csr
set -euo pipefail
source "$(dirname "$0")/../common/env.sh"
CSR="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
D="$PKI/mldsa"; cd "$D"
"$OSSL" req -in "$CSR" -noout -verify -subject      # proof-of-possession check
"$OSSL" x509 -req -in "$CSR" -CA inter.pem -CAkey inter.key -set_serial 0x1004 \
  -days $DAYS -extfile "$EXT" -extensions v3_leaf -out b_leaf.pem
der b_leaf.pem
"$OSSL" verify -no-CApath -no-CAstore -CAfile root.pem -untrusted inter.pem b_leaf.pem
echo "Return to B: b_leaf.pem inter.pem root.pem"
