#!/usr/bin/env bash
# COMPUTER B: create B's own ML-DSA-44 key + CSR. Only the CSR goes to A.
set -euo pipefail
source "$(dirname "$0")/../common/env.sh"
D="$PKI/mldsa_b"; mkdir -p "$D"; cd "$D"
"$OSSL" genpkey -algorithm ML-DSA-44 -out b_leaf.key; chmod 600 b_leaf.key
"$OSSL" req -new -key b_leaf.key -out b_leaf.csr -subj "/O=CS6530/CN=client-B"
echo "Send $D/b_leaf.csr to A. When A returns b_leaf.pem, inter.pem, root.pem, put them in $D/"
echo "Then on B compare:  $OSSL x509 -in $D/root.pem -noout -fingerprint -sha256"
