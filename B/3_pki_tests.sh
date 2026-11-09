#!/usr/bin/env bash
# COMPUTER B: TR-1 (paths), TR-2 (signatures), TR-3 (wrong anchor), TR-4 (missing intermediate), FR-4.
# Needs pki/ecdsa/* (built here) and pki/mldsa_b/{root,inter,b_leaf,a_leaf}.pem (public, from A).
set -uo pipefail
source "$(dirname "$0")/../common/env.sh"
E="$PKI/ecdsa"; M="$PKI/mldsa_b"; W="$ROOTDIR/artifacts/tests"; rm -rf "$W"; mkdir -p "$W"
V() { "$OSSL" verify -no-CApath -no-CAstore "$@"; }   # isolated trust store every time
res() { if [ "$1" = "$2" ]; then echo "  => PASS (expected $2)"; else echo "  => FAIL (expected $2, got $1)"; fi; }
run() { local exp=$1; shift; echo "\$ $*" | sed "s|$ROOTDIR/||g"; "$@" 2>&1 | sed 's/^/    /'; local rc=${PIPESTATUS[0]}; [ $rc -eq 0 ] && r=ok || r=fail; res $r $exp; }

echo "host=$(hostname) $("$OSSL" version)"; echo
echo "== TR-1 valid paths =="
run ok V -CAfile "$E/root.pem" -untrusted "$E/inter.pem" -show_chain "$E/leaf.pem"
run ok V -CAfile "$M/root.pem" -untrusted "$M/inter.pem" -show_chain "$M/b_leaf.pem"
[ -f "$M/a_leaf.pem" ] && run ok V -CAfile "$M/root.pem" -untrusted "$M/inter.pem" -show_chain "$M/a_leaf.pem"

echo; echo "== FR-4 / TR-2 signatures =="
printf 'CS6530 A4 common test message\n' > "$W/msg.txt"
cp "$W/msg.txt" "$W/msg_altered.txt"; printf 'X' >> "$W/msg_altered.txt"
"$OSSL" x509 -in "$E/leaf.pem" -pubkey -noout > "$W/ecdsa_pub.pem"
"$OSSL" dgst -sha256 -sign "$E/leaf.key" -out "$W/ecdsa.sig" "$W/msg.txt"
"$OSSL" pkeyutl -sign -rawin -inkey "$M/b_leaf.key" -in "$W/msg.txt" -out "$W/mldsa.sig"
run ok   "$OSSL" dgst -sha256 -verify "$W/ecdsa_pub.pem" -signature "$W/ecdsa.sig" "$W/msg.txt"
run fail "$OSSL" dgst -sha256 -verify "$W/ecdsa_pub.pem" -signature "$W/ecdsa.sig" "$W/msg_altered.txt"
run ok   "$OSSL" pkeyutl -verify -rawin -certin -inkey "$M/b_leaf.pem" -in "$W/msg.txt" -sigfile "$W/mldsa.sig"
run fail "$OSSL" pkeyutl -verify -rawin -certin -inkey "$M/b_leaf.pem" -in "$W/msg_altered.txt" -sigfile "$W/mldsa.sig"

echo; echo "== TR-3 wrong trust anchor (correct intermediate, other PKI's root) =="
run fail V -CAfile "$M/root.pem" -untrusted "$E/inter.pem" "$E/leaf.pem"
run fail V -CAfile "$E/root.pem" -untrusted "$M/inter.pem" "$M/b_leaf.pem"

echo; echo "== TR-4 missing intermediate (correct root only) =="
run fail V -CAfile "$E/root.pem" "$E/leaf.pem"
run fail V -CAfile "$M/root.pem" "$M/b_leaf.pem"

echo; echo "== issuer relationships =="
for c in "$E/root.pem" "$E/inter.pem" "$E/leaf.pem" "$M/root.pem" "$M/inter.pem" "$M/b_leaf.pem"; do
  echo "$(basename $(dirname $c))/$(basename $c):"; "$OSSL" x509 -in "$c" -noout -subject -issuer -serial | sed 's/^/    /'
done
