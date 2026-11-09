# Source this from the other scripts. Override OSSL if your OpenSSL 3.5+ is elsewhere.
# macOS (Homebrew): /opt/homebrew/opt/openssl@3/bin/openssl  (Apple Silicon)
#                   /usr/local/opt/openssl@3/bin/openssl     (Intel)
if [ -z "$OSSL" ]; then
  for c in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl openssl; do
    if command -v "$c" >/dev/null 2>&1; then OSSL="$c"; break; fi
  done
fi
export OSSL
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTDIR="$(cd "$HERE/.." && pwd)"
EXT="$ROOTDIR/common/ext.cnf"
PKI="$ROOTDIR/pki"
DAYS=365

ver=$("$OSSL" version | awk '{print $2}')
case "$ver" in
  3.[5-9]*|3.[1-9][0-9]*|[4-9].*) ;;
  *) echo "ERROR: need OpenSSL 3.5+, found $ver at $OSSL (brew install openssl@3)"; exit 1;;
esac

der() { "$OSSL" x509 -in "$1" -outform DER -out "${1%.pem}.der"; }
fp()  { "$OSSL" x509 -in "$1" -noout -fingerprint -sha256; }
