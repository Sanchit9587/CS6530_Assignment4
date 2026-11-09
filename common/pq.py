"""Thin wrappers: OpenSSL 3.5 CLI for X.509/ML-DSA/ML-KEM, `cryptography` for HKDF + AES-GCM.
No primitive is implemented here."""
import hashlib, os, shutil, struct, subprocess, tempfile, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL_ID = b"CS6530-A4|B-to-A|v1"
HKDF_INFO   = b"CS6530-A4|B-to-A|ML-KEM-768|AES-256-GCM|v1"
GCM_AAD     = b"CS6530-A4|client-B|server-A|v1"

def _find_ossl():
    if os.environ.get("OSSL"):
        return os.environ["OSSL"]
    for c in ("/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"):
        if os.path.exists(c):
            return c
    return shutil.which("openssl") or "openssl"
OSSL = _find_ossl()

def log(tag, msg):
    print(f"{time.strftime('%H:%M:%S')} [{tag}] {msg}", flush=True)

def ossl(*args, check=True):
    r = subprocess.run([OSSL, *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed:\n{r.stdout}{r.stderr}")
    return r

class Tmp:
    """Scratch dir for transient files; removed on exit."""
    def __enter__(self):
        self.d = tempfile.mkdtemp(prefix="a4_"); return self
    def __exit__(self, *a):
        shutil.rmtree(self.d, ignore_errors=True)
    def write(self, name, data: bytes):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f: f.write(data)
        return p
    def path(self, name): return os.path.join(self.d, name)

def read(p):
    with open(p, "rb") as f: return f.read()

def pem_to_der(pem_path):
    return subprocess.run([OSSL, "x509", "-in", pem_path, "-outform", "DER"],
                          capture_output=True, check=True).stdout

# ---------- certificate path validation ----------
def verify_chain(t: Tmp, leaf_der, inter_der, trusted_root_pem, expected_cn):
    """Isolated store: only the locally pre-checked root is trusted; intermediate supplied as untrusted."""
    leaf = t.write("peer_leaf.der", leaf_der)
    inter = t.write("peer_inter.der", inter_der)
    leaf_pem, inter_pem = t.path("peer_leaf.pem"), t.path("peer_inter.pem")
    ossl("x509", "-inform", "DER", "-in", leaf, "-out", leaf_pem)
    ossl("x509", "-inform", "DER", "-in", inter, "-out", inter_pem)
    r = ossl("verify", "-no-CApath", "-no-CAstore", "-CAfile", trusted_root_pem,
             "-untrusted", inter_pem, "-purpose", "any", "-show_chain", leaf_pem, check=False)
    if r.returncode != 0:
        raise ValueError("CERTIFICATE PATH VALIDATION FAILED:\n" + r.stdout + r.stderr)
    subj = ossl("x509", "-in", leaf_pem, "-noout", "-subject", "-nameopt", "RFC2253").stdout.strip()
    if f"CN={expected_cn}" not in subj:
        raise ValueError(f"IDENTITY MISMATCH: expected CN={expected_cn}, got {subj}")
    algo = ossl("x509", "-in", leaf_pem, "-noout", "-text").stdout
    if "ML-DSA-44" not in algo:
        raise ValueError("peer leaf is not ML-DSA-44")
    return leaf_pem, subj, r.stdout.strip()

# ---------- ML-DSA message signatures (no external digest) ----------
def mldsa_sign(t: Tmp, key_pem, data: bytes) -> bytes:
    d = t.write("tosign.bin", data); s = t.path("sig.bin")
    ossl("pkeyutl", "-sign", "-rawin", "-inkey", key_pem, "-in", d, "-out", s)
    return read(s)

def mldsa_verify_cert(t: Tmp, cert_pem, data: bytes, sig: bytes) -> bool:
    d = t.write("toverify.bin", data); s = t.write("vsig.bin", sig)
    r = ossl("pkeyutl", "-verify", "-rawin", "-certin", "-inkey", cert_pem,
             "-in", d, "-sigfile", s, check=False)
    return r.returncode == 0

# ---------- ML-KEM-768 ----------
def kem_keygen(priv_path):
    ossl("genpkey", "-algorithm", "ML-KEM-768", "-out", priv_path)
    os.chmod(priv_path, 0o600)
    return subprocess.run([OSSL, "pkey", "-in", priv_path, "-pubout", "-outform", "DER"],
                          capture_output=True, check=True).stdout

def kem_encap(t: Tmp, pub_der: bytes):
    p = t.write("kem_pub.der", pub_der); ct, ss = t.path("kem.ct"), t.path("kem.ss")
    ossl("pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", p, "-out", ct, "-secret", ss)
    return read(ct), read(ss)

def kem_decap(t: Tmp, priv_pem, ct: bytes):
    c = t.write("rx.ct", ct); ss = t.path("rx.ss")
    ossl("pkeyutl", "-decap", "-inkey", priv_pem, "-in", c, "-secret", ss)
    return read(ss)

def check_kem_pub(t: Tmp, pub_der):
    p = t.write("chk.der", pub_der)
    txt = ossl("pkey", "-pubin", "-inform", "DER", "-in", p, "-noout", "-text").stdout
    if "ML-KEM-768" not in txt:
        raise ValueError("KEM public key is not ML-KEM-768")

# ---------- KDF / AEAD / transcript ----------
def hkdf(ss: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(ss)

def transcript(ct, salt, nonce, enc):
    return b"".join(struct.pack(">I", len(f)) + f for f in (PROTOCOL_ID, ct, salt, nonce, enc))

def fpr(b: bytes) -> str:
    """Short fingerprint for logs (never print the secret itself)."""
    return hashlib.sha256(b"fp|" + b).hexdigest()[:16]

def aes_encrypt(key, nonce, pt):  return AESGCM(key).encrypt(nonce, pt, GCM_AAD)
def aes_decrypt(key, nonce, ct):  return AESGCM(key).decrypt(nonce, ct, GCM_AAD)
