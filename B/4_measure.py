#!/usr/bin/env python3
"""FR-8: sizes and timings. Run on computer B (has both PKIs' public certs + its own keys).
Timing method: wall-clock (time.perf_counter) median of N runs of the OpenSSL CLI.
LIMIT: includes process start-up + PEM parsing (~ms), so it overstates the primitive cost;
`openssl speed` numbers at the end show raw primitive throughput for comparison."""
import os, statistics, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import pq

R = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
E, M = os.path.join(R, "pki", "ecdsa"), os.path.join(R, "pki", "mldsa_b")
N = 20
def sz(p): return os.path.getsize(p)
def der_cert(p): return len(pq.pem_to_der(p))
def der_pub(p):
    pem = subprocess.run([pq.OSSL, "x509", "-in", p, "-pubkey", "-noout"], capture_output=True, check=True).stdout
    return len(subprocess.run([pq.OSSL, "pkey", "-pubin", "-outform", "DER"], input=pem,
                              capture_output=True, check=True).stdout)

print("== DER sizes (bytes) ==")
print(f"{'':28}{'ECDSA P-256':>14}{'ML-DSA-44':>14}")
for label, e, m in (("root cert", "root.pem", "root.pem"), ("intermediate cert", "inter.pem", "inter.pem"),
                    ("leaf cert", "leaf.pem", "b_leaf.pem")):
    print(f"{label:28}{der_cert(os.path.join(E,e)):>14}{der_cert(os.path.join(M,m)):>14}")
ce = sum(der_cert(os.path.join(E, f)) for f in ("root.pem", "inter.pem", "leaf.pem"))
cm = sum(der_cert(os.path.join(M, f)) for f in ("root.pem", "inter.pem", "b_leaf.pem"))
print(f"{'complete chain (3 certs)':28}{ce:>14}{cm:>14}")
print(f"{'sent path (leaf+inter)':28}{ce-der_cert(os.path.join(E,'root.pem')):>14}{cm-der_cert(os.path.join(M,'root.pem')):>14}")
print(f"{'leaf public key (SPKI DER)':28}{der_pub(os.path.join(E,'leaf.pem')):>14}{der_pub(os.path.join(M,'b_leaf.pem')):>14}")

td = tempfile.mkdtemp(); msg = os.path.join(td, "m"); open(msg, "wb").write(b"CS6530 A4 timing message")
es, ms = os.path.join(td, "e.sig"), os.path.join(td, "m.sig")
subprocess.run([pq.OSSL, "dgst", "-sha256", "-sign", os.path.join(E, "leaf.key"), "-out", es, msg], check=True)
subprocess.run([pq.OSSL, "pkeyutl", "-sign", "-rawin", "-inkey", os.path.join(M, "b_leaf.key"), "-in", msg, "-out", ms], check=True)
print(f"{'signature':28}{sz(es):>14}{sz(ms):>14}   (ECDSA DER sig varies 70-72B)")
kp = os.path.join(td, "k.pem"); kpub = pq.kem_keygen(kp)
with pq.Tmp() as t: ct, ss = pq.kem_encap(t, kpub)
print(f"ML-KEM-768: public key DER {len(kpub)}B, ciphertext {len(ct)}B, shared secret {len(ss)}B")

def tm(cmd):
    xs = []
    for _ in range(N):
        t0 = time.perf_counter(); subprocess.run(cmd, capture_output=True, check=True); xs.append(time.perf_counter()-t0)
    return f"{statistics.median(xs)*1000:8.2f} ms"
O = pq.OSSL
pubf = os.path.join(td, "kpub.der"); open(pubf, "wb").write(kpub); ctf = os.path.join(td, "ct"); open(ctf, "wb").write(ct)
print(f"\n== CLI timings, median of {N} (includes process start-up) ==")
print("baseline `openssl version`  ", tm([O, "version"]))
print("ECDSA keygen                ", tm([O, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", os.path.join(td, "x")]))
print("ML-DSA-44 keygen            ", tm([O, "genpkey", "-algorithm", "ML-DSA-44", "-out", os.path.join(td, "x")]))
print("ML-KEM-768 keygen           ", tm([O, "genpkey", "-algorithm", "ML-KEM-768", "-out", os.path.join(td, "x")]))
print("ECDSA sign                  ", tm([O, "dgst", "-sha256", "-sign", os.path.join(E, "leaf.key"), "-out", os.path.join(td, "y"), msg]))
print("ML-DSA-44 sign              ", tm([O, "pkeyutl", "-sign", "-rawin", "-inkey", os.path.join(M, "b_leaf.key"), "-in", msg, "-out", os.path.join(td, "y")]))
epub = os.path.join(td, "ep.pem"); open(epub, "wb").write(subprocess.run([O, "x509", "-in", os.path.join(E, "leaf.pem"), "-pubkey", "-noout"], capture_output=True).stdout)
print("ECDSA verify                ", tm([O, "dgst", "-sha256", "-verify", epub, "-signature", es, msg]))
print("ML-DSA-44 verify            ", tm([O, "pkeyutl", "-verify", "-rawin", "-certin", "-inkey", os.path.join(M, "b_leaf.pem"), "-in", msg, "-sigfile", ms]))
print("ML-KEM-768 encap            ", tm([O, "pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", pubf, "-out", os.path.join(td, "c"), "-secret", os.path.join(td, "s")]))
print("ML-KEM-768 decap            ", tm([O, "pkeyutl", "-decap", "-inkey", kp, "-in", ctf, "-secret", os.path.join(td, "s")]))

print("\n== openssl speed (raw primitive ops/s, 1 s each) ==")
print("(ML-DSA-44 is not benchmarkable via `openssl speed` in 3.5; use the CLI timings above)")
for alg in ("ecdsap256", "ML-KEM-768"):
    r = subprocess.run([O, "speed", "-seconds", "1", alg], capture_output=True, text=True)
    lines = (r.stdout + r.stderr).splitlines()
    print("\n".join(l for l in lines if "/s" in l or alg.lower().replace("p256", "") in l.lower()
                    and not l.startswith(("CPUINFO", "compiler", "options"))))
