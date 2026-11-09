#!/usr/bin/env python3
"""COMPUTER A — server A.
  python3 A/server_a.py --ping                     # FR-1 plain connectivity
  python3 A/server_a.py                            # TR-5 valid exchange
  python3 A/server_a.py --tamper-kem-pub           # TR-6 publish modified KEM key, original signature
  python3 A/server_a.py --wrong-kem-key            # TR-8 decapsulate with a different ML-KEM-768 key
"""
import argparse, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from tcp_helper import listen, send_msg, recv_msg, send_fields, recv_fields
import pq
from pq import log

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CA = os.path.join(ROOT, "pki", "mldsa")
OUT = os.path.join(ROOT, "artifacts", "A"); os.makedirs(OUT, exist_ok=True)

ap = argparse.ArgumentParser()
ap.add_argument("--bind", default="0.0.0.0"); ap.add_argument("--port", type=int, default=6530)
ap.add_argument("--ping", action="store_true")
ap.add_argument("--tamper-kem-pub", action="store_true")
ap.add_argument("--wrong-kem-key", action="store_true")
a = ap.parse_args()

log("A", f"host={socket.gethostname()} openssl={pq.ossl('version').stdout.strip()}")
srv = listen(a.bind, a.port); log("A", f"listening on {a.bind}:{a.port}")
conn, peer = srv.accept(); log("A", f"connection from {peer[0]}:{peer[1]}")

if a.ping:
    m = recv_msg(conn); log("A", f"RECV {m!r}")
    send_msg(conn, b"PONG from server-A " + socket.gethostname().encode()); log("A", "SENT pong")
    sys.exit(0)

with pq.Tmp() as t:
    # FR-5: separate ML-KEM-768 key pair, public key DER signed by A's ML-DSA leaf key
    kem_priv = os.path.join(OUT, "kem_priv.pem")      # private: never sent, never submitted
    kem_pub = pq.kem_keygen(kem_priv)
    open(os.path.join(OUT, "kem_pub.der"), "wb").write(kem_pub)
    kem_sig = pq.mldsa_sign(t, os.path.join(CA, "a_leaf.key"), kem_pub)
    open(os.path.join(OUT, "kem_pub.sig"), "wb").write(kem_sig)
    log("A", f"ML-KEM-768 pub DER={len(kem_pub)}B, ML-DSA sig over it={len(kem_sig)}B")

    pub_to_send = kem_pub
    if a.tamper_kem_pub:
        b = bytearray(kem_pub); b[-5] ^= 0x01; pub_to_send = bytes(b)
        log("A", "TR-6: publishing MODIFIED KEM public key with ORIGINAL signature")

    a_leaf = pq.pem_to_der(os.path.join(CA, "a_leaf.pem"))
    inter = pq.pem_to_der(os.path.join(CA, "inter.pem"))
    send_fields(conn, [a_leaf, inter, pub_to_send, kem_sig])
    log("A", f"SENT [A leaf {len(a_leaf)}B, inter {len(inter)}B, KEM pub {len(pub_to_send)}B, sig {len(kem_sig)}B]")

    try:
        ct, salt, nonce, enc, b_leaf, b_inter, b_sig = recv_fields(conn)
    except Exception as e:
        log("A", f"no record received ({e}) - B aborted"); sys.exit(1)
    log("A", f"RECV [KEM ct {len(ct)}B, salt {len(salt)}B, nonce {len(nonce)}B, enc+tag {len(enc)}B, "
             f"B leaf {len(b_leaf)}B, B inter {len(b_inter)}B, B sig {len(b_sig)}B]")
    for n, v in (("kem_ct.bin", ct), ("salt.bin", salt), ("nonce.bin", nonce), ("record.bin", enc),
                 ("b_transcript.sig", b_sig)):
        open(os.path.join(OUT, n), "wb").write(v)

    # FR-3: validate B's ML-DSA path against the locally trusted root only
    try:
        b_pem, subj, chain = pq.verify_chain(t, b_leaf, b_inter, os.path.join(CA, "root.pem"), "client-B")
    except ValueError as e:
        log("A", f"REJECT (certificate path validation): {e}"); sys.exit(2)
    log("A", f"B certificate path OK: {subj}")

    # FR-7: reconstruct transcript from received fields and verify B's ML-DSA signature
    tr = pq.transcript(ct, salt, nonce, enc)
    if not pq.mldsa_verify_cert(t, b_pem, tr, b_sig):
        log("A", "REJECT (ML-DSA transcript signature verification failed) - no plaintext released"); sys.exit(3)
    log("A", f"B transcript signature OK ({len(tr)}B transcript)")

    if len(salt) != 32 or len(nonce) != 12:
        log("A", "REJECT: bad salt/nonce length"); sys.exit(4)

    priv = kem_priv
    if a.wrong_kem_key:
        priv = t.path("other_kem.pem"); pq.kem_keygen(priv)
        log("A", "TR-8: decapsulating with a DIFFERENT ML-KEM-768 private key")
    ss = pq.kem_decap(t, priv, ct)
    log("A", f"decapsulated shared secret: {len(ss)}B  fingerprint={pq.fpr(ss)}")
    key = pq.hkdf(ss, salt)
    log("A", f"HKDF-SHA-256 -> 32B AES key derived independently (key fp={pq.fpr(key)})")

    try:
        pt = pq.aes_decrypt(key, nonce, enc)
    except Exception:
        log("A", "REJECT (AES-GCM authentication failed) - no plaintext released"); sys.exit(5)
    log("A", f"AES-GCM tag OK. PLAINTEXT: {pt.decode(errors='replace')}")
    send_msg(conn, b"ACK")
conn.close()
