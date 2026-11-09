#!/usr/bin/env python3
"""COMPUTER B — client B.
  python3 B/client_b.py --host <A-IP> --ping
  python3 B/client_b.py --host <A-IP> --msg "Team: <roll1>, <roll2> ..."      # TR-5
  python3 B/client_b.py --host <A-IP> --msg "..." --tamper-record             # TR-7
"""
import argparse, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from tcp_helper import connect, send_msg, recv_msg, send_fields, recv_fields
import pq
from pq import log

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MY = os.path.join(ROOT, "pki", "mldsa_b")   # b_leaf.key, b_leaf.pem, inter.pem, root.pem (trusted copy)
OUT = os.path.join(ROOT, "artifacts", "B"); os.makedirs(OUT, exist_ok=True)

ap = argparse.ArgumentParser()
ap.add_argument("--host", required=True); ap.add_argument("--port", type=int, default=6530)
ap.add_argument("--ping", action="store_true")
ap.add_argument("--msg", default="CS6530 A4 team message")
ap.add_argument("--tamper-record", action="store_true")
a = ap.parse_args()

log("B", f"host={socket.gethostname()} openssl={pq.ossl('version').stdout.strip()}")
s = connect(a.host, a.port); log("B", f"connected to {a.host}:{a.port} from {s.getsockname()[0]}")

if a.ping:
    send_msg(s, b"PING from client-B " + socket.gethostname().encode()); log("B", "SENT ping")
    log("B", f"RECV {recv_msg(s)!r}"); sys.exit(0)

with pq.Tmp() as t:
    a_leaf, a_inter, kem_pub, kem_sig = recv_fields(s)
    log("B", f"RECV [A leaf {len(a_leaf)}B, inter {len(a_inter)}B, KEM pub {len(kem_pub)}B, sig {len(kem_sig)}B]")

    # FR-3/FR-5: path validation with pre-checked trusted root, then signature on exact KEM DER bytes
    try:
        a_pem, subj, _ = pq.verify_chain(t, a_leaf, a_inter, os.path.join(MY, "root.pem"), "server-A")
    except ValueError as e:
        log("B", f"REJECT (certificate path validation): {e}"); sys.exit(2)
    log("B", f"A certificate path OK: {subj}")
    if not pq.mldsa_verify_cert(t, a_pem, kem_pub, kem_sig):
        log("B", "REJECT (ML-DSA signature on KEM public key failed) - NOT encapsulating"); sys.exit(3)
    pq.check_kem_pub(t, kem_pub)
    log("B", "A's ML-KEM-768 public key signature OK -> key authenticated")

    # FR-6: encapsulate, derive
    ct, ss = pq.kem_encap(t, kem_pub)
    log("B", f"encapsulated: ct={len(ct)}B shared secret={len(ss)}B fingerprint={pq.fpr(ss)}")
    salt, nonce = os.urandom(32), os.urandom(12)
    key = pq.hkdf(ss, salt)
    log("B", f"HKDF-SHA-256 -> 32B AES key (key fp={pq.fpr(key)})")

    # FR-7: encrypt, sign transcript
    pt = a.msg.encode()
    assert pt, "message must be nonempty"
    enc = pq.aes_encrypt(key, nonce, pt)
    tr = pq.transcript(ct, salt, nonce, enc)
    sig = pq.mldsa_sign(t, os.path.join(MY, "b_leaf.key"), tr)
    log("B", f"AES-256-GCM record={len(enc)}B (incl. 16B tag); transcript sig={len(sig)}B")

    if a.tamper_record:
        b = bytearray(enc); b[0] ^= 0x01; enc = bytes(b)
        log("B", "TR-7: flipped 1 bit of ciphertext AFTER signing (signature not recomputed)")

    for n, v in (("kem_ct.bin", ct), ("salt.bin", salt), ("nonce.bin", nonce),
                 ("record.bin", enc), ("transcript.sig", sig)):
        open(os.path.join(OUT, n), "wb").write(v)
    b_leaf = pq.pem_to_der(os.path.join(MY, "b_leaf.pem"))
    b_inter = pq.pem_to_der(os.path.join(MY, "inter.pem"))
    send_fields(s, [ct, salt, nonce, enc, b_leaf, b_inter, sig])
    log("B", "SENT record [ct, salt, nonce, enc+tag, B leaf, B inter, B sig]")
    try:
        log("B", f"RECV {recv_msg(s)!r}")
    except Exception:
        log("B", "A closed without ACK (A rejected the record)")
s.close()
