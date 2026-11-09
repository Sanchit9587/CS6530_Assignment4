# CS6530 Assignment 4 — Post-Quantum PKI and Authenticated Encrypted Exchange

Team: `<Name A, Roll A>` (server A, ML-DSA CA) · `<Name B, Roll B>` (client B, ECDSA PKI)

## Requirements (both computers)
- OpenSSL 3.5+ (ML-DSA, ML-KEM). macOS: `brew install openssl@3` (scripts auto-detect `/opt/homebrew/opt/openssl@3/bin/openssl`; else `export OSSL=/path/to/openssl`). Linux: build/install 3.5+.
- Python 3.9+ and `pip3 install cryptography` (HKDF-SHA-256, AES-256-GCM).
- Copy this whole `a4/` folder to both machines. Both must be on the same network; allow TCP 6530 inbound on A (macOS firewall prompt → Allow).

## Layout
```
common/ tcp_helper.py   2-byte length-framed TCP helper (no security)
        pq.py           OpenSSL CLI wrappers + HKDF/AES-GCM + transcript
        ext.cnf         CA (CA:TRUE, keyCertSign) and leaf (CA:FALSE, digitalSignature) profiles
A/      1_mldsa_ca.sh   ML-DSA-44 root -> intermediate -> server-A leaf
        2_sign_b_csr.sh issue client-B leaf from B's CSR
        server_a.py     server A
B/      1_ecdsa_pki.sh  ECDSA P-256 root -> intermediate -> leaf
        2_mldsa_csr.sh  B's own ML-DSA-44 key + CSR
        3_pki_tests.sh  TR-1..TR-4, FR-4
        4_measure.py    FR-8 sizes and timings
        client_b.py     client B
```

## Step by step
| # | Computer | Command |
|---|---|---|
| 0 | both | `hostname; ipconfig getifaddr en0` (Linux: `hostname -I`); `$OSSL version`; `sw_vers` / `uname -a` |
| 1 | A | `python3 A/server_a.py --ping` |
|   | B | `python3 B/client_b.py --host <A-IP> --ping`  → FR-1 / TR-1 connectivity |
| 2 | A | `bash A/1_mldsa_ca.sh` |
| 3 | B | `bash B/1_ecdsa_pki.sh` ; `bash B/2_mldsa_csr.sh` |
| 4 | B→A | copy `pki/mldsa_b/b_leaf.csr` to A (USB/AirDrop/scp) |
| 5 | A | `bash A/2_sign_b_csr.sh <path>/b_leaf.csr` |
| 6 | A→B | copy `pki/mldsa/{root,inter,b_leaf,a_leaf}.pem` into B's `pki/mldsa_b/` (public only, never `.key`) |
| 7 | both | **Out-of-band root check:** `$OSSL x509 -in <root.pem> -noout -fingerprint -sha256` on both, compare by reading aloud/photo |
| 8 | B | `bash B/3_pki_tests.sh` → TR-1, FR-4, TR-2, TR-3, TR-4 |
| 9 | A, then B | TR-5: `python3 A/server_a.py` / `python3 B/client_b.py --host <A-IP> --msg "CS6530 A4 team <ROLL_A> <ROLL_B>"` |
| 10 | A, then B | TR-6: `python3 A/server_a.py --tamper-kem-pub` / same client cmd → B rejects before encapsulating |
| 11 | A, then B | TR-7: `python3 A/server_a.py` / client cmd + `--tamper-record` → A: transcript-signature failure |
| 12 | A, then B | TR-8: `python3 A/server_a.py --wrong-kem-key` / client cmd → A: AES-GCM failure |
| 13 | A, then B | rerun step 9 after each failure (baseline still succeeds) |
| 14 | B | `python3 B/4_measure.py` → FR-8 |

Capture logs with `... 2>&1 | tee logs/<step>_<A|B>.log`.

## Which boundary rejects what
| Test | Rejected by | Where |
|---|---|---|
| TR-2 | ECDSA / ML-DSA signature verification | B |
| TR-3 | certificate path validation, error 20 at depth 1 (intermediate's issuer not a trust anchor) | B |
| TR-4 | certificate path validation, error 20 at depth 0 (leaf's issuer not found; root can't sign leaf directly) | B |
| TR-6 | ML-DSA signature over KEM public-key DER | B (before encap) |
| TR-7 | ML-DSA transcript signature (GCM would also fail) | A |
| TR-8 | AES-GCM tag (wrong-key decap yields a different secret, implicit rejection) | A |

## Design notes
- Trust: every `openssl verify` uses `-no-CApath -no-CAstore -CAfile <local root>`, with the intermediate only as `-untrusted`. Roots received over TCP are never trusted. Leaf CN is checked (`server-A` / `client-B`).
- A's ML-DSA certificate key signs; the separate ML-KEM-768 key establishes the secret. A signs the exact DER SubjectPublicKeyInfo of the KEM key.
- Transcript = `len32||Protocol_ID || len32||ct || len32||salt || len32||nonce || len32||enc+tag`, rebuilt by A from received fields.
- HKDF info `CS6530-A4|B-to-A|ML-KEM-768|AES-256-GCM|v1`, 32B fresh salt; AAD `CS6530-A4|client-B|server-A|v1`; 12B random nonce.
- Logs print only SHA-256 fingerprints of the shared secret / AES key, never the values.
- No forward secrecy: A's KEM private key is saved in `artifacts/A/kem_priv.pem`; anyone holding it can decapsulate recorded ciphertexts later. Use an ephemeral KEM key and delete it after use to get FS.

## Do NOT submit
`*.key`, `artifacts/A/kem_priv.pem`. Submit certs (`*.pem/*.der`), `artifacts/A/kem_pub.der`, `kem_pub.sig`, and `artifacts/B/*.bin`.
