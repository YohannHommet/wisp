# Wisp — Threat Model

This document is the security contract. It is versioned with the code and
describes exactly what Wisp does and does **not** protect against *at the
current phase*. We never claim a property we have not shipped.

## Design principles

1. **Compose proven primitives.** Wisp invents no cryptography. It uses QUIC
   (TLS 1.3), BLAKE3, and (from Phase 2) a CFRG-track PAKE. Rolling our own
   crypto is forbidden.
2. **Authenticate before persisting.** No unverified byte is ever written under
   the final filename. Data lands in a `.part` file and is renamed atomically
   only after integrity verification.
3. **Least trust.** No accounts, no PKI, no server that can read user data. Any
   relay we add must be *blind* (ciphertext + opaque routing only).
4. **Honest defaults.** Insecure modes, if any, are opt-in and loudly labeled.

## Assets

- **Confidentiality** of file *content*.
- **Confidentiality** of *metadata* (filename, size, who-sends-what-to-whom).
- **Integrity & authenticity** of delivered bytes.
- **Availability** of a transfer (resistance to griefing / DoS on the LAN).

## Adversaries

- **Passive eavesdropper** on the local network or the path.
- **Active on-path attacker** (can inject, drop, reorder, spoof mDNS).
- **Malicious relay** (future WAN phase).
- **Malicious peer** (someone who has, or guesses, the code).

---

## Phase 1 (current) — LAN, verified, TLS-pinned

**Transport:** QUIC (TLS 1.3) on the LAN. The sender generates a self-signed
certificate; its SHA-256 fingerprint is advertised over mDNS and **pinned** by
the receiver. The pairing code selects which advertised transfer to fetch.

**Integrity:** the sender publishes the file's BLAKE3 hash. The receiver streams
into a `.part` file, hashes incrementally, verifies the full hash, and only then
renames. A mismatch deletes the partial file. (Phase 1.5 upgrades this to
per-chunk BLAKE3/`bao` verified streaming + resume.)

| Property | Phase 1 status |
| --- | --- |
| Content confidentiality vs **passive** eavesdropper | ✅ TLS 1.3 over QUIC |
| Content integrity / corruption detection | ✅ BLAKE3 verify-before-rename |
| Content confidentiality vs **active mDNS spoofer** | ⚠️ **Not yet** — see below |
| Metadata confidentiality (name, size) | ❌ advertised in cleartext over mDNS |
| Mutual authentication of peers | ⚠️ fingerprint pinning only (TOFU-on-LAN) |
| Forward secrecy | ✅ QUIC ephemeral key exchange |
| WAN / NAT traversal | ❌ Phase 3 |

**Known Phase-1 limitation (documented honestly):** an *active* attacker on the
same LAN can advertise a competing mDNS record under the same code with their
own certificate fingerprint and MITM an unauthenticated pairing. **This is
exactly what the PAKE in Phase 2 closes** — the code becomes a shared secret
that authenticates the channel, making spoofing computationally infeasible
without offline brute-force resistance.

Do not use Phase 1 on an untrusted LAN for confidential data. Use Phase 2+.

---

## Phase 2 (planned) — PAKE-authenticated channel

- Short code becomes a **CPace** (balanced PAKE) password. Both sides derive a
  strong shared key with **mutual authentication** and **no offline dictionary
  attack**. A wrong code aborts with no usable oracle.
- The QUIC/TLS session is **bound** to the PAKE secret (channel binding), so an
  mDNS spoofer cannot interpose.
- **All metadata** (filename, size, structure) moves *inside* the encrypted
  channel. The only cleartext is a *blinded* rendezvous topic.

## Phase 3 (planned) — WAN, blind relay

- Rendezvous via DHT / minimal server addressed by a blinded topic.
- NAT traversal via ICE-style hole punching.
- Fallback **blind relay** forwards only E2E ciphertext; it learns neither
  content nor metadata.

## Phase 4 (planned) — performance & assurance

- Multipath bonding, optional FEC for lossy links.
- Wire-format fuzzing (`cargo-fuzz`), formal analysis of the handshake
  (Tamarin/ProVerif), and an independent third-party audit **before** the word
  "secure" appears unqualified in marketing.

## Out of scope (always)

- Endpoint compromise (malware on sender/receiver).
- Coercion of a party who holds the code.
- Traffic-analysis resistance against a global passive adversary (we reduce
  metadata leakage; we do not claim anonymity).
