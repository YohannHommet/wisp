# Wisp — Threat Model

This document is the security contract. It is versioned with the code and
describes exactly what Wisp does and does **not** protect against *at the
current phase*. We never claim a property we have not shipped.

## Design principles

1. **Compose proven primitives.** Wisp invents no cryptography. It uses QUIC
   (TLS 1.3), BLAKE3, and SPAKE2 (RFC 9382). Rolling our own crypto is
   forbidden.
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

## Phase 1 — LAN, verified, TLS-pinned ✅

**Superseded by Phase 2.** Documented here for historical reference.

Transport: QUIC/TLS 1.3 with self-signed cert fingerprint pinning. Discovery
via mDNS advertising the code and file metadata in cleartext. Integrity via
BLAKE3 verify-before-rename.

Known limitation: an active LAN attacker could spoof the mDNS record (including
the fingerprint) and MITM the connection. Phase 2 closes this.

---

## Phase 2 (current) — PAKE-authenticated channel

**Transport:** QUIC (TLS 1.3) on the LAN. The sender generates a self-signed
certificate; its BLAKE3 fingerprint is advertised over mDNS and pinned by the
receiver. The pairing code selects which transfer to fetch.

**Authentication:** immediately after the QUIC connection is established, both
sides run a **SPAKE2** (RFC 9382, balanced PAKE) handshake over the bidirectional
stream. The pairing code is the shared PAKE password. Both sides derive a strong
ephemeral key and exchange BLAKE3-keyed confirmation MACs. A peer that does not
know the code cannot pass this step — it will observe no useful oracle.

**mDNS advertisement (Phase 2):** only `ch` = `hex(BLAKE3(code)[..16])` (a
commitment, not the code itself) and the TLS fingerprint are advertised. A
passive observer on the LAN cannot extract the code from a packet capture.

**Metadata:** filename, size, and BLAKE3 hash are **never sent over mDNS**. They
travel inside the PAKE-authenticated, TLS-encrypted QUIC stream, invisible to
a LAN observer.

**Integrity:** verify-before-rename on BLAKE3 hash (same as Phase 1).

| Property | Phase 2 status |
| --- | --- |
| Content confidentiality vs **passive** eavesdropper | ✅ TLS 1.3 over QUIC |
| Content integrity / corruption detection | ✅ BLAKE3 verify-before-rename |
| Content confidentiality vs **active mDNS spoofer** | ✅ PAKE fails without the code |
| Metadata confidentiality (name, size) | ✅ inside encrypted channel only |
| Mutual authentication of peers | ✅ SPAKE2 (RFC 9382) |
| Forward secrecy | ✅ QUIC ephemeral key exchange |
| Offline brute-force of pairing code | ✅ no usable oracle; PAKE is zero-knowledge |
| Channel binding (TLS ↔ PAKE key) | ⚠️ not yet — see note below |
| WAN / NAT traversal | ❌ Phase 3 |

**Remaining Phase-2 limitation (documented honestly):** the PAKE shared key and
the TLS session are not formally *bound* together (channel binding via TLS
exported key material). A very sophisticated active attacker who can both spoof
mDNS *and* knows the code could theoretically relay a legitimate PAKE exchange
over a MITM TLS connection. This requires knowing the code, which is the primary
secret — in practice, if the code is shared out-of-band (Signal, in-person), this
attack surface is minimal. Full channel binding is planned for Phase 2.5.

---

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
