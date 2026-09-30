# ADR-0003: LAN PAKE DoS Mitigation and Bounded Authentication Budget

**Date**: 2026-09-27  
**Status**: Accepted  
**Deciders**: Yohann Hommet, Security & Protocol Team  

## Context

In Wisp v0.2, the sender enforced a strict single-attempt policy on SPAKE2 authentication: any authentication failure immediately and permanently burned the pairing code and terminated the session. Concurrently, the sender allowed up to 3 pre-authentication transport retries before aborting (`MAX_PRE_AUTH_RETRIES = 3`).

Adversarial testing revealed two symmetric vulnerabilities on shared local networks:
1. **Unsolicited Probe DoS / Pre-Auth Kill**: Any ambient network port scan or rogue peer sending 3 empty TCP/QUIC handshakes caused `MAX_PRE_AUTH_RETRIES` to trip, prematurely aborting the legitimate sender before the true receiver even typed the code.
2. **Brute-Force vs Typo Usability Trade-off**: If a legitimate receiver made a single typographical error in the 4-word secret phrase, the pairing code was burned immediately, requiring the sender to regenerate and redistribute a new pairing code. However, simply allowing unbounded retries would allow an active LAN attacker to brute-force the 27.6-bit password entropy space.
3. **Expensive Crypto Pre-emption**: Unauthenticated connections previously triggered full SPAKE2 scalar multiplications on Curve25519 before demonstrating knowledge of the target session.

## Decision

We mitigate LAN PAKE DoS while strictly bounding online guess resistance through three composable mechanisms:

1. **Pre-PAKE Proof of Intent (`locator_token`)**:
   - Before executing any SPAKE2 group operations, the receiver must send a 32-byte proof of intent token:
     $$\text{locator\_token} = \text{BLAKE3-KeyedHash}_{K=\text{tls\_unique}}(\text{"wisp:v2:client-intent\\0"} \parallel \text{locator})$$
   - The token binds the public session locator (the 8-digit prefix) to the TLS 1.3 channel exporter.
   - The sender verifies this token in constant time (`ct_eq`). Connections that fail to supply a valid token (e.g., port scanners, rogue probes) return `HandshakeError::InvalidIntent` and are immediately closed.
   - Crucially, `InvalidIntent` **does not consume a password guess attempt**, eliminating probe-based DoS.

2. **Bounded 3-Attempt Password Budget (`MAX_AUTH_ATTEMPTS = 3`)**:
   - Only peers demonstrating valid intent (knowledge of the 8-digit locator) can trigger SPAKE2 execution.
   - For legitimate connection attempts with valid locators, the sender permits up to 3 failed SPAKE2 key confirmation attempts before burning the code.
   - A mandatory 1.0-second rate-limiting delay is enforced after every `AuthFailed` error.
   - Across 3 attempts, the probability of an online guess succeeding against the 4-word dictionary ($120^4 = 207{,}360{,}000$) is:
     $$P(\text{guess}) = \frac{3}{207{,}360{,}000} \approx 1.45 \times 10^{-8}$$
     This remains negligible while tolerating realistic human typographical errors.

3. **Session Preservation & Pre-Auth Resilience**:
   - The fragile `MAX_PRE_AUTH_RETRIES` counter is removed. Unsolicited transport drops or port probes are logged as warnings and closed without aborting the session.
   - The mDNS discovery advertisement is preserved across retry attempts until successful authentication or code burning.
   - Stalled or interrupted connections after key confirmation are strictly mapped to `AuthFailed` to prevent offline verification oracles.

## Alternatives Considered

### Alternative 1: Strict Single-Attempt Only (v0.2 Baseline)
- **Pros**: Absolutely minimal attack surface ($1 / 207\text{M}$).
- **Cons**: Severe usability friction. A single typo on mobile or terminal burns the code. Vulnerable to ambient LAN probes aborting the session.
- **Why not**: Does not address the unauthenticated port scan DoS.

### Alternative 2: IP-Based Rate Limiting
- **Pros**: Allows unlimited retries for legitimate IP addresses.
- **Cons**: On LANs (NAT, bridged Wi-Fi, or rogue DHCP), source IPs can be easily spoofed or shared among multiple clients. Adds stateful IP tracking complexity.
- **Why not**: Flawed security boundary on local networks.

### Alternative 3: Longer Wordlists (e.g., BIP-39 2048 words)
- **Pros**: 44 bits of entropy would allow larger retry budgets.
- **Cons**: Requires typing significantly longer or more complex words; breaks wire format and UX across version boundaries.
- **Why not**: Reserved for future major version (WSP/3); locator intent token solves the issue within the current code schema.

## Consequences

### Positive
- Ambient LAN port scans and spurious probes no longer kill the sender or burn pairing codes.
- Users can recover from typos without needing the sender to re-run and share a new code.
- Expensive SPAKE2 elliptic curve operations are never executed for unsolicited probes.
- Guess resistance remains firmly at $< 1.5 \times 10^{-8}$.

### Negative
- A malicious party on the same subnet who knows the public 8-digit locator can intentionally burn the 3-attempt budget in ~3 seconds, requiring a fresh code. (This is bounded denial-of-service, but never compromised confidentiality).
