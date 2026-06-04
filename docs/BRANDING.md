# Wisp — Brand Book

> A wisp of light that finds its way to you, then vanishes.

## The name

**Wisp** (n.) — a thin, fleeting streak of light; a will-o'-the-wisp that
appears, guides, and disappears. It carries three ideas at once:

- **Speed** — a wisp is made of light.
- **Privacy** — it *whispers*; it leaves no trace.
- **Ephemerality** — one-shot transfers that vanish when done.

CLI ergonomics: `wisp send file.pdf`, `wisp recv 7-tiger-saturn`.

## One-liner

**Wisp — send anything, to anyone, instantly. End-to-end encrypted. Zero trust, zero servers.**

## Positioning

> The security of a Magic-Wormhole code, the speed of a WireGuard tunnel,
> and zero infrastructure to trust — in a single binary, with one short code.

Wisp is not "yet another secure transfer." Its moat is a *combination* the
incumbents don't ship together:

1. **Verified streaming** — every chunk is authenticated as it lands (BLAKE3
   Merkle tree). Wisp never writes an unverified byte to disk, and resumes
   from any offset.
2. **Blind relay** — when direct P2P is impossible, the fallback relay only
   ever sees ciphertext. It cannot read content *or* metadata.
3. **Zero trust infrastructure** — pairing is a short human code backed by a
   PAKE. No accounts, no PKI, no server that can read your data.
4. **One static binary** — no runtime, no app store, no daemon required.

## Voice & tone

- **Confident, not loud.** We make precise claims we can prove (benchmarks +
  audit), never marketing superlatives we can't.
- **Honest about limits.** Every release states its threat model plainly. If a
  property isn't shipped yet, we say so.
- **Quiet by default.** The tool gets out of the way. Beautiful output, no spam.

## Visual identity (direction)

- **Symbol:** a single luminous streak / spark tapering to a point — the wisp.
- **Palette:** deep night (`#0B0E14`) background, electric cyan→violet spark
  gradient (`#22D3EE` → `#A78BFA`), warm off-white text (`#E6E1D6`).
- **Type:** geometric sans for the wordmark; monospace for the CLI surface.
- **Motion:** things *fade in and dissipate* — never harsh; light that arrives
  and leaves.

## Naming conventions

- Project / crate root: `wisp`
- Library crate: `wisp-core`
- CLI binary: `wisp`
- Protocol on the wire: **WSP/1** (Wisp Secure Protocol, version 1)
- mDNS service type: `_wisp._udp.local.`
- Pairing code format: `<number>-<word>-<word>` (e.g. `7-tiger-saturn`)
