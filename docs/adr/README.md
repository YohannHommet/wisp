# Architecture Decision Records (ADRs)

This directory documents the key architectural choices, protocol designs, and storage invariants of Wisp.

## Decision Log

| ADR | Title | Status | Date |
|:---|:---|:---:|:---:|
| [0001](0001-in-flight-directory-streaming.md) | In-Flight Directory Streaming Architecture | Accepted | 2026-09-22 |
| [0002](0002-transfer-resumption-and-checkpointing.md) | Transfer Resumption and Periodic Checkpointing | Accepted | 2026-09-24 |
| [0003](0003-lan-pake-dos-mitigation-and-bounded-auth-budget.md) | LAN PAKE DoS Mitigation and Bounded Authentication Budget | Accepted | 2026-09-27 |

## Contributing an ADR
To record a new architectural decision, copy [`template.md`](template.md) to `NNNN-decision-title.md` and add an entry to the index table above.
