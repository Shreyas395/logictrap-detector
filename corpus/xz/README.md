# corpus/xz

XZ Utils backdoor (CVE-2024-3094). The **gold demonstration case** for
the "characterize-don't-crack" reframe — the Ed448 signature gate is
information-theoretically uncrackable, so the system must correctly emit
`bypass_difficulty: crypto-hard` and abort the symex attempt.

## What to drop here (week 7)

- The malicious `liblzma.so.5.6.0` or `5.6.1` build artifacts (Akamai
  and Kaspersky publish hashed IOCs; do NOT pull from a live tarball).
- `bad-3-corrupt_lzma2.xz` and `good-large_compressed.lzma` from the
  injection payload.

## Ground truth (paper-citable)

| Gate                          | Kind     | Bypass difficulty | Source              |
|-------------------------------|----------|-------------------|---------------------|
| Ed448 signature verification  | crypto   | crypto-hard       | Securelist part 3   |
| `argv[0]` ends with `/sshd`   | process  | env-controllable  | Securelist part 3   |
| `TERM` unset                  | env      | env-controllable  | Securelist part 3   |
| `LD_DEBUG` / `LD_PROFILE` unset | env    | env-controllable  | Securelist part 3   |
| `LANG` set                    | env      | env-controllable  | Securelist part 3   |
| Debugger absent               | process  | env-controllable  | Securelist part 3   |

## Citations

- Akamai SIRT — XZ backdoor analysis.
- Kaspersky Securelist parts 1–3 — predicate enumeration.
- arXiv 2404.08987 — independent academic analysis.
- arXiv 2504.17473 — supply-chain trigger framing.

## `manifest.json`

Populated in week 7 once the artifacts are dropped in. Schema mirrors
`corpus/synthetic/manifest.json`.
