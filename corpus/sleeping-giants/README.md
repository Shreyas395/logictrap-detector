# corpus/sleeping-giants

Dormant Java deserialization gadget chains, drawn from Kreyssig et al.
"Sleeping Giants" (ACM CCS 2025). They found 53 manually verified
dormant chains in 533 dependencies — 26.08% activation rate after minor
stealthy code modifications.

## What to drop here (week 7)

Per the URTC scope cut: **3 chains, not all 53**. Pick a diverse triple:
one Tabby-detected, one Crystallizer-detected, one AndroChain-detected,
so the eval shows coverage across detection styles.

Each chain goes in its own subdir:

```
corpus/sleeping-giants/
  chain-01-<short-name>/
    original.jar       # benign dependency
    modified.jar       # stealthy mod that activates the chain
    label.json         # ground truth for the chain trigger
  chain-02-...
  chain-03-...
```

## Ground-truth schema for `label.json`

```json
{
  "chain_name": "...",
  "detector": "tabby|crystallizer|androchain",
  "sink_class": "deserialize",
  "gate_kinds": ["trivial"],
  "bypass_difficulty": "trivial",
  "modification_summary": "1-2 sentences describing what changed"
}
```

## Citations

- arXiv 2504.20485 — Sleeping Giants, CCS 2025.

The CCS supplementary material includes the chain list and modification
recipes.
