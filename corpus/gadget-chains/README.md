# corpus/gadget-chains

Dormant Java deserialization gadget chains. Use this directory for
samples that become triggerable after small, benign-looking
modifications to a dependency.

## Layout

Each chain in its own subdirectory:

```
corpus/gadget-chains/
  chain-01-<short-name>/
    original.jar       # benign dependency
    modified.jar       # stealthy mod that activates the chain
    label.json         # ground truth
  chain-02-...
  chain-03-...
```

## `label.json` schema

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
