# corpus/negatives

Clean binaries with legitimate env / time / locale / process checks.
Used to measure the false-positive rate of the gate locator and the
characterizer.

## Suggested set

Standard utilities exercise plenty of benign env-var and locale logic:

- `ls`, `cat`, `grep`, `find` (coreutils): `getenv("LANG")`,
  `getenv("LC_*")`, file-stat checks.
- `bash`: heavy on env-var introspection.
- `git`: `GIT_*` env vars, config-file reads, timestamps.
- `ssh`: process checks, env-controlled behavior.

Drop the binaries here, or write a manifest pointing to system paths.

## `manifest.json` schema

Each entry has `has_payload: false` with an expected upper bound of
zero gates flagged. `bench/run.py` counts every gate flagged on these
samples as a false positive.

```json
{
  "category": "negatives",
  "samples": [
    {
      "id": "neg-coreutils-ls",
      "path": "/usr/bin/ls",
      "ground_truth": {
        "has_payload": false,
        "expected_gates_flagged_upper_bound": 0,
        "note": "Lots of locale checks; should not be characterized as crypto/process trigger."
      }
    }
  ]
}
```
