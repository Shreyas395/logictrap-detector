# corpus/negatives

Clean binaries with legitimate env/time/locale/process checks. Used to
measure the **false-positive rate** of the gate locator + LLM
characterizer. Per the verified caveats in the deep-research plan, this
is itself a publishable subcontribution — no prior work has measured
LLM-trigger FPR on benign environment checks.

## URTC-scoped target: ~10 clean binaries

Suggested set (cross-platform-safe):

- `ls`, `cat`, `grep`, `find` — coreutils, lots of `getenv("LANG")`,
  `getenv("LC_*")`, file-stat checks.
- `bash` — heavy on env-var introspection.
- `git` — env-var (`GIT_*`), config file reads, time stamps.
- `ssh` — process checks, env-controlled behavior.

Drop the binaries (or a manifest pointing to system paths) here.

## Ground-truth `manifest.json` schema

Each entry has `has_payload: false` and an `expected_gates_flagged: 0`
prediction. The eval driver in `bench/run.py` counts every gate flagged
on these as a false positive.

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

## Honest scoping note

The plan caps this at ~10 binaries for URTC. A full coreutils sweep
(>100 binaries) is the right follow-up for an arXiv-extended version
or a top-tier resubmission post-URTC.
