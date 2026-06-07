# logictrap-detector

A static-analysis tool for finding **logic-trap gates** in compiled
binaries: branches whose predicates hide dangerous behavior (shell
execution, deserialization, function-pointer writes) behind layers of
bitwise arithmetic and environment-dependent checks.

The tool combines:

- **Symbolic execution** (angr) for control-flow construction, sink
  discovery, and gate location.
- **Backward slicing + Ghidra-headless decompilation** for
  human-readable predicate extraction.
- **Language-model reasoning** for structured characterization of each
  gate — what kind of trigger it is, how hard it would be to bypass,
  and what payload class it guards.

Rather than trying to satisfy every gate it finds (futile against a
cryptographic signature check, useless against an unknown environment
variable), the tool aims to **describe** each gate precisely enough
that a human analyst can decide what to do with it.

## What you get

For each binary, the tool produces a list of candidate gates. Each one
includes:

- The address of the predicate basic block.
- The address of the dangerous sink it guards.
- The pseudo-C of the predicate (backward-sliced from the gate to its
  inputs, decompiled by Ghidra).
- The set of external dependencies the gate touches (env vars,
  randomness, file I/O, time, UID, network, processes).
- A **characterization** from the LLM with four structured fields:
  - `gate_kind`: one of `env`, `time`, `crypto`, `process`, `fs`,
    `net`, `hw`, `locale`, `mixed`.
  - `bypass_difficulty`: one of `trivial`, `env-controllable`,
    `fuzz-solvable`, `crypto-hard`, `unknown`.
  - `payload_class`: one of `shell-exec`, `deserialize`, `jit-write`,
    `fnptr-overwrite`, `other`.
  - `why`: a short natural-language justification quoting the lifted
    IR.
- A **sink-distance score** combining gate complexity, external
  dependency count, and distance to the sink in basic blocks.

## Installation

```bash
pip install -r requirements.txt
```

You also need:

- **Ghidra** (any recent release) for the slicer's pseudo-C
  pretty-printer. Set `GHIDRA_INSTALL_DIR` to the install path.
- One LLM backend for the characterizer:
  - **Ollama** (local, recommended default):
    ```bash
    ollama pull qwen2.5-coder:7b
    ```
  - **Google AI Studio**: set `GOOGLE_API_KEY`.
  - **Groq**: set `GROQ_API_KEY`.

## Quick start

Analyze a single binary:

```bash
python Model/logictrapdetector.py path/to/binary
```

Run the harness across every sample in the corpus:

```bash
python bench/run.py
```

Filter to a single category or sample:

```bash
python bench/run.py --filter synthetic
python bench/run.py --filter pin_check_l4
```

## How it works

The pipeline runs in five stages.

### 1. Control-flow reconstruction

angr's `CFGFast` builds the control-flow graph with full data
references and indirect-jump resolution. A snapshot of the first ten
nodes is emitted to `output/partial_cfg.png`.

### 2. Sink discovery

`gate_locator.SinkFinder` walks angr's knowledge base, the PLT, and
the symbol table for known dangerous functions (`system`, `execve`,
`execvp`, `popen`, `fork`, and friends). It then disassembles every
basic block to catch direct call instructions and raw `syscall` /
`int` / `sysenter` opcodes.

### 3. Gate location

`gate_locator.LogicTrapAnalyzer` scores each basic block by instruction
density:

| Instruction class                 | Score |
|-----------------------------------|-------|
| Bitwise op (`xor`, `and`, `shl`…) | +2    |
| Comparison (`cmp`, `test`…)       | +1    |
| Conditional jump                  | +1    |
| Call into an external gate        | +3    |

Blocks at or above the trap threshold (default 3) become candidate
gates.

### 4. Slicing

For each gate-to-sink pair, `slicer.GateSlicer` computes the backward
slice of instructions reaching the predicate, lifts the slice to angr
VEX IR, and shells out to Ghidra headless to pretty-print the result
as pseudo-C. External calls inside the slice are resolved into a
structured description (e.g. `getenv("LANG")`,
`EVP_DigestVerifyFinal(ctx, sig, 56)`).

### 5. Characterization

`characterizer.Characterizer` sends the slice, the pseudo-C, and the
structured external-call list to the configured LLM with a strict
output schema. The model returns the structured prediction shown in
the *What you get* section above.

`scorer.SinkDistanceScorer` then ranks all surfaced gates:

```
score = (gate_complexity * external_dep_count) / max(1, basic_blocks_to_sink)
```

Higher means the gate is more "loaded" (heavy obfuscation, many
external dependencies) and sits close to a dangerous sink.

External dependencies are modeled symbolically by
`external_gates.ExternalGateCatalog`, which hooks seven categories of
syscalls (`environ`, `time`, randomness, file I/O, UID, network,
processes) as angr `SimProcedure`s so that gates depending on them
are not eliminated as infeasible.

## Output

Per-sample JSON is written to `output/<sample-id>.json`:

```json
{
  "sample": {
    "id": "synthetic-pin-check-l4",
    "path": "Model/pin_check_l4",
    "source": "Model/Logic-bombs/pin_check_l4.c",
    "ground_truth": {
      "has_payload": true,
      "sink_class": "shell-exec",
      "gate_kinds": ["mixed"],
      "bypass_difficulty": "fuzz-solvable"
    }
  },
  "result": {
    "binary_path": "Model/pin_check_l4",
    "elapsed_sec": 14.2,
    "gates": [
      {
        "gate_addr": "0x401234",
        "sink_addr": "0x4013f0",
        "complexity": 9,
        "external_deps": ["fgets", "stdin"],
        "distance_to_sink": 4,
        "score": 4.5,
        "characterization": {
          "gate_kind": "mixed",
          "bypass_difficulty": "fuzz-solvable",
          "payload_class": "shell-exec",
          "why": "Predicate masks pin then XORs with 0x4B before a chained shift-multiply check."
        }
      }
    ]
  }
}
```

The aggregate roll-up across all samples sits in
`output/bench_results.json`.

## CLI reference

`bench/run.py` accepts:

| Flag               | Default                          | Description                                          |
|--------------------|----------------------------------|------------------------------------------------------|
| `--corpus`         | `corpus/`                        | Root directory of the corpus.                        |
| `--out`            | `output/bench_results.json`      | Aggregate output path.                               |
| `--filter`         | (none)                           | Substring match on category or sample id.            |
| `--max-input-size` | `256`                            | Symbolic stdin size passed to the analyzer.          |

The characterizer backend is selected by environment variable:

| Variable             | Values                          | Required for                |
|----------------------|---------------------------------|-----------------------------|
| `LOGICTRAP_LLM`      | `ollama` / `gemini` / `groq`    | Selecting the backend.      |
| `LOGICTRAP_MODEL`    | model name (e.g. `qwen2.5-coder:7b`) | Optional override.     |
| `GOOGLE_API_KEY`     | API key                         | `LOGICTRAP_LLM=gemini`.     |
| `GROQ_API_KEY`       | API key                         | `LOGICTRAP_LLM=groq`.       |
| `GHIDRA_INSTALL_DIR` | Path to Ghidra install          | Slicer pseudo-C lifting.    |

## Project layout

```
Model/
  logictrapdetector.py     orchestrator
  gate_locator.py          SinkFinder + LogicTrapAnalyzer
  external_gates.py        ExternalGateCatalog (SimProcedure factories)
  slicer.py                backward slice + Ghidra pseudo-C
  characterizer.py         LLM characterizer + output schema
  scorer.py                SinkDistanceScorer
  Logic-bombs/             source for the synthetic samples
bench/
  run.py                   corpus harness
corpus/
  synthetic/               handwritten logic bombs
  xz/                      XZ Utils backdoor artifacts (CVE-2024-3094)
  gadget-chains/           Java deserialization gadget chains
  negatives/               clean binaries (false-positive baseline)
output/                    results, generated CFG snapshots (gitignored)
tests/                     pytest suite
.github/workflows/         CI
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

The test suite covers the scorer formula edge cases, the corpus
manifest schema, the bench harness helpers, the external-gate catalog,
and the gate-locator defaults. CI runs the same `pytest` invocation on
every push to `main` and on every pull request.

## Corpus

The `corpus/` directory is split by category. Each category has a
`README.md` describing what goes in it and a `manifest.json` listing
samples with ground-truth labels:

- `synthetic/` — handwritten logic bombs with known triggers.
  Populated by default; used as the smoke-test tier.
- `xz/` — placeholder for XZ Utils backdoor artifacts. Useful as a
  test that the characterizer correctly reports
  `bypass_difficulty: crypto-hard` for the Ed448 signature gate.
- `gadget-chains/` — placeholder for dormant Java deserialization
  gadget chains.
- `negatives/` — clean binaries (coreutils, `bash`, `git`, `ssh`)
  for measuring false-positive rate.

See each subdirectory's `README.md` for the manifest schema and
suggested artifacts.

## Limitations

- Symbolic exploration time grows quickly on large or heavily
  obfuscated binaries. The exploration loop has a 60-second budget
  per pass.
- The characterizer's accuracy is bounded by the LLM. Local 7B-class
  models give reasonable structured output but will misclassify
  intricate crypto-style gates.
- Gates guarded by a cryptographic signature check are flagged but
  not solved. The tool reports `bypass_difficulty: crypto-hard`
  rather than attempting to forge the signature.
- Backward slicing relies on Ghidra being installed and on
  `GHIDRA_INSTALL_DIR` being set; without it, the slicer falls back
  to raw VEX IR.

## Intended use

Defensive security research, malware triage, CTF-binary analysis,
and experimentation with symbolic execution and LLM-assisted binary
reasoning.

## Contributing

Issues and pull requests welcome. Please run the test suite before
submitting:

```bash
pip install -r requirements-dev.txt
pytest
```
