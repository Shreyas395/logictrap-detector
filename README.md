# logictrap-detector

## Abstract

logictrap-detector is a security research framework for detecting stealthy shell payloads hidden behind logic-obfuscated control flow in compiled binaries. The system addresses limitations of traditional static and dynamic analysis by combining guided symbolic execution, heuristic-driven path prioritization, and targeted fuzzing to systematically reach guarded execution states.

## Motivation

Modern malware and challenge binaries increasingly conceal malicious behavior behind:

- Deeply nested logical conditions  
- Bitwise-heavy predicate checks  
- Environment- or time-dependent execution gates  
- Randomized or externally influenced control flow  

These techniques significantly reduce the effectiveness of naive analysis approaches.  
logictrap-detector addresses this gap by prioritizing execution paths that are semantically close to dangerous system primitives while maintaining tractable exploration.

## System Overview

The framework integrates symbolic execution, control-flow analysis, and input generation into a unified pipeline for uncovering guarded behavior. External dependencies are explicitly modeled to reduce false infeasibility and to improve coverage of paths that depend on environmental or runtime conditions.

## Core Capabilities

### Guided Symbolic Exploration

Uses the angr framework to explore program paths with domain-specific heuristics that prioritize states approaching high-risk primitives such as system() and execve(), rather than uniform path enumeration.

### Constraint-Aware Input Generation

Augments symbolic execution with targeted fuzzing to generate concrete inputs for paths guarded by complex or brittle constraints that are difficult to solve symbolically.

### External Dependency Modeling

Identifies and simulates interactions with environment variables, randomness sources, file I/O, networking, time, and process control to prevent premature path elimination.

### Logic-Gated Control-Flow Analysis

Detects regions of control flow dominated by layered comparisons, bitwise arithmetic, or compound predicates that commonly serve as execution gates for hidden payloads.

### Payload Ranking and Prioritization

Scores discovered payloads based on constraint depth, gate interactions, and structural complexity to prioritize inputs with higher evasion potential.

## Installation

```bash
pip install angr
```

Additional dependencies may be required depending on the target binary and analysis configuration.

## Usage

### Analyze a binary

```bash
python logictrapdetector.py /path/to/binary
```

## Analysis Pipeline

1. **Binary Initialization**  
   Loads the target executable into angr and prepares the symbolic execution environment.

2. **Gate Identification**  
   Discovers external dependencies such as randomness, environment variables, file I/O, time, and networking that influence control flow.

3. **Control-Flow Reconstruction**  
   Builds a control-flow graph to identify reachable and unexplored execution paths.

4. **Sink Identification**  
   Locates dangerous primitives including system(), execve(), and related calls.

5. **Logic Gate Detection**  
   Flags control regions with dense logical computation likely guarding sensitive behavior.

6. **External Call Simulation**  
   Hooks or simulates external calls to preserve path feasibility.

7. **Guided Symbolic Exploration**  
   Applies heuristic-driven exploration to advance toward guarded sinks while limiting path explosion.

8. **Targeted Fuzzing**  
   Generates concrete inputs to complement symbolic exploration in hard-to-solve regions.

9. **Result Aggregation and Reporting**  
   Collects, ranks, and reports inputs that successfully trigger guarded behavior.

## Output

Each discovered payload includes:

- Triggering input  
- Stealth score indicating evasion potential  
- Discovery method (symbolic execution or fuzzing)  
- Trigger location (function or address)  
- External gate values  
- Constraint count  

## Stealth Scoring Model

- Base discovery method: 3–5 points  
- Logic gate complexity: +2–10 points  
- External dependency interactions: +1 point per gate  
- Constraint complexity: +1 point per factor  

## Exploration Strategy

- Prioritize states near dangerous system primitives  
- Favor unexplored basic blocks to improve coverage  
- Bound symbolic constraint growth to prevent path explosion  
- Enforce timeouts for long-running analyses  

## Limitations

Analysis may be slow on large or heavily obfuscated binaries.  
Some execution paths may remain unreachable due to environmental assumptions.

## Intended Use

This project is intended for defensive security research, malware analysis, and experimentation with symbolic execution techniques.
