# logictrap-detector

## Key Features

- **Symbolic Execution**  
  Thoroughly explores program paths using the angr framework.

- **Dynamic Fuzzing**  
  Generates and tests custom inputs alongside symbolic runs.

- **External-Call Modeling**  
  Recognizes and simulates calls to things like `system()`, file I/O, networking, randomness, environment variables, and more.

- **Logic-Trap Detection**  
  Spots code blocks with heavy comparisons or bitwise math: areas likely guarding security checks.

- **Stealth Scoring**  
  Rates each payload by how quiet it can be (complexity + evasion potential).

## Usage

### Basic scan of a binary
```bash
python logictrapdetector.py /path/to/your/binary
```

## How It Works

### Load the binary
Load the target file into angr for analysis.

### Discover external calls
Identify "gates" (randomness, environment, file I/O, time, networking, process control).

### Build control-flow graph
Construct a CFG to map all possible execution paths.

### Extract relevant strings
Pull out shell-related strings and cross-reference their usage.

### Detect dangerous calls
Spot risky functions like system(), execve(), etc.

### Identify logic traps
Locate code regions with heavy comparisons or bitwise operations.

### Model external calls
Hook or simulate external functions so symbolic execution can handle them.

### Run guided symbolic execution
Explore promising paths with custom exploration strategies.

### Run intelligent fuzzing
Complement symbolic runs with targeted fuzz-generated inputs.

### Collect and report payloads
Compile, score, and present payloads that trigger shell commands.

## Output Format

### Input string
The payload that triggers a shell or logic trap.

### Stealth score
How subtle the payload is (higher = more evasion potential).

### Discovery method
Whether it was found via symbolic execution or fuzzing.

### Trigger location
The address or function where the payload activates.

### Gate values
Values returned by external calls (e.g., getenv, time).

### Constraint count
The number of symbolic conditions involved.

## Stealth Scoring Breakdown

### Base method
3–5 points

### Logic-trap complexity
+2–10 points

### Gate interactions
+1 point each

### Constraint complexity
+1 point per factor

## Exploration Strategies

### Prioritize system-call proximity
Focus on states near dangerous calls.

### Cover new blocks first
Encourage exploration of unvisited code paths.

### Limit constraints
Prevent symbolic explosion by capping condition counts.

### Handle timeouts gracefully
Ensure clean termination on long-running analyses.

## Limitations

### Performance
Large or heavily obfuscated binaries may take a long time to analyze.

### Coverage
Some execution paths may be missed.