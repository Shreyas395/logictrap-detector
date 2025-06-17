import angr
import claripy

# loading the binary
proj = angr.Project("sha_cf", auto_load_libs=False)

# Try multiple CFG methods for better analysis
try:
    cfg = proj.analyses.CFGFast(normalize=True)
except:
    try:
        cfg = proj.analyses.CFGEmulated(normalize=True)
    except:
        cfg = None
        print("CFG analysis failed, continuing without it")

# identifying branch blocks in the CFG (blocks with more than one outgoing edge)
branch_blocks = set()
if cfg:
    branch_blocks = {
        node for node in cfg.graph.nodes
        if len(list(cfg.graph.successors(node))) > 1
    }
# collecting branch conditions for analysis
branch_conds = []
for block in branch_blocks:
    try:
        vexir = proj.factory.block(block.addr).vex
        for stmt in vexir.statements:
            if hasattr(stmt, 'guard') and stmt.guard is not None:
                branch_conds.append((block.addr, stmt.guard))
        if vexir.jumpkind == 'Ijk_Boring' and vexir.next:
            branch_conds.append((block.addr, vexir.next))
    except Exception:
        continue

#heuristic to score complexity of a branch condition
def score_complexity(expr):
    if expr is None:
        return 0
    s = str(expr) #converting expression to string
    score = 0
    if any(op in s for op in ["Xor", "Mul", "And", "Shl", "Shr", "Div", "Eq"]):
        score += 1
    if hasattr(expr, 'depth') and expr.depth > 4:
        score += 1
    return score

# score and filter for logic traps (complex branches)
scored_branches = [(addr, cond, score_complexity(cond)) for addr, cond in branch_conds]
logic_traps    = [(addr, cond, score) for addr, cond, score in scored_branches if score >= 1]
trap_addrs     = {addr for addr, _, _ in logic_traps}

# create a symbolic input of 80 bits
sym_input = claripy.BVS("sym_input", 8 * 10)
state = proj.factory.entry_state()

# Setup stdin multiple ways to ensure it works
stdin_data = angr.storage.SimFile(name='stdin', content=sym_input)
state.fs.insert('stdin', stdin_data)
state.posix.stdin = stdin_data

# Add newline constraint for fgets behavior
state.solver.add(sym_input.get_byte(8) == 0x0a)

#setting options to handle unkown memory
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Track if shell was spawned
shell_found = []

# hook for system() call that marks shell spawn
def _hook_shell_spawn(state):
    print("System call hooked!")
    state.globals["spawned_shell"] = True
    shell_found.append(state)
    return claripy.BVV(0, state.arch.bits)

# Hook system function
proj.hook_symbol("system", _hook_shell_spawn)

# Also hook at common addresses where system might be
try:
    for addr in proj.loader.main_object.plt.values():
        try:
            proj.hook(addr, _hook_shell_spawn)
        except:
            pass
except:
    pass

simgr = proj.factory.simgr(state)

# Try to reach logic traps first
if trap_addrs:
    print(f"Exploring {len(trap_addrs)} logic traps...")
    simgr.explore(
        find=lambda s: s.addr in trap_addrs,
        step_func=lambda sm: sm.stash(from_stash='active', to_stash='cut', 
                                     filter_func=lambda s: len(s.history.bbl_addrs) > 100)
    )

if simgr.stashes.get('found'):
    trap_state = simgr.stashes['found'][0]
    print(f"Reached trap at {hex(trap_state.addr)}")
else:
    trap_state = state

# Main exploration for shell spawn
simgr2 = proj.factory.simgr(trap_state)

def find_shell(s):
    return s.globals.get("spawned_shell", False)

def step_limit(sm):
    sm.stash(from_stash='active', to_stash='cut',
             filter_func=lambda s: len(s.history.bbl_addrs) > 150)
    return sm

print("Exploring for shell spawn...")
simgr2.explore(find=find_shell, step_func=step_limit)

# Check if we found via hook even if not in found stash
if shell_found and not simgr2.stashes.get('found'):
    print("Found via hook, using shell_found state")
    simgr2.stashes['found'] = [shell_found[-1]]

# Fallback exploration from entry
if not simgr2.stashes.get('found'):
    print("Trying direct exploration...")
    simgr3 = proj.factory.simgr(state)
    simgr3.explore(find=find_shell, step_func=step_limit)
    if simgr3.stashes.get('found'):
        simgr2 = simgr3
    elif shell_found:
        print("Found via hook in direct exploration")
        simgr2.stashes['found'] = [shell_found[-1]]

# Final fallback with more steps
if not simgr2.stashes.get('found'):
    print("Trying extended exploration...")
    simgr4 = proj.factory.simgr(state)
    simgr4.explore(
        find=find_shell,
        step_func=lambda sm: sm.stash(from_stash='active', to_stash='cut',
                                     filter_func=lambda s: len(s.history.bbl_addrs) > 300)
    )
    if simgr4.stashes.get('found'):
        simgr2 = simgr4
    elif shell_found:
        print("Found via hook in extended exploration")
        simgr2.stashes['found'] = [shell_found[-1]]

# Use shell_found as final fallback
if not simgr2.stashes.get('found') and shell_found:
    print("Using shell_found as fallback")
    simgr2.stashes['found'] = [shell_found[-1]]

if not simgr2.stashes.get('found'):
    print("No shell-spawn detected.")
    exit(0)

found = simgr2.stashes['found'][0]
print(f"Shell spawn found at {hex(found.addr)}")

# Get the input (first 8 bytes)
try:
    secret = found.solver.eval(sym_input, cast_to=bytes)[:8]
except:
    print("Failed to extract input")
    exit(0)

score = 0
controlled = any(sym_input.args[0] in c.variables for c in found.solver.constraints)
if controlled:
    score += 1

if trap_addrs and simgr.stashes.get('found'):
    score += 2

score += 2

try:
    stdout = found.posix.dumps(1)
    stderr = found.posix.dumps(2)
    if not any(x in stdout + stderr for x in [b"/bin/sh", b"sh"]):
        score += 1
except:
    pass

print(f"[+] Found input → triggers shell spawn: {secret!r}")
print(f"[+] Stealth score: {score} / 6")
if score > 4:
    print("High stealth score - Likely stealthy shell payload")
else:
    print("Lower score - May be noisy or simple payload")