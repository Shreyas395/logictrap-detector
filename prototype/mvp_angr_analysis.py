import angr 
import claripy


# loading the compiled binary
proj = angr.Project("./trap_binary_O0", auto_load_libs=False)

#creating the symbolic 3-byte input
input_len = 3
input_bvs = claripy.BVS("input", input_len * 8)

# set up symbolic stdin
state = proj.factory.full_init_state(stdin=input_bvs)

#constrain input to printable characters
for byte in input_bvs.chop(8):
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

#creating simulation manager
simgr = proj.factory.simgr(state)

def is_successful(s):
    return b"MALICIOUS PAYLOAD TRIGGERED" in s.posix.dumps(1)

simgr.explore(find=is_successful)

if simgr.found:
    found = simgr.found[0]
    concrete_input = found.solver.eval(input_bvs, cast_to=bytes)
    print(f"Payload is triggered with the input {concrete_input}")
    print(found.posix.dumps(1).decode())
else:
    print("No payload trigger found")