import angr 

proj = angr.Project("logicbomb", auto_load_libs=False) #replace logicbomb with the actual logic bomb name
cfg = proj.analyses.CFGFast(normalize=True)

# block in cfg is a node, decision points are blocks with multiple successors
branch_blocks = {
    node for node in cfg.graph.nodes
    if len(list(cfg.graph.successors(node))) > 1
}

branch_conds = []
for block in branch_blocks:
    try:
        vexir = proj.factory.block(block.addr).fex # .vex translates the block to representation used by angr ,block from binary at a given address
        if vexir.jumpkind == 'Ijk_Boring' and vexir.statements: # the jump is a normal conditiional branch
            branch_conds.append((block.addr, vexir.next)) # symbolic expression that determines where the control flow goes next - basically represents a branch condition
    except Exception:
        continue

# define a heuristic for complex expressions, create a function that takes a branch conditional expression from the vexir and return True if it looks like a logic trap - if its obfuscated or complex
# filter for logic trap candidates - filter out simple branches that olny meet the complexity heuristic