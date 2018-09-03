#!/usr/bin/env python2
import angr

p = angr.Project('./test.elf')

main = p.loader.main_object.get_symbol('main')
cfg = p.analyses.CFGFast()
loops = p.analyses.LoopFinder()

loop = loops.loops[0]

# Sim to loop entry point to gather initial constraints
loop_entry_simgr = p.factory.simgr(p.factory.entry_state())
loop_entry_simgr.explore(find=[loop.entry.addr,])
loop_entry_state = loop_entry_simgr.found[0]

# now search from the top of the loop back to itself
loop_simgr = p.factory.simgr(loop_entry_state)

def is_at_loop_entry(addr):
    """
    The entry of the loop doesn't have to be the top of a IRSB (the preceeding block can jump
    into the middle of a IRSB that is at the end of a loop iteration)
    """
    if addr in [successor.addr for successor in loop.entry.successors()]:
        return True

    return False

def has_looped(state):
    """
    Determine if the given state has been through the loop already.
    """
    # The loop entry addr(s) must show up at least twice
    return len(filter(is_at_loop_entry, state.history.bbl_addrs)) >= 2

def state_is_spinning(state):
    """
    Constrain all variables referenced in loop continue blocks to be the same value as the last loop entry, and
    test if this is satisfiable.
    If it is, we have a spinloop.
    """
    # NOTE: we don't apply constraints directly to `state` so that we can examine input on avoided/unsat cases
    test_state = state.copy()

    # TODO: automatically extract constraints on loop continue edges
    test_state.add_constraints(
        test_state.memory.load(test_state.regs.rbp - 0x420, 8) == loop_entry_state.memory.load(loop_entry_state.regs.rbp - 0x420, 8),
    )
    return test_state.satisfiable()

def find_cond(state):
    # We're only interested in things that have looped and are now back at the top of the loop
    if not has_looped(state) or not is_at_loop_entry(state.addr):
        return False

    # And for which nothing referenced in loop conditions has changed
    if state_is_spinning(state):
        return True

    return False

def avoid_cond(state):
    # Explicit breaks (we're out of the loop)
    if state.addr in [break_edge[1].addr for break_edge in loop.break_edges]:
        return True

    # If we haven't looped yet, don't avoid
    if not has_looped(state):
        return False

    # We've looped, so test if we're spinning. If we're not, abort.
    if not state_is_spinning(state):
        return True

    # We must be spinning! Don't avoid so we can find it.
    return False

loop_simgr.explore(find=find_cond, avoid=avoid_cond)

spinloop_state = loop_simgr.found[0]

dos_input = spinloop_state.posix.dumps(0)

print(repr(dos_input))
