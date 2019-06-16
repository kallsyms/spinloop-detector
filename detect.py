#!/usr/bin/env python3
import angr


class SpinLoopExplorationTechnique(angr.ExplorationTechnique):
    def __init__(self, init_state, loop, cfg):
        super().__init__()
        self.init_state = init_state
        self.loop = loop
        self.cfg = cfg

        self.after_first_loop_state = None

    def _is_at_loop_entry(self, addr):
        """
        The entry of the loop doesn't have to be the top of a IRSB (the preceeding block can jump
        into the middle of a IRSB that is at the end of a loop iteration)
        """
        if addr in (successor.addr for successor in self.loop.entry.successors()):
            return True

        return False

    def _loop_count(self, state):
        """
        Returns the number of times the loop entry point has been hit, giving the index of the current loop iteration.
        """
        return len(list(filter(self._is_at_loop_entry, list(state.history.bbl_addrs) + [state.addr])))

    def filter(self, simgr, state, **kwargs):
        print(hex(state.addr))

        # If we've broken out of the loop, avoid
        if state.addr in (break_edge[1].addr for break_edge in self.loop.break_edges):
            return "deadended"

        # Continue to the beginning of the second iteration
        if self._loop_count(state) < 2:
            return "active"

        # constrain ourselves to take the same path as iter 1
        # XXX: doesn't look like this is working?
        if self._loop_count(state) < 3:
            bbl_hist = list(state.history.bbl_addrs) + [state.addr]
            for i, bb in enumerate(bbl_hist):
                if any(bb == s.addr for s in self.loop.entry.successors()):
                    first_loop_start = i
                    break

            for i, bb in enumerate(bbl_hist):
                if i <= first_loop_start:
                    continue
                if any(bb == s.addr for s in self.loop.entry.successors()):
                    second_loop_start = i
                    break

            for bb1, bb2 in zip(bbl_hist[first_loop_start:second_loop_start], bbl_hist[second_loop_start:]):
                if bb1 != bb1:
                    print("Avoiding to constrain second loop to match path of first")
                    return "deadended"

            return "active"

        test_state = state.copy()

        for break_bb, _ in self.loop.break_edges:
            bb_addrs = [break_bb.addr]

            # BB addresses saved in history may not be the same as those in CFGs.
            # Look for additional bb addresses that might point to this same bb
            for pred in self.cfg.model.get_node(break_bb.addr).predecessors:
                for target, kind in self.cfg.model.get_successors_and_jumpkind(pred):
                    if target.addr == break_bb.addr and kind == "Ijk_Boring":
                        bb_addrs.append(pred.addr)

            first_loop_constraint = None
            second_loop_constraint = None

            for action in state.history.actions:
                if action.type != "constraint":
                    continue

                if action.bbl_addr in bb_addrs:
                    if first_loop_constraint is None:
                        first_loop_constraint = action.constraint
                    elif second_loop_constraint is None:
                        second_loop_constraint = action.constraint
                        break

            if first_loop_constraint is None:
                print(f"No constraints around {break_bb.addr:#x}")
                if self.loop.entry.addr in bb_addrs:
                    print("Loop entry not constrained by symbolic input")
                    return "deadended"

                continue

            if first_loop_constraint is not None and second_loop_constraint is None:
                print(f"Constraint on first loop found ({first_loop_constraint}) for bb {break_bb.addr:#x}, but no second one found")
                continue

            for a, b in zip(first_loop_constraint.ast.args, second_loop_constraint.ast.args):
                print(f"Constraining {a} == {b}")
                test_state.add_constraints(a == b)

        if test_state.satisfiable():
            return "found"
        else:
            return "deadended"

    def complete(self, simgr):
        return len(simgr.stashes["found"]) > 0


if __name__ == "__main__":
    p = angr.Project('./test.elf', auto_load_libs=False)

    main = p.loader.main_object.get_symbol('main')
    cfg = p.analyses.CFGFast(normalize=True)
    loops = p.analyses.LoopFinder()

    loop = loops.loops[0]

    # Sim to loop entry point to gather initial constraints
    loop_entry_simgr = p.factory.simgr(p.factory.entry_state())
    loop_entry_simgr.explore(find=[loop.entry.addr])
    loop_entry_state = loop_entry_simgr.found[0]

    # now search from the top of the loop back to itself
    loop_simgr = p.factory.simgr(loop_entry_state)
    loop_simgr.use_technique(SpinLoopExplorationTechnique(loop_entry_state, loop, cfg))
    loop_simgr.explore()
    spinloop_state = loop_simgr.found[0]
    dos_input = spinloop_state.posix.dumps(0)
    print(repr(dos_input))
