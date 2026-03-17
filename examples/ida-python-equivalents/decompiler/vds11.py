"""
This is equivalent of vds11.py from IDAPython examples — goto chain optimizer.
Original: https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds11.py

Demonstrates MicroBlockOptimizer pattern: follows chains of unconditional
gotos and rewrites the first goto to jump directly to the final target.
"""

import ida_hexrays
import ida_idaapi

from ida_domain.microcode import MicroBlockOptimizer, MicroOpcode


class GotoChainOptimizer(MicroBlockOptimizer):
    """Collapse chains of unconditional gotos."""

    def optimize(self, block):
        tail = block.tail
        if not tail or tail.opcode != MicroOpcode.GOTO:
            return 0

        mf = block.mba
        visited = []
        t0 = tail.left.block_ref
        i = t0

        # Follow the goto chain using is_simple_goto / jump_target
        while True:
            if i in visited:
                return 0
            visited.append(i)
            b = mf[i]
            if not b.is_simple_goto:
                break
            i = b.jump_target

        if i == t0:
            return 0

        # Rewrite: point goto directly at chain end
        tail.raw_instruction.l.b = i
        block.replace_successor(t0, i)           # updates succset + predsets
        mf.mark_chains_dirty()
        mf.verify(True)
        return 1


class vds11_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = 'Optimize goto chains (ida-domain)'
    wanted_hotkey = ''
    comment = 'Sample plugin11 for Hex-Rays decompiler'
    help = ''

    def init(self):
        self.optimizer = None
        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = GotoChainOptimizer()
            self.optimizer.install()
            return ida_idaapi.PLUGIN_KEEP
        return ida_idaapi.PLUGIN_SKIP

    def term(self):
        if self.optimizer is not None:
            self.optimizer.remove()

    def run(self, arg):
        if arg == 1:
            return self.optimizer.remove()
        elif arg == 2:
            return self.optimizer.install()


def PLUGIN_ENTRY():
    return vds11_plugin_t()
