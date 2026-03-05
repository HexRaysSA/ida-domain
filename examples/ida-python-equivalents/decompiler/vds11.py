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

        # Follow the goto chain
        while True:
            if i in visited:
                return 0
            visited.append(i)
            b = mf[i]
            m2 = b.first_regular_insn
            if not m2 or m2.opcode != MicroOpcode.GOTO:
                break
            i = m2.left.block_ref

        if i == t0:
            return 0

        # Rewrite: point goto directly at chain end
        tail.raw_instruction.l.b = i
        block.raw_block.succset[0] = i
        mf.raw_mba.get_mblock(i).predset.add(block.serial)
        mf.raw_mba.get_mblock(t0).predset._del(block.serial)
        mf.raw_mba.mark_chains_dirty()
        mf.raw_mba.verify(True)
        return 1


class vds11_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = 'Optimize goto chains (ida-domain)'
    wanted_hotkey = ''
    comment = 'Sample plugin11 for Hex-Rays decompiler'
    help = ''

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = GotoChainOptimizer()
            self.optimizer.install()
            return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self.optimizer.remove()

    def run(self, arg):
        if arg == 1:
            return self.optimizer.remove()
        elif arg == 2:
            return self.optimizer.install()


def PLUGIN_ENTRY():
    return vds11_plugin_t()
