"""
This is equivalent of vds19.py from IDAPython examples — x | ~x -> -1 optimizer.
Original: https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds19.py

Demonstrates MicroInstructionOptimizer + MicroInstructionVisitor pattern:
finds x | ~x patterns and rewrites them to mov -1.
"""

import ida_hexrays
import ida_idaapi

from ida_domain.microcode import (
    MicroInstructionOptimizer,
    MicroInstructionVisitor,
    MicroOpcode,
)


class OrNotVisitor(MicroInstructionVisitor):
    """Visitor that finds x | ~x patterns and rewrites to mov -1."""

    cnt = 0

    def visit(self, insn):
        if (
            insn.opcode == MicroOpcode.OR
            and insn.right.is_sub_instruction(MicroOpcode.BNOT)
            and insn.left == insn.right.sub_instruction.left
            and not insn.left.raw_operand.has_side_effects()
        ):
            insn.opcode = MicroOpcode.MOV
            insn.left.raw_operand.make_number(-1, insn.right.size)
            insn.right.clear()
            self.cnt += 1
        return 0


class OrNotOptimizer(MicroInstructionOptimizer):
    def optimize(self, block, insn, optflags):
        visitor = OrNotVisitor()
        insn.raw_instruction.for_all_insns(visitor)
        if visitor.cnt:
            block.mba.raw_mba.verify(True)
        return visitor.cnt


class vds19_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = 'Optimize x|~x (ida-domain)'
    wanted_hotkey = ''
    comment = ''
    help = ''

    def init(self):
        self.optimizer = None
        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = OrNotOptimizer()
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
    return vds19_plugin_t()
