"""
Equivalent of https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds7.py
"""

import ida_domain
from ida_domain.pseudocode import PseudocodeInstructionVisitor


class BlockDumpVisitor(PseudocodeInstructionVisitor):
    """Print every cit_block and its nested instructions."""

    def visit_instruction(self, insn):
        if insn.is_block:
            print(f'dumping block 0x{insn.ea:X}')
            for child in insn.block:
                print(f'  0x{child.ea:X}: insn {child.op.name.lower()}')
        return 0


db = ida_domain.Database.open()

func = db.functions.get_at(db.current_ea)
if func is None:
    print('Please position the cursor within a function')
    raise SystemExit(1)

pfunc = db.pseudocode.decompile(func)
BlockDumpVisitor().apply_to(pfunc.body)
