"""
This is equivalent of vds10.py from IDAPython examples — assertion call argument injection.
Original: https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds10.py

Demonstrates MicroInstructionOptimizer pattern: adds the assertion string
as a call argument to DbgRaiseAssertionFailure() calls so they show up
in the decompiler output.
"""

import ida_hexrays
import ida_idaapi

import ida_domain
from ida_domain.microcode import MicroInstructionOptimizer


class AssertOptimizer(MicroInstructionOptimizer):
    """Add assertion text as a call argument to DbgRaiseAssertionFailure()."""

    def __init__(self, database):
        super().__init__()
        self.db = database

    def optimize(self, block, insn, optflags):
        if not insn.is_helper('DbgRaiseAssertionFailure'):
            return 0

        fi = insn.dest.call_info
        if fi is None or fi.arg_count > 0:
            return 0

        info = self.db.comments.get_at(insn.ea)
        if info is None:
            return 0

        cmt = info.comment
        if cmt.startswith('NT_ASSERT("'):
            cmt = cmt[11:]
            if cmt.endswith('")'):
                cmt = cmt[:-2]

        fi.add_string_argument(cmt)
        return 1


class vds10_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = 'Optimize DbgRaiseAssertionFailure (ida-domain)'
    wanted_hotkey = ''
    comment = 'Sample plugin10 for Hex-Rays decompiler'
    help = ''

    def init(self):
        self.optimizer = None
        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP
        db = ida_domain.Database.open()
        self.optimizer = AssertOptimizer(db)
        self.optimizer.install()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if self.optimizer is not None:
            self.optimizer.uninstall()

    def run(self, arg):
        if self.optimizer is None:
            return
        if arg == 1:
            return self.optimizer.uninstall()
        elif arg == 2:
            return self.optimizer.install()


def PLUGIN_ENTRY():
    return vds10_plugin_t()
