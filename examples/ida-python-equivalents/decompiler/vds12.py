"""
This is equivalent of vds12.py from IDAPython examples — register use-def xrefs.
Original: https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds12.py

Shows a list of direct references (uses and defs) to the register or
stack variable under the cursor.  Uses ida-domain for microcode generation
and intra-block use-def analysis; cross-block chain walking and the chooser
UI use raw IDAPython (ida_hexrays / ida_kernwin).
"""

import ida_hexrays
import ida_kernwin
import ida_pro

import ida_domain
from ida_domain.microcode import (
    AccessType,
    AnalyzeCallsFlags,
    DecompilationFlags,
    MicroBlock,
    MicroInstruction,
    MicroLocationSet,
    MicroMaturity,
)

# -- intra-block xref collection (uses ida-domain) --------------------------

def collect_block_xrefs(out, mlist, block, start_insn, find_uses):
    insn = start_insn
    while insn and mlist:                              # MicroLocationSet.__bool__
        use_set = block.build_use_list(insn, AccessType.MUST)
        def_set = block.build_def_list(insn, AccessType.MUST)
        check = use_set if find_uses else def_set
        if mlist.has_common(check):                     # any overlap?
            if insn.ea not in out:
                out.append(insn.ea)
        mlist -= def_set                               # MicroLocationSet.__isub__ (subtract)
        insn = insn.next if find_uses else insn.prev


# -- cross-block xref collection (raw IDAPython chains) ---------------------

def collect_xrefs(out, ctx, mop, mlist, du, mf, find_uses):
    # Current block — wrap raw ctx objects into ida-domain wrappers
    block = MicroBlock(ctx.blk, mf)
    top = MicroInstruction(ctx.topins, block)
    start = top.next if find_uses else top.prev
    if start:
        collect_block_xrefs(out, mlist.copy(), block, start, find_uses)

    # Other blocks — chain analysis (raw: voff_t, block_chains_t)
    bc = du[block.serial]
    voff = ida_hexrays.voff_t(mop.raw_operand)
    ch = bc.get_chain(voff)
    if not ch:
        return
    for bn in ch:
        b = mf[bn]                                    # MicroBlockArray.__getitem__
        ins = b.head if find_uses else b.tail
        if ins:
            collect_block_xrefs(out, mlist.copy(), b, ins, find_uses)


# -- chooser UI (raw ida_kernwin) -------------------------------------------

class XrefChooser(ida_kernwin.Choose):
    """Chooser dialog showing use/def xrefs."""

    def __init__(self, db, xrefs, title, ndefs, curr_ea, gco):
        super().__init__(
            title,
            [['Type', 3], ['Address', 16], ['Instruction', 60]],
        )
        self.db = db
        self.xrefs = xrefs
        self.ndefs = ndefs
        self.curr_ea = curr_ea
        self.gco = gco
        self.items = [self._make_item(idx) for idx in range(len(xrefs))]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def _make_item(self, idx):
        ea = self.xrefs[idx]
        both_mask = ida_hexrays.GCO_USE | ida_hexrays.GCO_DEF
        both = (self.gco.flags & both_mask) == both_mask
        if ea == self.curr_ea and both:
            type_str = 'use/def'
        elif idx < self.ndefs:
            type_str = 'def'
        else:
            type_str = 'use'
        disasm = self.db.bytes.get_disassembly_at(ea) or ''
        return [type_str, f'{ea:08x}', disasm]


# -- main -------------------------------------------------------------------

if not ida_hexrays.init_hexrays_plugin():
    print('vds12: Hex-rays is not available.')
    raise SystemExit(1)

db = ida_domain.Database.open()
ea = db.current_ea
func = db.functions.get_at(ea)
w = ida_kernwin.warning

if not func:
    w('Please position the cursor within a function')
    raise SystemExit(1)

if not db.bytes.is_code_at(ea):
    w('Please position the cursor on an instruction')
    raise SystemExit(1)

gco = ida_hexrays.gco_info_t()
if not ida_hexrays.get_current_operand(gco):
    w('Could not find a register or stkvar in the current operand')
    raise SystemExit(1)

mf = db.microcode.generate(
    func,
    maturity=MicroMaturity.PREOPTIMIZED,
    flags=DecompilationFlags.WARNINGS | DecompilationFlags.NO_CACHE,
)
ncalls = mf.analyze_calls(AnalyzeCallsFlags.GUESS)
if ncalls < 0:
    print(f'{func.start_ea:08x}: failed to determine '
          f'some calling conventions')

mlist = MicroLocationSet()
if not gco.append_to_list(mlist.raw_mlist, mf.raw_mba):
    w(f'Failed to represent {gco.name} as microcode list')
    raise SystemExit(1)

ctx = ida_hexrays.op_parent_info_t()
mop = mf.find_mop(ctx, ea, gco.is_def(), mlist)
if not mop:
    w('Could not find the operand in the microcode')
    raise SystemExit(1)

xrefs = ida_pro.eavec_t()
ndefs = 0
graph = mf.get_graph()
ud = graph.get_use_def_chains(ida_hexrays.GC_REGS_AND_STKVARS)
du = graph.get_def_use_chains(ida_hexrays.GC_REGS_AND_STKVARS)

if gco.is_use():
    collect_xrefs(xrefs, ctx, mop, mlist, ud, mf, False)
    ndefs = xrefs.size()
    if ea not in xrefs:
        xrefs.append(ea)
if gco.is_def():
    if ea not in xrefs:
        xrefs.append(ea)
        ndefs = len(xrefs)
    collect_xrefs(xrefs, ctx, mop, mlist, du, mf, True)

title = f'xrefs to {gco.name} at {ea:08x}'
xc = XrefChooser(db, xrefs, title, ndefs, ea, gco)
i = xc.Show(True)
if i >= 0:
    ida_kernwin.jumpto(xrefs[i])
