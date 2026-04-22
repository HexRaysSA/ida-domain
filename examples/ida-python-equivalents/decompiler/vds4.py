"""
Equivalent of https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds4.py
"""

import ida_bytes

import ida_domain
from ida_domain.pseudocode import NumberFormatFlags

db = ida_domain.Database.open()

func = db.functions.get_at(db.current_ea)
if func is None:
    print('Please position the cursor within a function')
    raise SystemExit(1)

entry_ea = func.start_ea
print(f'Dump of user-defined information for function at 0x{entry_ea:X}')

# We still need a PseudocodeFunction to access the restore_user_* helpers,
# but we do not need to walk its body — the context managers pull data
# straight from the IDB.
pfunc = db.pseudocode.decompile(func)

# -- user-defined labels ---------------------------------------------------
with pfunc.user_labels() as labels:
    if labels is not None:
        print(f'------- {len(labels)} user defined labels')
        for org_label, name in labels.items():
            print(f'Label {org_label}: {name}')

# -- user-defined indented comments ----------------------------------------
with pfunc.user_comments() as cmts:
    if cmts is not None:
        print(f'------- {len(cmts)} user defined comments')
        for tl, cmt in cmts.items():
            print(f'Comment at 0x{tl.ea:X}, preciser {tl.itp:x}:\n{cmt}\n')

# -- user-defined citem iflags ---------------------------------------------
with pfunc.user_iflags() as iflags:
    if iflags is not None:
        import ida_hexrays
        print(f'------- {len(iflags)} user defined citem iflags')
        for cl, f in iflags.items():
            collapsed = ' CIT_COLLAPSED' if (f & ida_hexrays.CIT_COLLAPSED) else ''
            print(f'0x{cl.ea:X}({cl.op}): {f:08X}{collapsed}')

# -- user-defined number formats -------------------------------------------
with pfunc.user_numforms() as numforms:
    if numforms is not None:
        print(f'------- {len(numforms)} user defined number formats')
        for ol, nf in numforms.items():
            negated = 'negated ' if (ord(nf.props) & NumberFormatFlags.NEGATE) else ''
            print(f'Number format at 0x{ol.ea:X}, operand {ol.opnum}: {negated}', end='')
            if nf.is_enum():
                print(f'enum {nf.type_name} (serial {nf.serial})')
            elif nf.is_char():
                print('char')
            elif nf.is_stroff():
                print(f'struct offset {nf.type_name}')
            else:
                print(f'number base={ida_bytes.get_radix(nf.flags, ol.opnum)}')

# -- user-defined local variable info --------------------------------------
with pfunc.user_lvar_settings() as lvinf:
    if lvinf is not None:
        print('------- User defined local variable information')
        for lv in lvinf.lvvec:
            print(f'Lvar defined at 0x{lv.ll.defea:X}')
            if str(lv.name):
                print(f'  Name: {lv.name}')
            if str(lv.type):
                print(f'  Type: {lv.type}')
            if str(lv.cmt):
                print(f'  Comment: {lv.cmt}')
