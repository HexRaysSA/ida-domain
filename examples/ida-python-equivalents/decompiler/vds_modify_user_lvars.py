"""
Equivalent of https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds_modify_user_lvars.py
"""

import ida_typeinf

import ida_domain

NAME_PREFIX = 'patched_'
COMMENT_PREFIX = '(patched) '
NEW_TYPES = {}  # { 'var_name' : 'type decl string', ... }


db = ida_domain.Database.open()

func = db.functions.get_at(db.current_ea)
if func is None:
    print('Please position the cursor within a function')
    raise SystemExit(1)

pfunc = db.pseudocode.decompile(func)
lvars = pfunc.local_variables
print(f'modify_lvars: {len(lvars)} local variables')

for idx, lvar in enumerate(lvars):
    print(f"modify_lvars: var #{idx}: name = '{lvar.name}'")
    print(f"modify_lvars: var #{idx}: type = '{lvar.type_info}'")
    print(f"modify_lvars: var #{idx}: cmt  = '{lvar.comment}'")
    print(f"modify_lvars: var #{idx}: size = {lvar.width}")

    new_type_decl = NEW_TYPES.get(lvar.name)
    type_changed = False
    if new_type_decl:
        decl = new_type_decl if new_type_decl.rstrip().endswith(';') else new_type_decl + ';'
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tif, None, decl, 0) is not None:
            lvar.set_type(tif)
            type_changed = True
        else:
            print(f"modify_lvars: could not parse type {new_type_decl!r}, skipping retype")

    lvar.set_user_name(NAME_PREFIX + lvar.name)
    lvar.set_user_comment(COMMENT_PREFIX + (lvar.comment or ''))

    pfunc.save_local_variable_info(
        lvar,
        save_name=True,
        save_type=type_changed,
        save_comment=True,
    )

print('Local variable modifications saved.')
