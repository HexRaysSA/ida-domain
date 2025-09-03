"""
This is equivalent of vds13.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/decompiler/vds13.py
NOTE: Partially migrated - Domain API does not expose user selection
"""

import ida_domain

db = ida_domain.Database.open()

# Get function at current position and use it instead of user selection
func = db.functions.get_at(db.current_ea)
if func:
    sea, eea = func.start_ea, func.end_ea
    if db.bytes.is_code_at(sea):
        mcode = db.bytes.get_microcode_between(sea, eea)
        if mcode:
            print(f'Successfully generated microcode between  0x{sea:X} and 0x{eea:X}')
            print(mcode)
        else:
            print(f'Failed to generate microcode between  0x{sea:X} and 0x{eea:X}')
    else:
        print('The selected range must start with an instruction')
else:
    print('Please position the cursor within a function')
