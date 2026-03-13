"""
This is equivalent of vds13.py from IDAPython examples
Original: https://github.com/HexRaysSA/ida-sdk/blob/main/src/plugins/idapython/examples/decompiler/vds13.py
NOTE: Partially migrated - Domain API does not expose user selection
"""

import ida_domain
from ida_domain.microcode import MicrocodeError

db = ida_domain.Database.open()

# Get function at current position and use it instead of user selection
func = db.functions.get_at(db.current_ea)
if not func:
    print('Please position the cursor within a function')
    raise SystemExit(1)

sea, eea = func.start_ea, func.end_ea
if not db.bytes.is_code_at(sea):
    print('The selected range must start with an instruction')
    raise SystemExit(1)

try:
    mf = db.microcode.generate_for_range(sea, eea)
except MicrocodeError as e:
    print(f'Failed to generate microcode between  0x{sea:X} and 0x{eea:X}: {e}')
    raise SystemExit(1)

print(f'Successfully generated microcode between  0x{sea:X} and 0x{eea:X}')
print(mf)
