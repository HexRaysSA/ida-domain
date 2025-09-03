"""
This is equivalent of vds1.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/decompiler/vds1.py
"""

import ida_domain

# Refer to current database by calling open with no arguments
db = ida_domain.Database.open()

# Get current address - using database.current_ea as alternative to get_screen_ea()
current_ea = db.current_ea

# Get function at current position
func = db.functions.get_at(current_ea)
if func is None:
    print('Please position the cursor within a function')
else:
    try:
        # Get pseudocode for the function
        pseudocode = db.functions.get_pseudocode(func)

        if pseudocode:
            print(f'Decompiled function at 0x{func.start_ea:X}:')
            for line in pseudocode:
                print(line)
        else:
            print('Failed to get pseudocode!')

    except RuntimeError as e:
        print(f'Failed to decompile: {e}')
