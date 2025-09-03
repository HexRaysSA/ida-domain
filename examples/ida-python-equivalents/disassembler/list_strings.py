"""
This is equivalent of list_strings.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/list_strings.py
"""

import ida_domain

# Reference current database
db = ida_domain.Database.open()

# Iterate over all strings, filtering for C and C_16 types
index = 0
for ea, str in db.strings.get_all():
    # Filter for C and C_16 string types (equivalent to the original filter)
    str_type = db.strings.get_type(ea)
    if str_type in [ida_domain.strings.StringType.C, ida_domain.strings.StringType.C_16]:
        print(f"{ea:x}: len={len(str)} type={str_type.name} index={index}-> '{str}'")
        index += 1
