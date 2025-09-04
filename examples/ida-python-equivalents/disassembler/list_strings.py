"""
This is equivalent of list_strings.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/list_strings.py
"""

import ida_domain

# Reference current database
db = ida_domain.Database.open()

# Iterate over all strings, filtering for C and C_16 types
index = 0
for item in db.strings:
    # Filter for C and C_16 string types (equivalent to the original filter)
    str_type = item.type
    ea = item.address
    if str_type in [ida_domain.strings.StringType.C, ida_domain.strings.StringType.C_16]:
        print(f"{ea:x}: len={item.length} type={str_type.name} index={index}-> '{str(item)}'")
        index += 1
