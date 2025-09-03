"""
This is equivalent of list_segment_functions.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/list_segment_functions.py
"""

import ida_domain


def main():
    # Open current database
    db = ida_domain.Database.open()

    # Get current address (use first entry point if no current EA)
    current_ea = db.current_ea
    if not current_ea:
        entries = list(db.entries.get_all())
        if entries:
            current_ea = entries[0].ea
        else:
            current_ea = db.minimum_ea

    # Get segment at current address
    segment = db.segments.get_at(current_ea)
    if not segment:
        print(f'No segment found at address 0x{current_ea:x}')
        return

    print(
        f"Functions in segment '{segment.name}' (0x{segment.start_ea:x} - 0x{segment.end_ea:x}):"
    )

    # Get all functions in the segment
    for func in db.functions.get_all():
        # Check if function is within the segment
        if segment.start_ea <= func.start_ea < segment.end_ea:
            print(f'Function {func.name} at 0x{func.start_ea:x}')

            # Get cross-references to this function
            xrefs = list(db.xrefs.to_ea(func.start_ea))
            code_xrefs = [x for x in xrefs if x.is_code]

            for xref in code_xrefs:
                # Get function name at the source of the xref
                caller_func = db.functions.get_at(xref.from_ea)
                if caller_func:
                    caller_name = caller_func.name
                else:
                    caller_name = f'sub_{xref.from_ea:x}'
                print(f'  called from {caller_name}(0x{xref.from_ea:x})')


main()
