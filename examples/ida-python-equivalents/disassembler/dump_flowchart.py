"""
This is equivalent of dump_flowchart.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/dump_flowchart.py
"""

import ida_domain


def out(p, msg):
    if p:
        print(msg)


def out_succ(p, start_ea, end_ea):
    out(p, '  SUCC:  %x - %x' % (start_ea, end_ea))


def out_pred(p, start_ea, end_ea):
    out(p, '  PRED:  %x - %x' % (start_ea, end_ea))


def dump_flowchart(ea, p=True):
    """
    Dump function flowchart using IDA Domain API.

    Args:
        ea: Address within the function
        p: Print output (default True)
    """
    db = ida_domain.Database.open()

    # Get function at the given address
    func = db.functions.get_at(ea)
    if not func:
        print(f'No function found at address 0x{ea:x}')
        return

    # Create flowchart for the function
    flowchart = db.functions.get_flowchart(func)

    # Iterate through all basic blocks
    for block in flowchart:
        out(p, '%x - %x [%d]:' % (block.start_ea, block.end_ea, block.id))

        # Show successors
        for succ_block in block.get_successors():
            out_succ(p, succ_block.start_ea, succ_block.end_ea)

        # Show predecessors
        for pred_block in block.get_predecessors():
            out_pred(p, pred_block.start_ea, pred_block.end_ea)


# Dump flowchart at current EA."""
db = ida_domain.Database.open()
print(f'>>> Dumping flow chart for function at 0x{db.current_ea:x}')
dump_flowchart(db.current_ea)
