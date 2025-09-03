"""
This is equivalent of list_function_items.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/list_function_items.py
"""

import ida_domain


class logger_t(object):
    class section_t(object):
        def __init__(self, logger, header):
            self.logger = logger
            self.logger.log(header)

        def __enter__(self):
            self.logger.indent += 2
            return self

        def __exit__(self, tp, value, traceback):
            self.logger.indent -= 2
            if value:
                return False

    def __init__(self):
        self.indent = 0

    def log(self, *args):
        print('  ' * self.indent + ''.join(args))

    def log_ea(self, ea, db):
        parts = [f'0x{ea:08x}', ': ']

        # Check if it's code
        if db.heads.is_code(ea):
            insn = db.instructions.get_at(ea)
            if insn:
                mnem = db.instructions.get_mnemonic(insn)
                parts.append(f'instruction ({mnem})')

        # Check if it's data
        if db.heads.is_data(ea):
            parts.append('data')

        # Check if it's tail
        if db.heads.is_tail(ea):
            parts.append('tail')

        # Check if it's unknown
        if db.heads.is_unknown(ea):
            parts.append('unknown')

        self.log(*parts)


def main():
    db = ida_domain.Database.open()

    # Get current ea
    ea = db.current_ea

    # Get function at current position
    func = db.functions.get_at(ea)

    if func is None:
        print(f'No function defined at 0x{ea:x}')
        return

    func_name = db.names.get_at(func.start_ea) or f'sub_{func.start_ea:x}'
    logger = logger_t()
    logger.log(f'Function {func_name} at 0x{ea:x}')

    # Code items (instructions) - using basic blocks
    with logger_t.section_t(logger, 'Code items:'):
        flowchart = db.functions.get_flowchart(func)
        for block in flowchart:
            for ea in db.heads.get_between(block.start_ea, block.end_ea):
                if db.heads.is_code(ea):
                    logger.log_ea(ea, db)

    # Head items (both code and data)
    with logger_t.section_t(logger, "'head' items:"):
        for ea in db.heads.get_between(func.start_ea, func.end_ea):
            logger.log_ea(ea, db)

    # All addresses (not just heads)
    with logger_t.section_t(logger, 'Addresses:'):
        for ea in range(func.start_ea, func.end_ea):
            if db.is_valid_ea(ea):
                logger.log_ea(ea, db)

    # Function chunks
    with logger_t.section_t(logger, 'Function chunks:'):
        chunks = db.functions.get_chunks(func)
        for chunk in chunks:
            chunk_type = 'Main' if chunk.is_main else 'Tail'
            logger.log(f'{chunk_type} chunk: 0x{chunk.start_ea:08x}..0x{chunk.end_ea:08x}')

    # Data items in function
    with logger_t.section_t(logger, 'Data items:'):
        for ea in db.functions.get_data_items(func):
            logger.log_ea(ea, db)


main()
