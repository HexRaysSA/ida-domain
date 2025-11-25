import os
import sys

# Ensure local ida-domain is used
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ida_domain.database import Database, IdaCommandOptions
from ida_domain.instructions import Instructions
from ida_domain.operands import ImmediateOperand, MemoryOperand, RegisterOperand

import ida_ua # isort: skip

def format_immediate(val):
    if val < 0:
        return f'-0x{abs(val):x}'
    return f'0x{val:x}'


def format_memory_operand(op: MemoryOperand) -> str:
    parts = []
    size = op.get_size_token()
    if size:
        parts.append(f'{size} ptr')

    seg = op.get_segment_prefix()

    # Always use complex addressing string for raw reconstruction
    addr = op.get_complex_addressing_string()

    if seg:
        if addr.startswith(seg):
            op_str = f'{" ".join(parts)} {addr}'.strip()
        else:
            op_str = f'{" ".join(parts)} {seg}{addr}'.strip()
    else:
        op_str = f'{" ".join(parts)} {addr}'.strip()
    return op_str


def format_immediate_operand(op: ImmediateOperand) -> str:
    if op.is_address():
        name = op.get_name()
        if name:
            return name
        return format_immediate(op.get_value())
    return format_immediate(op.get_value())


def reconstruct_instruction(db, insn):
    # 1. Prefixes
    prefixes = db.instructions.get_prefixes(insn)
    prefix_str = ' '.join(prefixes) + ' ' if prefixes else ''
    comments = []

    # 2. Mnemonic
    mnem = db.instructions.get_mnemonic(insn)
    if not mnem:
        mnem = '???'

    # 3. Operands
    ops = []
    for op in db.instructions.get_operands(insn):
        if isinstance(op, MemoryOperand):
            ops.append(format_memory_operand(op))
            stack_var = op.get_stack_variable_name()
            if stack_var:
                comments.append(stack_var)
            elif op.get_name():
                comments.append(op.get_name())

        elif isinstance(op, RegisterOperand):
            ops.append(op.get_register_name())
        elif isinstance(op, ImmediateOperand):
            ops.append(format_immediate_operand(op))
            if op.is_address() and op.get_name():
                # Add name as comment if not already used as operand
                pass

    # Add comment for calls if not already present
    if db.instructions.is_call_instruction(insn):
        for op in db.instructions.get_operands(insn):
            if isinstance(op, ImmediateOperand) and op.is_address():
                name = op.get_name()
                if name and name not in ops:
                    comments.append(name)

    op_str = ', '.join(ops)
    if op_str:
        # Check for jump types
        if mnem.startswith('j'):
            if insn.size == 2:
                op_str = f'short {op_str}'
            else:
                # Check for far jump
                for op in db.instructions.get_operands(insn):
                    if op.type == ida_ua.o_far:
                        op_str = f'far {op_str}'
                        break

        # IDA uses tab or multiple spaces after mnemonic.
        if len(mnem) < 8:
            res = f'{prefix_str}{mnem:<8}{op_str}'
        else:
            res = f'{prefix_str}{mnem} {op_str}'
    else:
        res = f'{prefix_str}{mnem}'

    if comments:
        # Deduplicate comments
        unique_comments = []
        for c in comments:
            if c not in unique_comments:
                unique_comments.append(c)
        if unique_comments:
            res += f' ; {", ".join(unique_comments)}'
    return res


def main():
    binary_path = os.path.abspath('tmptest/libidalib.so')
    if not os.path.exists(binary_path):
        print(f'Error: Binary not found at {binary_path}')
        return

    options = IdaCommandOptions(auto_analysis=True, new_database=False)
    print(f'Opening {binary_path}...')
    with Database.open(path=binary_path, args=options, save_on_close=False) as db:
        print('Database opened. Analyzing first 20 instructions of first function...')

        # Get first function
        funcs = list(db.functions.get_all())
        if not funcs:
            print('No functions found.')
            return

        for func in funcs:
            func_name = db.functions.get_name(func)
            func_ea = func.start_ea
            print(f'\nFunction: {func_name} @ 0x{func_ea:x}')
            print(f'{"Address":<12} | {"Our Assembly":<50} | {"IDA Assembly"}')
            print('-' * 120)
            for insn in db.functions.get_instructions(func):
                ida_raw = db.instructions.get_disassembly(insn)
                ida_raw_clean = ' '.join(ida_raw.split())

                our_reconstruction = reconstruct_instruction(db, insn)
                addr_str = f'0x{insn.ea:x}'
                print(f'{addr_str:<12} | {our_reconstruction:<50} | {ida_raw_clean}')
            print('-' * 120)


if __name__ == '__main__':
    main()
