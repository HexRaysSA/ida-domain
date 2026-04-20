import ida_domain  # isort: skip
import ida_domain.operands


def test_operands(test_env):
    db = test_env

    # Test basic register operand - mov rax, rdi at 0x2A7
    instruction = db.instructions.get_at(0x2A7)
    operands = db.instructions.get_operands(instruction)

    # First operand should be rax (destination register)
    reg_op = operands[0]
    assert isinstance(reg_op, ida_domain.operands.RegisterOperand)
    assert reg_op.get_register_name() == 'rax'
    assert reg_op.register_number == 0  # rax register number
    assert reg_op.get_access_type() == ida_domain.operands.AccessType.WRITE
    assert reg_op.is_write() and not reg_op.is_read()

    # Test base operand info
    base_info = reg_op.get_info()
    assert base_info.number == 0
    assert base_info.access_type == ida_domain.operands.AccessType.WRITE

    # Second operand should be rdi (source register)
    reg_op2 = operands[1]
    assert isinstance(reg_op2, ida_domain.operands.RegisterOperand)
    assert reg_op2.get_register_name() == 'rdi'
    assert reg_op2.get_access_type() == ida_domain.operands.AccessType.READ

    # Test immediate value - mov edi, 1 at 0x5
    instruction = db.instructions.get_at(0x5)
    operands = db.instructions.get_operands(instruction)

    imm_op = operands[1]  # Second operand should be immediate 1
    assert isinstance(imm_op, ida_domain.operands.ImmediateOperand)
    assert imm_op.get_value() == 1
    assert not imm_op.is_address()
    assert imm_op.get_name() is None  # Not an address

    # Test larger immediate value - mov rax, 1234567890ABCDEFh at 0xE2
    instruction = db.instructions.get_at(0xE2)
    operands = db.instructions.get_operands(instruction)

    large_imm_op = operands[1]
    assert isinstance(large_imm_op, ida_domain.operands.ImmediateOperand)
    large_value = large_imm_op.get_value()
    assert large_value == 0x1234567890ABCDEF

    # Test Near Address Operands (calls/jumps)
    # Find a call instruction - call add_numbers at 0x27
    instruction = db.instructions.get_at(0x27)
    operands = db.instructions.get_operands(instruction)

    addr_op = operands[0]
    assert isinstance(addr_op, ida_domain.operands.ImmediateOperand)
    assert addr_op.is_address()
    symbol_name = addr_op.get_name()
    assert symbol_name == 'add_numbers'  # Should resolve to function name

    # Test direct memory access - mov rax, test_data at 0xFF
    instruction = db.instructions.get_at(0xFF)
    operands = db.instructions.get_operands(instruction)

    mem_op = operands[1]
    assert isinstance(mem_op, ida_domain.operands.MemoryOperand)
    assert mem_op.is_direct_memory()
    assert not mem_op.is_register_based()

    # Test memory address and symbol
    addr = mem_op.get_address()
    assert addr is not None
    symbol = mem_op.get_name()
    assert symbol == 'test_data'

    # Test register indirect - mov rax, [rbx] at 0x125
    instruction = db.instructions.get_at(0x125)
    operands = db.instructions.get_operands(instruction)

    phrase_op = operands[1]
    assert isinstance(phrase_op, ida_domain.operands.MemoryOperand)
    assert phrase_op.is_register_based()
    assert not phrase_op.is_direct_memory()

    # Test phrase number
    phrase_num = phrase_op.get_phrase_number()
    assert phrase_num is not None

    # Test formatted string
    formatted = phrase_op.get_formatted_string()
    assert '[rbx]' in formatted

    # Test register+displacement - mov rax, [rbp+8] at 0x12D
    instruction = db.instructions.get_at(0x12D)
    operands = db.instructions.get_operands(instruction)

    disp_op = operands[1]
    assert isinstance(disp_op, ida_domain.operands.MemoryOperand)
    assert disp_op.is_register_based()

    # Test displacement value
    displacement = disp_op.get_displacement()
    assert displacement is not None
    assert displacement == 8  # [rbp+8]

    # Test outer displacement (should be None for simple displacement)
    outer_disp = disp_op.get_outer_displacement()
    assert outer_disp is None

    # Test has_outer_displacement flag
    assert not disp_op.has_outer_displacement()

    formatted = disp_op.get_formatted_string()
    assert '[rbp+' in formatted and '8' in formatted

    # Test complex displacement - mov rax, [rsi+rdi*2+8] at 0x162
    instruction = db.instructions.get_at(0x162)
    operands = db.instructions.get_operands(instruction)

    complex_disp_op = operands[1]
    assert isinstance(complex_disp_op, ida_domain.operands.MemoryOperand)

    formatted = complex_disp_op.get_formatted_string()
    assert 'rsi' in formatted and 'rdi' in formatted and '*2' in formatted

    # Test Operand Value Method Consistency
    # Register operand value should be register number
    reg_val = reg_op.get_value()
    assert isinstance(reg_val, int)

    # Memory operand values vary by type
    mem_val = complex_disp_op.get_value()
    assert isinstance(mem_val, dict)  # Displacement operands return dict
    assert 'phrase' in mem_val and 'displacement' in mem_val

    # All operands should have meaningful string representations
    reg_str = str(reg_op)
    assert 'Register' in reg_str
    assert 'Op0' in reg_str  # Operand number

    mem_str = str(mem_op)
    assert 'Memory' in mem_str
