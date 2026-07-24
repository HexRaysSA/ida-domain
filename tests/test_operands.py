import ida_bytes
import ida_typeinf
import pytest

import ida_domain  # isort: skip
import ida_domain.operands
from ida_domain.base import InvalidParameterError
from ida_domain.operands import OperandFormat


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


def test_operand_display(test_env):
    db = test_env
    insn = db.instructions.get_at(0xBA)
    op = db.instructions.get_operand(insn, 1)
    assert db.instructions.get_disassembly(insn) == "mov     eax, 3Ch ; '<'"

    # Test number representations
    assert op.display_hex() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 3Ch'
    assert op.display_decimal() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 60'
    assert op.display_octal() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 74o'
    assert op.display_binary() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 111100b'
    assert op.display_char() is True
    assert db.instructions.get_disassembly(insn) == "mov     eax, '<'"
    assert op.display_float() is True
    assert 'floating' in db.instructions.get_disassembly(insn)

    # Test the generic format setter
    assert op.display_as(OperandFormat.NUMBER) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 3Ch'
    assert op.display_as(OperandFormat.OFFSET, 0) is True
    assert 'offset' in db.instructions.get_disassembly(insn)
    with pytest.raises(InvalidParameterError):
        op.display_as('bogus')

    # Test the offset setter
    assert op.display_offset(0) is True
    assert 'offset' in db.instructions.get_disassembly(insn)

    # Test sign and negate toggles
    op.display_decimal()
    assert op.toggle_sign() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, -4294967236'
    op.clear_representation()
    op.display_hex()
    assert op.toggle_negate() is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, not 0FFFFFFC3h'

    # Test clear reverts to the default rendering
    assert op.clear_representation() is True
    assert db.instructions.get_disassembly(insn) == "mov     eax, 3Ch ; '<'"

    # Test forced operand override
    assert op.get_forced_text() is None
    assert op.set_forced_text('MYNAME') is True
    assert op.get_forced_text() == 'MYNAME'
    assert db.instructions.get_disassembly(insn) == 'mov     eax, MYNAME'
    assert op.set_forced_text('') is True
    assert op.get_forced_text() is None

    # Test struct offset with a nested type path
    ida_typeinf.parse_decls(
        ida_typeinf.get_idati(),
        'struct InnerStruct { int inner_field1; int inner_field2; };'
        ' struct OuterStruct { int leading_field; struct InnerStruct nested; };',
        None,
        ida_typeinf.HTI_DCL,
    )
    outer = ida_typeinf.get_named_type_tid('OuterStruct')
    inner = ida_typeinf.get_named_type_tid('InnerStruct')
    assert op.display_struct_offset([outer, inner], 0) is True
    assert 'OuterStruct.' in db.instructions.get_disassembly(insn)
    assert op.struct_offset_path() == ([outer, inner], 0)
    assert op.struct_offset_path_names() == ['OuterStruct', 'InnerStruct']
    # A register operand has no struct-offset path
    reg = db.instructions.get_operand(insn, 0)
    assert reg.struct_offset_path() is None
    assert reg.struct_offset_path_names() == []

    # Test based struct offset
    base = db.maximum_ea - 8
    ida_bytes.del_items(base, ida_bytes.DELIT_SIMPLE, 8)
    assert ida_bytes.create_struct(base, 8, inner) is True
    op.clear_representation()
    assert op.display_based_struct_offset(0, base) is True
    assert 'InnerStruct.' in db.instructions.get_disassembly(insn)
    assert op.struct_offset_path() == ([inner], 0)
    op.clear_representation()
    assert op.display_based_struct_offset(0, 0x0) is False

    # Test stack-variable link
    sv_insn = db.instructions.get_at(0x135)
    sv = db.instructions.get_operand(sv_insn, 1)
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is True
    assert db.instructions.get_disassembly(sv_insn) == 'mov     rax, [rsp+28h+var_18]'
    assert sv.clear_representation() is True
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is False
    assert db.instructions.get_disassembly(sv_insn) == 'mov     rax, [rsp+10h]'
    assert sv.display_stack_var() is True
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is True
    assert db.instructions.get_disassembly(sv_insn) == 'mov     rax, [rsp+28h+var_18]'
