import ida_bytes
import ida_lines
import ida_typeinf
import pytest

import ida_domain  # isort: skip

from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.operands import OperandFormat


def test_instruction(test_env):
    db = test_env

    count = 0
    for _ in db.instructions:
        count += 1
    assert count == 197

    instructions = list(db.instructions.get_all())
    assert len(instructions) == 197

    instruction = db.instructions.get_at(0xD6)
    assert instruction is not None
    assert db.instructions.is_valid(instruction)
    assert db.instructions.get_disassembly(instruction) == 'mov     ax, bx'
    assert db.instructions.get_operands_count(instruction) == 2

    operands = db.instructions.get_operands(instruction)
    assert len(operands) == 2
    assert isinstance(operands[0], ida_domain.operands.RegisterOperand)
    assert isinstance(operands[1], ida_domain.operands.RegisterOperand)

    assert isinstance(
        db.instructions.get_operand(instruction, 0), ida_domain.operands.RegisterOperand
    )
    assert isinstance(
        db.instructions.get_operand(instruction, 1), ida_domain.operands.RegisterOperand
    )

    operands = db.instructions.get_operands(instruction)
    assert len(operands) == 2
    assert isinstance(operands[0], ida_domain.operands.RegisterOperand)
    assert isinstance(operands[1], ida_domain.operands.RegisterOperand)

    instruction = db.instructions.get_previous(0xD6)
    assert instruction is not None
    assert instruction.ea == 0xD4
    assert db.instructions.is_valid(instruction)
    assert db.instructions.get_disassembly(instruction) == 'mov     eax, ebx'
    assert db.instructions.get_operands_count(instruction) == 2

    operands = db.instructions.get_operands(instruction)
    assert len(operands) == 2
    assert isinstance(operands[0], ida_domain.operands.RegisterOperand)
    assert isinstance(operands[1], ida_domain.operands.RegisterOperand)

    instructions = list(db.instructions.get_between(0xD0, 0xE0))
    assert len(instructions) == 7

    instruction = db.instructions.get_at(0xD6)
    assert instruction is not None
    mnemonic = db.instructions.get_mnemonic(instruction)
    assert mnemonic == 'mov'

    # Test get_operand with valid index
    operand0 = db.instructions.get_operand(instruction, 0)
    assert operand0 is not None
    assert isinstance(operand0, ida_domain.operands.RegisterOperand)

    operand1 = db.instructions.get_operand(instruction, 1)
    assert operand1 is not None
    assert isinstance(operand1, ida_domain.operands.RegisterOperand)

    # Find a call instruction at 0x262
    call_insn = db.instructions.get_at(0x262)
    assert call_insn is not None
    assert db.instructions.is_call_instruction(call_insn) is True
    assert db.instructions.is_indirect_jump_or_call(call_insn) is True
    assert db.instructions.breaks_sequential_flow(call_insn) is False

    # Find a jump instruction at 0x269
    jmp_insn = db.instructions.get_at(0x269)
    assert jmp_insn is not None
    assert db.instructions.is_call_instruction(jmp_insn) is False
    assert db.instructions.is_indirect_jump_or_call(jmp_insn) is True
    assert db.instructions.breaks_sequential_flow(jmp_insn) is True

    with pytest.raises(InvalidEAError):
        list(db.instructions.get_between(0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        list(db.instructions.get_between(0x200, 0x100))

    with pytest.raises(InvalidEAError):
        db.instructions.get_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.instructions.get_previous(0xFFFFFFFF)

    # Test tagged disassembly text
    insn = db.instructions.get_at(0xBA)
    tagged = db.instructions.text(insn)
    assert tagged == db.instructions.get_disassembly(insn, remove_tags=False)
    assert '\x01' in tagged
    assert ida_lines.tag_remove(tagged) == db.instructions.get_disassembly(insn)

    # Test control-flow predicates
    ret = db.instructions.get_at(0x2A2)
    assert db.instructions.is_return(ret) is True
    assert db.instructions.is_jump(ret) is False
    assert db.instructions.has_fall_through(ret) is False

    cond = db.instructions.get_at(0x2DE)
    assert db.instructions.is_jump(cond) is True
    assert db.instructions.is_conditional_jump(cond) is True
    assert db.instructions.has_fall_through(cond) is True

    uncond = db.instructions.get_at(0x260)
    assert db.instructions.is_jump(uncond) is True
    assert db.instructions.is_conditional_jump(uncond) is False
    assert db.instructions.has_fall_through(uncond) is False

    indirect = db.instructions.get_at(0x269)
    assert db.instructions.is_jump(indirect) is True
    assert db.instructions.is_conditional_jump(indirect) is False

    call = db.instructions.get_at(0x18)
    assert db.instructions.is_return(call) is False
    assert db.instructions.is_jump(call) is False
    assert db.instructions.has_fall_through(call) is True

    mov = db.instructions.get_at(0x0)
    assert db.instructions.is_return(mov) is False
    assert db.instructions.is_jump(mov) is False
    assert db.instructions.is_conditional_jump(mov) is False
    assert db.instructions.has_fall_through(mov) is True

    # Test call and jump targets
    assert list(db.instructions.call_targets(call)) == [0xC4]
    assert list(db.instructions.jump_targets(uncond)) == [0x272]
    assert list(db.instructions.jump_targets(cond)) == [0x2D0]
    assert list(db.instructions.call_targets(mov)) == []
    assert list(db.instructions.jump_targets(mov)) == []

    # Test next
    following = db.instructions.next(0x0)
    assert following is not None
    assert following.ea == 0x5
    assert db.instructions.next(0x322) is None
    with pytest.raises(InvalidEAError):
        db.instructions.next(0xFFFFFFFF)

    # Test create
    size = db.instructions.get_at(0x0).size
    assert size == 5
    ida_bytes.del_items(0x0, ida_bytes.DELIT_SIMPLE, size)
    assert ida_bytes.is_code(ida_bytes.get_flags(0x0)) is False
    assert db.instructions.create(0x0) == size
    assert ida_bytes.is_code(ida_bytes.get_flags(0x0)) is True
    assert db.instructions.get_disassembly(db.instructions.get_at(0x0)) == 'mov     eax, 1'
    with pytest.raises(InvalidEAError):
        db.instructions.create(0xFFFFFFFF)


def test_instruction_operand(test_env):
    db = test_env
    insn = db.instructions.get_at(0xBA)
    default = db.instructions.get_disassembly(insn)
    assert default == "mov     eax, 3Ch ; '<'"

    # Test operand index validation
    assert db.instructions.is_valid_operand(insn, 0) is True
    assert db.instructions.is_valid_operand(insn, 1) is True
    assert db.instructions.is_valid_operand(insn, 2) is False
    assert db.instructions.is_valid_operand(insn, -1) is False
    assert db.instructions.is_valid_operand(insn, 99) is False
    # An invalid index is a no-op, not an error
    assert db.instructions.set_operand_hex(insn, 99) is False
    assert db.instructions.set_operand_hex(insn, -1) is False
    assert db.instructions.get_operand(insn, 99) is None
    assert db.instructions.get_forced_operand(insn, 99) is None
    assert db.instructions.operand_struct_offset_path(insn, 99) is None
    assert db.instructions.operand_struct_offset_path_names(insn, 99) == []

    # Test number representations
    assert db.instructions.set_operand_hex(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 3Ch'
    assert db.instructions.set_operand_decimal(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 60'
    assert db.instructions.set_operand_octal(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 74o'
    assert db.instructions.set_operand_binary(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 111100b'
    assert db.instructions.set_operand_char(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == "mov     eax, '<'"
    assert db.instructions.set_operand_float(insn, 1) is True
    assert 'floating' in db.instructions.get_disassembly(insn)

    # Test the generic format setter
    assert db.instructions.set_operand_format(insn, 1, OperandFormat.NUMBER) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 3Ch'
    assert db.instructions.set_operand_format(insn, 1, OperandFormat.DECIMAL) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, 60'
    assert db.instructions.set_operand_format(insn, 1, OperandFormat.FLOAT) is True
    assert 'floating' in db.instructions.get_disassembly(insn)
    assert db.instructions.set_operand_format(insn, 1, OperandFormat.OFFSET, 0) is True
    assert 'offset' in db.instructions.get_disassembly(insn)
    with pytest.raises(InvalidParameterError):
        db.instructions.set_operand_format(insn, 1, 'bogus')

    # Test the offset setter
    assert db.instructions.set_operand_offset(insn, 1, 0) is True
    assert 'offset' in db.instructions.get_disassembly(insn)

    # Test sign and negate toggles
    db.instructions.set_operand_decimal(insn, 1)
    assert db.instructions.toggle_operand_sign(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, -4294967236'
    db.instructions.clear_operand_representation(insn, 1)
    db.instructions.set_operand_hex(insn, 1)
    assert db.instructions.toggle_operand_negate(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == 'mov     eax, not 0FFFFFFC3h'

    # Test clear reverts to the default rendering
    assert db.instructions.clear_operand_representation(insn, 1) is True
    assert db.instructions.get_disassembly(insn) == default

    # Test forced operand override
    assert db.instructions.get_forced_operand(insn, 1) is None
    assert db.instructions.set_forced_operand(insn, 1, 'MYNAME') is True
    assert db.instructions.get_forced_operand(insn, 1) == 'MYNAME'
    assert db.instructions.get_disassembly(insn) == 'mov     eax, MYNAME'
    assert db.instructions.set_forced_operand(insn, 1, '') is True
    assert db.instructions.get_forced_operand(insn, 1) is None

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
    assert db.instructions.set_operand_struct_offset(insn, 1, [outer, inner], 0) is True
    assert 'OuterStruct.' in db.instructions.get_disassembly(insn)
    assert db.instructions.operand_struct_offset_path(insn, 1) == ([outer, inner], 0)
    assert db.instructions.operand_struct_offset_path_names(insn, 1) == [
        'OuterStruct',
        'InnerStruct',
    ]
    # A register operand has no struct-offset path
    assert db.instructions.operand_struct_offset_path(insn, 0) is None
    assert db.instructions.operand_struct_offset_path_names(insn, 0) == []

    # Test based struct offset
    base = db.maximum_ea - 8
    ida_bytes.del_items(base, ida_bytes.DELIT_SIMPLE, 8)
    assert ida_bytes.create_struct(base, 8, inner) is True
    db.instructions.clear_operand_representation(insn, 1)
    assert db.instructions.set_operand_based_struct_offset(insn, 1, 0, base) is True
    assert 'InnerStruct.' in db.instructions.get_disassembly(insn)
    assert db.instructions.operand_struct_offset_path(insn, 1) == ([inner], 0)
    db.instructions.clear_operand_representation(insn, 1)
    assert db.instructions.set_operand_based_struct_offset(insn, 1, 0, 0x0) is False

    # Test stack-variable link
    sv = db.instructions.get_at(0x135)
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is True
    assert db.instructions.get_disassembly(sv) == 'mov     rax, [rsp+28h+var_18]'
    assert db.instructions.clear_operand_representation(sv, 1) is True
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is False
    assert db.instructions.get_disassembly(sv) == 'mov     rax, [rsp+10h]'
    assert db.instructions.set_operand_stack_var(sv, 1) is True
    assert ida_bytes.is_stkvar(ida_bytes.get_flags(0x135), 1) is True
    assert db.instructions.get_disassembly(sv) == 'mov     rax, [rsp+28h+var_18]'
