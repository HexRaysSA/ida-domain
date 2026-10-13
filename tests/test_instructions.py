import ida_bytes
import ida_lines
import ida_xref
import pytest

import ida_domain  # isort: skip

from ida_domain.base import InvalidEAError, InvalidParameterError


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

    # Test operand index validation
    assert db.instructions.has_operand(instruction, 0) is True
    assert db.instructions.has_operand(instruction, 2) is False
    assert db.instructions.has_operand(instruction, -1) is False
    assert db.instructions.get_operand(instruction, 99) is None

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

    # Test get_next follows execution flow
    assert db.instructions.get_next(0x0).ea == 0x5  # mov: fall-through to the next instruction
    assert db.instructions.get_next(0x18).ea == 0x1D  # call: fall through
    assert db.instructions.get_next(0x262).ea == 0x264  # indirect call: fall through
    assert db.instructions.get_next(0x2DE).ea == 0x2E0  # conditional jmp: fall through
    assert db.instructions.get_next(0x260).ea == 0x272  # unconditional jmp: jump target
    assert db.instructions.get_next(0x269) is None  # indirect jmp, no known target
    assert db.instructions.get_next(0x2A2) is None  # ret: flow ends
    assert db.instructions.get_next(0x322) is None  # last instruction
    assert db.instructions.get_next(0x1) is None  # tail byte
    assert db.instructions.get_next(0x400) is None  # data
    with pytest.raises(InvalidEAError):
        db.instructions.get_next(0xFFFFFFFF)

    # Test get_previous follows execution flow
    assert db.instructions.get_previous(0x5).ea == 0x0  # falls through from the previous
    assert db.instructions.get_previous(0xC4).ea == 0x18  # callee entry: the caller, not 0xC2
    assert db.instructions.get_previous(0x272).ea == 0x260  # jump target: the jump
    assert db.instructions.get_previous(0x2BC).ea == 0x4B  # two callers: the lowest addressed
    assert db.instructions.get_previous(0x2D0).ea == 0x2CB  # backward jmp ignored, falls through
    assert db.instructions.get_previous(0x0) is None  # nothing reaches the first instruction
    assert db.instructions.get_previous(0x1) is None  # tail byte
    assert db.instructions.get_previous(0x400) is None  # data
    with pytest.raises(InvalidEAError):
        db.instructions.get_previous(0xFFFFFFFF)

    # Test that a branch with several targets yields the lowest addressed one,
    # rather than the pre-existing or the most recently added one
    assert ida_xref.add_cref(0x260, 0xC4, ida_xref.fl_JN) is True
    assert list(db.instructions.jump_targets(uncond)) == [0xC4, 0x272]
    assert db.instructions.get_next(0x260).ea == 0xC4
    ida_xref.del_cref(0x260, 0xC4, False)
    assert list(db.instructions.jump_targets(uncond)) == [0x272]

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


def test_get_previous_only_reached_from_higher(tiny_pseudocode_env):
    db = tiny_pseudocode_env

    # A function called only from higher addresses has no flow predecessor
    caller = db.instructions.get_at(0x1A7)
    assert list(db.instructions.call_targets(caller)) == [0x26]
    assert db.instructions.get_previous(0x26) is None


def _switch_in(db, func_name):
    """The only switch IDA found in a function."""
    func = db.functions.get_by_name(func_name)
    assert func is not None
    switches = []
    for insn in db.functions.get_instructions(func):
        switch = db.instructions.get_switch(insn)
        if switch is not None:
            switches.append(switch)
    assert len(switches) == 1
    return switches[0]


def _callee(db, ea):
    """Name of the function the case code at ea calls (tail calls are jumps)."""
    ref = next(db.xrefs.code_refs_from_ea(ea, flow=False), None)
    assert ref is not None, f'no call or jump at 0x{ea:x}'
    return db.names.get_at(ref)


def _calls_by_value(db, switch):
    return {v: _callee(db, case.target) for case in switch.cases for v in case.values}


DENSE_CALLS = {
    10: 'dense_10',
    11: 'dense_11',
    12: 'dense_12_14',
    13: 'dense_default',
    14: 'dense_12_14',
    15: 'dense_15',
    16: 'dense_16',
    17: 'dense_17',
    18: 'dense_default',
    19: 'dense_19',
}


def test_get_switch(tiny_switch_x64_env):
    db = tiny_switch_x64_env

    switch = _switch_in(db, 'dense')
    jump = db.instructions.get_at(switch.ea)
    assert db.instructions.is_indirect_jump_or_call(jump)
    assert db.instructions.get_switch(jump) == switch
    assert switch.element_size == 8
    assert switch.low_case == 10
    assert _callee(db, switch.default_ea) == 'dense_default'
    assert _calls_by_value(db, switch) == DENSE_CALLS
    # Gaps in the cases go to the default block
    assert switch.target_of(13) == switch.target_of(18) == switch.default_ea
    assert [case.values for case in switch.cases] == [
        (10,),
        (11,),
        (12, 14),
        (13, 18),
        (15,),
        (16,),
        (17,),
        (19,),
    ]
    # Values outside the table fall back to the default
    assert switch.target_of(9) == switch.target_of(20) == switch.default_ea
    assert switch.target_of(12) == switch.target_of(14) != switch.default_ea
    assert db.segments.get_name(db.segments.get_at(switch.jump_table_ea)) == '.rodata'
    assert hash(switch) == hash(db.instructions.get_switch(jump))

    # The switch is stored on the indirect jump only
    dense = db.functions.get_by_name('dense')
    assert db.instructions.get_switch(db.instructions.get_at(dense.start_ea)) is None

    switch = _switch_in(db, 'no_default')
    assert switch.default_ea is None
    assert switch.low_case == 0
    assert _calls_by_value(db, switch) == {v: f'no_default_{v}' for v in range(8)}
    assert switch.target_of(8) is None

    switch = _switch_in(db, 'negative')
    assert switch.low_case == -3
    assert _calls_by_value(db, switch) == {
        -3: 'negative_m3',
        -2: 'negative_m2',
        -1: 'negative_m1',
        0: 'negative_0',
        1: 'negative_1',
        2: 'negative_2',
        3: 'negative_3',
    }
    assert _callee(db, switch.target_of(-4)) == 'negative_default'
    # Values are signed: the 32-bit pattern of -1 is not a case
    assert switch.target_of(0xFFFFFFFF) == switch.default_ea


def test_get_switch_thumb(tiny_switch_thumb_env):
    db = tiny_switch_thumb_env

    # TBB: one-byte jump table entries
    switch = _switch_in(db, 'dense')
    assert switch.element_size == 1
    assert switch.low_case == 10
    assert _callee(db, switch.default_ea) == 'dense_default'
    assert _calls_by_value(db, switch) == DENSE_CALLS

    # gcc handles case 0 through the out-of-range branch, so it is IDA's default
    switch = _switch_in(db, 'no_default')
    assert switch.low_case == 1
    assert _calls_by_value(db, switch) == {v: f'no_default_{v}' for v in range(1, 8)}
    assert _callee(db, switch.target_of(0)) == 'no_default_0'

    # IDA doesn't see the subtraction of the lowest case here, so it reports table
    # indices (0..6) instead of -3..3. Only check that the switch is found.
    assert _switch_in(db, 'negative') is not None
