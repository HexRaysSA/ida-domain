import pytest

import ida_domain  # isort: skip
from ida_idaapi import BADADDR

from ida_domain.base import InvalidEAError, InvalidParameterError


def test_function(test_env):
    db = test_env

    assert len(db.functions) == 8
    for idx, func in enumerate(db.functions):
        if idx == 0:
            assert func is not None
            assert func.name == 'test_all_operand_types'
        elif idx == 1:
            assert func is not None
            assert func.name == 'add_numbers'
            assert func.start_ea == 0x2A3

    func = db.functions.get_at(0x2A3)
    assert func is not None
    assert func.start_ea == 0x2A3
    assert db.functions.set_name(func, 'testing_function_rename')
    assert func.name == 'testing_function_rename'
    assert db.functions.set_name(func, 'add_numbers')
    assert func.name == 'add_numbers'

    blocks = db.functions.get_flowchart(func)
    assert blocks.size == 1
    assert blocks[0].start_ea == 0x2A3
    assert blocks[0].end_ea == 0x2AF

    disassembly_lines = db.functions.get_disassembly(func)
    assert len(disassembly_lines) == 6

    pseudocode = db.functions.get_pseudocode(func)
    pseudocode_lines = pseudocode.to_text()
    assert len(pseudocode_lines) == 4

    mf = db.functions.get_microcode(func)
    microcode_lines = mf.to_text()
    assert len(microcode_lines) == 13
    assert microcode_lines[11] == '1.11 mov    cs.2, seg.2             ; 2AE u=cs.2       d=seg.2'

    # Validate expected instructions and their addresses
    expected_instructions = [
        (0x2A3, 'push    rbp'),
        (0x2A4, 'mov     rbp, rsp'),
        (0x2A7, 'mov     rax, rdi'),
        (0x2AA, 'add     rax, rsi'),
        (0x2AD, 'pop     rbp'),
        (0x2AE, 'retn'),
        (BADADDR, ''),
    ]

    instructions = db.functions.get_instructions(func)
    for i, instruction in enumerate(instructions):
        assert expected_instructions[i][0] == instruction.ea
        assert expected_instructions[i][1] == db.instructions.get_disassembly(instruction)

    func = db.functions.get_at(0x2A3)
    assert func is not None

    # Validate function signature
    expected_signature = '__int64 __fastcall(__int64, __int64)'
    assert db.functions.get_signature(func) == expected_signature

    # Remove and re-create function
    assert db.functions.remove(0x2A3)
    assert db.functions.get_at(0x2A3) is None

    assert db.functions.create(0x2A3)
    assert db.functions.get_at(0x2A3) is not None

    func = db.functions.get_at(0x2A3)
    assert func is not None
    assert func.name == 'add_numbers'

    # Test local variables functionality
    lvars = db.functions.get_local_variables(func)
    assert len(lvars) == 3

    # Check first argument
    first_arg = lvars[0]
    assert first_arg.is_argument is True
    assert first_arg.name == 'a1'
    assert first_arg.size == 8
    assert str(first_arg.type) == '__int64'

    # Test get_local_variable_by_name
    var_by_name = db.functions.get_local_variable_by_name(func, 'a1')
    assert var_by_name is not None
    assert var_by_name.name == 'a1'

    # Test local variable references
    func = db.functions.get_at(0x2D0)
    lvars = db.functions.get_local_variables(func)
    assert len(lvars) == 9
    local_var = next(lv for lv in lvars if lv.name == 'a3')
    refs = db.functions.get_local_variable_references(func, local_var)
    assert len(refs) == 1

    from ida_domain.functions import LocalVariableAccessType, LocalVariableContext

    first_ref = refs[0]
    assert first_ref.access_type == LocalVariableAccessType.READ
    assert first_ref.context == LocalVariableContext.ASSIGNMENT
    assert first_ref.line_number == 8
    assert first_ref.code_line == '*((_QWORD *)&v3 + 1) = a3;'

    # Test WRITE access type - verify v5 assignment is correctly classified
    v5_var = db.functions.get_local_variable_by_name(func, 'v5')
    assert v5_var is not None
    v5_refs = db.functions.get_local_variable_references(func, v5_var)

    # v5 = v3; should be detected as WRITE
    write_refs = [ref for ref in v5_refs if ref.access_type == LocalVariableAccessType.WRITE]
    assert len(write_refs) == 1, 'Expected exactly one WRITE reference for v5'
    assert write_refs[0].access_type == LocalVariableAccessType.WRITE
    assert write_refs[0].context == LocalVariableContext.ASSIGNMENT
    assert write_refs[0].code_line == 'v5 = v3;'

    func = db.functions.get_at(0x311)
    assert func is not None
    assert func.name == 'level2_func_a'

    callers = db.functions.get_callers(func)
    assert len(callers) == 1
    assert callers[0].name == 'level1_func'

    callees = db.functions.get_callees(func)
    assert len(callees) == 1
    assert callees[0].name == 'level3_func'

    func = db.functions.get_at(0x2F7)
    assert func.name == 'level1_func'

    callers = db.functions.get_callers(func)
    assert len(callers) == 0

    callees = db.functions.get_callees(func)
    assert len(callees) == 2
    assert callees[0].name == 'level2_func_a'
    assert callees[1].name == 'level2_func_b'

    func = db.functions.get_at(0x307)
    assert func.name == 'level2_func_a'

    callers = db.functions.get_callers(func)
    assert len(callers) == 1
    assert callers[0].name == 'level1_func'

    callees = db.functions.get_callees(func)
    assert len(callees) == 1
    assert callees[0].name == 'level3_func'

    func = db.functions.get_at(0xC4)
    next_func = db.functions.get_next(func.start_ea)
    assert next_func is not None
    assert next_func.name == 'add_numbers'
    assert next_func.start_ea == 0x2A3


    with pytest.raises(InvalidEAError):
        db.functions.get_next(0xFFFFFFFF)

    func = db.functions.get_at(0x2A3)
    chunk = db.functions.get_chunk_at(0x2A3)
    assert chunk is not None
    assert chunk.start_ea == func.start_ea
    assert db.functions.is_entry_chunk(chunk) is True
    assert db.functions.is_tail_chunk(chunk) is False
    assert db.functions.is_chunk_at(0x2A3) is False

    chunks = list(db.functions.get_chunks(func))
    assert len(chunks) >= 1
    assert chunks[0].start_ea == func.start_ea
    assert chunks[0].end_ea == func.end_ea
    assert chunks[0].is_main is True

    func = db.functions.get_at(0x2A3)
    assert func is not None
    flags = db.functions.get_flags(func)
    assert flags is not None
    from ida_domain.functions import FunctionFlags

    assert isinstance(flags, FunctionFlags)
    assert db.functions.is_far(func) is False
    assert db.functions.does_return(func) is True

    func = db.functions.get_at(0x2A3)
    assert func is not None

    tails = db.functions.get_tails(func)
    assert len(tails) == 0

    stack_points = db.functions.get_stack_points(func)
    assert len(stack_points) == 0

    tail_info = db.functions.get_tail_info(func)
    assert tail_info is None

    func = db.functions.get_at(0x2A3)
    assert func is not None

    data_items = list(db.functions.get_data_items(func))
    assert len(data_items) == 0


    with pytest.raises(InvalidEAError):
        db.functions.get_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.functions.create(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.functions.remove(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.functions.get_next(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.functions.get_chunk_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        list(db.functions.get_between(0xFFFFFFFF, 0x1000))

    with pytest.raises(InvalidEAError):
        list(db.functions.get_between(0x1000, 0xFFFFFFFF))

    with pytest.raises(InvalidEAError):
        list(db.functions.get_between(0xFFFFFFFF, 0xEEEEEEEE))

    func = db.functions.get_at(0x2A3)
    with pytest.raises(InvalidParameterError):
        db.functions.set_name(func, '')

    with pytest.raises(InvalidParameterError):
        db.functions.set_name(func, '   ')

    with pytest.raises(InvalidParameterError):
        db.functions.set_name(func, '\t\n')

    # Test function comment methods
    func = db.functions.get_at(0x2A3)
    test_comment = 'Test function comment'
    test_repeatable_comment = 'Test repeatable function comment'

    # Test non-repeatable function comment
    assert db.functions.set_comment(func, test_comment, False)
    retrieved_comment = db.functions.get_comment(func, False)
    assert retrieved_comment == test_comment

    # Test repeatable function comment
    assert db.functions.set_comment(func, test_repeatable_comment, True)
    retrieved_repeatable_comment = db.functions.get_comment(func, True)
    assert retrieved_repeatable_comment == test_repeatable_comment

    # Test getting non-existent comment returns empty string
    func_no_comment = db.functions.get_at(0x311)
    empty_comment = db.functions.get_comment(func_no_comment, False)
    assert empty_comment == ''

    func = db.functions.get_at(0x2BC)
    mf = db.functions.get_microcode(func)
    microcode_lines = mf.to_text()
    assert len(microcode_lines) == 72
    assert microcode_lines[53] == '2.40 jcnd   tt.1, @2                ; 2DE u=tt.1'
    assert microcode_lines[67] == (
        '3.13 call   !sys_write <spec:"unsigned int fd" edi.4,'
        '"const char *buf" rsi.8,"size_t count" rdx.8> => "signed __int64" rax.8 ;'
        ' 2F0 u=rdx.8,edi.4,rsi.8,(ALLMEM) d=rax.8,(cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,'
        'rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,'
        'xmm5.16,ALLMEM)'
    )


def test_get_signature_returns_optional_str(test_env):
    """get_signature returns Optional[str] — None when no type is stored,
    str otherwise. The return must never be an empty string (that was the
    old docstring's claim before the fix)."""
    db = test_env
    for func in db.functions:
        sig = db.functions.get_signature(func)
        assert sig is None or isinstance(sig, str)
        assert sig != ''
