import re

import ida_domain  # isort: skip

from ida_domain.instructions import Instructions


def test_iterables(test_env):
    db = test_env

    segments = db.segments
    functions = db.functions
    entries = db.entries
    heads = db.heads
    instructions = db.instructions
    names = db.names
    strings = db.strings
    types = db.types

    def check_iterations(entity):
        first_count = 0
        second_count = 0
        for _ in entity:
            first_count += 1
        assert first_count > 0
        for _ in entity:
            second_count += 1
        assert second_count == first_count
        if not isinstance(entity, Instructions):
            assert list(entity) == list(entity)

    check_iterations(segments)
    check_iterations(functions)
    check_iterations(entries)
    check_iterations(heads)
    check_iterations(instructions)
    check_iterations(names)
    check_iterations(strings)
    # TODO add a few types to the test idb
    # check_iterations(types)


def test_complex_variable_access(tiny_c_env):
    """Test complex variable access patterns for issue #30.

    This tests that HIWORD/LOWORD-like patterns are correctly identified
    as WRITE access with ASSIGNMENT context.

    The test binary tiny_c.bin contains a function 'complex_assignments'
    with a local variable 'v9' that has three references:
    - HIWORD(v9) = a1;  -> WRITE / ASSIGNMENT
    - LOWORD(v9) = a2;  -> WRITE / ASSIGNMENT
    - use_val(v9);      -> READ / CALL_ARG
    """
    from ida_domain.pseudocode import LocalVariableAccessType, LocalVariableContext

    db = tiny_c_env

    func = db.functions.get_function_by_name('complex_assignments')
    assert func is not None

    v9 = db.functions.get_local_variable_by_name(func, 'v9')
    assert v9 is not None

    refs = db.functions.get_local_variable_references(func, v9)
    assert len(refs) == 3

    assert refs[0].access_type == LocalVariableAccessType.WRITE
    assert refs[0].context == LocalVariableContext.ASSIGNMENT
    assert refs[0].code_line == 'HIWORD(v9) = a1;'

    assert refs[1].access_type == LocalVariableAccessType.WRITE
    assert refs[1].context == LocalVariableContext.ASSIGNMENT
    assert refs[1].code_line == 'LOWORD(v9) = a2;'

    assert refs[2].access_type == LocalVariableAccessType.READ
    assert refs[2].context == LocalVariableContext.CALL_ARG
    # IDA 9.3 emits `use_val(v9);`; 9.4+ may prepend the parameter name as `use_val(a1: v9);`.
    assert re.fullmatch(r'use_val\((?:\w+:\s*)?v9\);', refs[2].code_line)
