import pytest

import ida_domain  # isort: skip
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.bytes import ByteFlags, NoValueError, SearchFlags
from ida_domain.strings import StringType


def test_bytes(test_env):
    db = test_env

    byte_val = db.bytes.get_byte_at(0x3FA)
    assert byte_val == 0x19

    word_val = db.bytes.get_word_at(0x3F0)
    assert word_val == 0xF5C3

    dword_val = db.bytes.get_dword_at(0x3E8)
    assert dword_val == 0x6375646F

    qword_val = db.bytes.get_qword_at(0x3ED)
    assert qword_val == 0x1F4048F5C30A203A

    float_val = db.bytes.get_float_at(0x3F0)
    assert pytest.approx(float_val, rel=3.14) == 0.0

    double_val = db.bytes.get_double_at(0x3F4)
    assert pytest.approx(double_val, rel=6.28) == 0.0

    disasm = db.bytes.get_disassembly_at(0x3D4)
    assert disasm == "db 'Hello, IDA!',0Ah,0"

    get_bytes = db.bytes.get_bytes_at(0x330, 4)
    assert isinstance(get_bytes, bytes) and get_bytes == b'\xef\xcd\xab\x90'

    test_addr = 0x330
    original_byte = db.bytes.get_byte_at(test_addr)
    db.bytes.set_byte_at(test_addr, 0xFF)
    assert db.bytes.get_byte_at(test_addr) == 0xFF
    db.bytes.set_byte_at(test_addr, original_byte)

    original_word = db.bytes.get_word_at(test_addr)
    db.bytes.set_word_at(test_addr, 0x1234)
    assert db.bytes.get_word_at(test_addr) == 0x1234
    db.bytes.set_word_at(test_addr, original_word)

    original_dword = db.bytes.get_dword_at(test_addr)
    db.bytes.set_dword_at(test_addr, 0x12345678)
    assert db.bytes.get_dword_at(test_addr) == 0x12345678
    db.bytes.set_dword_at(test_addr, original_dword)

    original_qword = db.bytes.get_qword_at(test_addr)
    db.bytes.set_qword_at(test_addr, 0x123456789ABCDEF0)
    assert db.bytes.get_qword_at(test_addr) == 0x123456789ABCDEF0
    db.bytes.set_qword_at(test_addr, original_qword)

    original_bytes = db.bytes.get_bytes_at(test_addr, 4)
    test_bytes_data = b'\xaa\xbb\xcc\xdd'
    db.bytes.set_bytes_at(test_addr, test_bytes_data)
    assert db.bytes.get_bytes_at(test_addr, 4) == test_bytes_data
    db.bytes.set_bytes_at(test_addr, original_bytes)

    pattern = b'\x48\x89\xe5'  # Common x64 prologue pattern
    found_addr = db.bytes.find_bytes_between(pattern)
    assert found_addr is not None

    text_addr = db.bytes.find_text_between('Hello')
    assert text_addr is not None

    imm_addr = db.bytes.find_immediate_between(1)
    assert imm_addr is not None

    tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', 'Point')
    assert db.bytes.create_struct_at(0x330, 1, tif.get_tid())
    assert db.bytes.is_struct_at(0x330)

    assert db.bytes.create_zword_at(0x338)
    assert db.bytes.is_zword_at(0x338)

    assert db.bytes.create_byte_at(0x330)
    assert db.bytes.is_byte_at(0x330)

    assert db.bytes.create_word_at(0x332)
    assert db.bytes.is_word_at(0x332)

    assert db.bytes.create_dword_at(0x334)
    assert db.bytes.is_dword_at(0x334)

    assert db.bytes.create_qword_at(0x338)
    assert db.bytes.is_qword_at(0x338)

    assert db.bytes.create_oword_at(0x340)
    assert db.bytes.is_oword_at(0x340)

    assert db.bytes.create_yword_at(0x350)
    assert db.bytes.is_yword_at(0x350)

    assert db.bytes.create_float_at(0x3F0)
    assert db.bytes.is_float_at(0x3F0)

    # Test comment methods
    test_comment_addr = 0x3F0
    test_comment = 'Test comment'
    test_repeatable_comment = 'Test repeatable comment'

    assert db.bytes.create_double_at(0x3F4)
    assert db.bytes.is_double_at(0x3F4)

    assert db.bytes.create_tbyte_at(0x37C)
    assert db.bytes.is_tbyte_at(0x37C)

    assert db.bytes.create_packed_real_at(0x37C)
    assert db.bytes.is_packed_real_at(0x37C)

    assert db.bytes.create_alignment_at(0x3EF, 0, 2)
    assert db.bytes.is_alignment_at(0x3EF)

    data_size = db.bytes.get_data_size_at(0x330)
    assert isinstance(data_size, int) and data_size == 1

    assert isinstance(db.bytes.is_value_initialized_at(0x330), bool)
    assert db.bytes.is_value_initialized_at(0x330)

    assert isinstance(db.bytes.is_code_at(0x67), bool)
    assert db.bytes.is_code_at(0x67) and not db.bytes.is_code_at(0x330)

    assert isinstance(db.bytes.is_data_at(0x400), bool)
    assert db.bytes.is_data_at(0x330) and not db.bytes.is_data_at(0x67)

    assert isinstance(db.bytes.is_unknown_at(0x400), bool)
    assert not db.bytes.is_unknown_at(0x67)

    assert isinstance(db.bytes.is_head_at(0x400), bool)
    assert db.bytes.is_head_at(0x400) and not db.bytes.is_head_at(0x64)

    assert isinstance(db.bytes.is_tail_at(0x401), bool)
    assert not db.bytes.is_tail_at(0x67) and db.bytes.is_tail_at(0x64)

    assert isinstance(db.bytes.is_not_tail_at(0x67), bool)
    assert db.bytes.is_not_tail_at(0x67)
    assert isinstance(db.bytes.is_flowed_at(0x67), bool)
    assert db.bytes.is_flowed_at(0x67)

    assert isinstance(db.bytes.is_manual_insn_at(0x67), bool)
    assert isinstance(db.bytes.is_forced_operand_at(0x67, 0), bool)

    string_val = db.bytes.get_string_at(0x3D4)
    assert isinstance(string_val, str) and string_val == 'Hello, IDA!\n'

    cstring_val = db.bytes.get_cstring_at(0x3D4)
    assert isinstance(cstring_val, str) and cstring_val == 'Hello, IDA!\n'

    orig_bytes = db.bytes.get_original_bytes_at(0x330, 4)
    assert isinstance(orig_bytes, bytes) and orig_bytes == b'\xef\xcd\xab\x90'

    has_name = db.bytes.has_user_name_at(0x330)
    assert isinstance(has_name, bool) and has_name
    name = db.names.get_at(0x330)
    assert name == 'test_data'

    flags = db.bytes.get_flags_at(0x330)
    assert isinstance(flags, int) and flags == 0x5400

    all_flags = db.bytes.get_all_flags_at(0x330)
    assert isinstance(all_flags, int) and all_flags == 0x55EF

    next_head = db.bytes.get_next_head(0x330)
    assert isinstance(next_head, int) and next_head == 0x332

    prev_head = db.bytes.get_previous_head(0x340)
    assert isinstance(prev_head, int) and prev_head == 0x338

    next_addr = db.bytes.get_next_address(0x330)
    assert isinstance(next_addr, int) and next_addr == 0x331

    prev_addr = db.bytes.get_previous_address(0x340)
    assert isinstance(prev_addr, int) and prev_addr == 0x33F

    test_patch_addr = 0x330  # Use test_data address for patching tests
    original_byte = db.bytes.get_byte_at(test_patch_addr)
    original_word = db.bytes.get_word_at(test_patch_addr)
    original_dword = db.bytes.get_dword_at(test_patch_addr)
    original_qword = db.bytes.get_qword_at(test_patch_addr)

    patch_result = db.bytes.patch_byte_at(test_patch_addr, 0xAB)
    assert isinstance(patch_result, bool)
    assert db.bytes.get_byte_at(test_patch_addr) == 0xAB

    orig_byte = db.bytes.get_original_byte_at(test_patch_addr)
    assert isinstance(orig_byte, int) and orig_byte == original_byte

    revert_result = db.bytes.revert_byte_at(test_patch_addr)
    assert isinstance(revert_result, bool) and revert_result
    assert db.bytes.get_byte_at(test_patch_addr) == original_byte

    patch_result = db.bytes.patch_word_at(test_patch_addr, 0xCDEF)
    assert isinstance(patch_result, bool)
    assert db.bytes.get_word_at(test_patch_addr) == 0xCDEF

    orig_word = db.bytes.get_original_word_at(test_patch_addr)
    assert isinstance(orig_word, int) and orig_word == original_word

    patch_result = db.bytes.patch_dword_at(test_patch_addr, 0x12345678)
    assert isinstance(patch_result, bool)
    assert db.bytes.get_dword_at(test_patch_addr) == 0x12345678

    orig_dword = db.bytes.get_original_dword_at(test_patch_addr)
    assert isinstance(orig_dword, int) and orig_dword == original_dword

    patch_result = db.bytes.patch_qword_at(test_patch_addr, 0x123456789ABCDEF0)
    assert isinstance(patch_result, bool)
    assert db.bytes.get_qword_at(test_patch_addr) == 0x123456789ABCDEF0

    orig_qword = db.bytes.get_original_qword_at(test_patch_addr)
    assert isinstance(orig_qword, int) and orig_qword == original_qword

    test_bytes = b'\x90\x90\x90\x90'  # NOP instructions
    db.bytes.patch_bytes_at(test_patch_addr, test_bytes)

    for i, expected_byte in enumerate(test_bytes):
        actual_byte = db.bytes.get_byte_at(test_patch_addr + i)
        assert actual_byte == expected_byte

    orig_bytes = db.bytes.get_original_bytes_at(test_patch_addr, len(test_bytes))
    assert isinstance(orig_bytes, bytes) and orig_bytes == b'\xef\xcd\xab\x90'

    from ida_domain.bytes import ByteFlags

    code_addr = 0x0  # Known code address
    data_addr = 0x338  # Known data address

    has_code_flag = db.bytes.check_flags_at(code_addr, ByteFlags.CODE)
    assert isinstance(has_code_flag, bool) and has_code_flag

    has_data_flag = db.bytes.check_flags_at(data_addr, ByteFlags.DATA)
    assert isinstance(has_data_flag, bool) and has_data_flag

    has_any_code_or_data = db.bytes.has_any_flags_at(code_addr, ByteFlags.CODE | ByteFlags.DATA)
    assert isinstance(has_any_code_or_data, bool) and has_any_code_or_data

    has_any_byte_or_word = db.bytes.has_any_flags_at(data_addr, ByteFlags.BYTE | ByteFlags.WORD)
    assert isinstance(has_any_byte_or_word, bool) and has_any_byte_or_word

    text_addr_with_flags = db.bytes.find_text_between(
        'Hello', flags=SearchFlags.DOWN | SearchFlags.CASE
    )
    assert text_addr_with_flags is not None

    string_addr = 0x3D4
    string_created = db.bytes.create_string_at(string_addr, string_type=StringType.C)
    assert isinstance(string_created, bool) and string_created

    db.bytes.delete_value_at(string_addr)
    assert not db.bytes.is_value_initialized_at(string_addr)

    byte_value = db.bytes.get_byte_at(0x3FA)
    assert byte_value == 0x19

    uninit_byte = db.bytes.get_byte_at(0x400, allow_uninitialized=True)
    assert isinstance(uninit_byte, int)

    assert db.bytes.is_string_literal_at(0x3D4)  # String location
    assert not db.bytes.is_string_literal_at(0x67)  # Code location

    assert db.bytes.get_next_address(db.maximum_ea - 1) is None
    assert db.bytes.get_previous_address(db.minimum_ea) is None

    next_head_limited = db.bytes.get_next_head(0x330, max_ea=0x335)
    assert next_head_limited == 0x332 or next_head_limited is None

    prev_head_limited = db.bytes.get_previous_head(0x340, min_ea=0x335)
    assert prev_head_limited == 0x338 or prev_head_limited is None

    string_result = db.bytes.create_string_at(0x3D4, length=5)
    assert string_result

    db.bytes.patch_bytes_at(0x330, b'\x90\x90')
    assert db.bytes.get_byte_at(0x330) == 0x90

    for addr in range(0x330, 0x338):
        db.bytes.revert_byte_at(addr)

    imm_found = db.bytes.find_immediate_between(0x1234, start_ea=0x0, end_ea=0x400)
    assert imm_found is None or isinstance(imm_found, int)

    text_found_case = db.bytes.find_text_between(
        'hello', start_ea=0x3D0, end_ea=0x3E0, flags=SearchFlags.DOWN
    )
    assert text_found_case == 0x3D4

    assert db.bytes.create_byte_at(0x400, count=2, force=True)
    assert db.bytes.create_word_at(0x404, force=True)

    test_flags = ByteFlags.CODE | ByteFlags.FUNC
    assert db.bytes.check_flags_at(0x67, test_flags) or db.bytes.has_any_flags_at(0x67, test_flags)

    # Test edge cases for string methods
    # max_length=0 should raise InvalidParameterError
    from ida_domain.base import InvalidParameterError

    with pytest.raises(InvalidParameterError):
        db.bytes.get_string_at(0x400, max_length=0)

    # Test cstring with very small max_length
    short_cstring = db.bytes.get_cstring_at(0x3D4, max_length=2)
    assert len(short_cstring) == 2

    from ida_domain.base import InvalidEAError

    with pytest.raises(InvalidEAError):
        db.bytes.get_byte_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_word_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_dword_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_qword_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_float_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_double_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.set_byte_at(0xFFFFFFFF, 0xFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_disassembly_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.get_string_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.is_string_literal_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.delete_value_at(0xFFFFFFFF)

    # Test basic functionality - find prologue pattern
    prologue_pattern = b'\x48\x89\xe5'  # push rbp; mov rbp,rsp
    results = db.bytes.find_binary_sequence(prologue_pattern)
    assert isinstance(results, list)
    assert len(results) > 0
    for addr in results:
        assert isinstance(addr, int)
        assert db.bytes.get_bytes_at(addr, 3) == prologue_pattern

    # Test with address range
    results_range = db.bytes.find_binary_sequence(prologue_pattern, start_ea=0x0, end_ea=0x100)
    assert isinstance(results_range, list)
    assert all(0x0 <= addr < 0x100 for addr in results_range)

    # Test with non-existent pattern
    non_existent = b'\xff\xee\xdd\xcc\xbb\xaa'
    empty_results = db.bytes.find_binary_sequence(non_existent)
    assert isinstance(empty_results, list)
    assert len(empty_results) == 0

    # Test with specific known pattern in data section
    data_pattern = b'\xef\xcd\xab\x90'  # Known pattern at 0x330
    data_results = db.bytes.find_binary_sequence(data_pattern, start_ea=0x300, end_ea=0x400)
    assert len(data_results) >= 1
    assert 0x330 in data_results

    with pytest.raises(InvalidParameterError):
        db.bytes.find_binary_sequence('not bytes')  # Wrong type

    with pytest.raises(InvalidParameterError):
        db.bytes.find_binary_sequence(b'')  # Empty pattern

    with pytest.raises(InvalidEAError):
        db.bytes.find_binary_sequence(b'\x90', start_ea=0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.bytes.find_binary_sequence(b'\x90', end_ea=0xFFFFFFFF)

    from ida_domain.bytes import NoValueError

    # Delete a value to create an uninitialized location
    test_addr_uninit = 0x400
    db.bytes.delete_value_at(test_addr_uninit)
    assert not db.bytes.is_value_initialized_at(test_addr_uninit)

    with pytest.raises(NoValueError):
        db.bytes.get_byte_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(NoValueError):
        db.bytes.get_word_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(NoValueError):
        db.bytes.get_dword_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(NoValueError):
        db.bytes.get_qword_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(NoValueError):
        db.bytes.get_float_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(NoValueError):
        db.bytes.get_double_at(test_addr_uninit, allow_uninitialized=False)

    with pytest.raises(InvalidParameterError):
        db.bytes.create_byte_at(0x400, count=0)

    with pytest.raises(InvalidParameterError):
        db.bytes.create_word_at(0x400, count=-1)

    with pytest.raises(InvalidParameterError):
        db.bytes.create_dword_at(0x400, count=0)

    with pytest.raises(InvalidParameterError):
        db.bytes.find_text_between('', start_ea=0x0)  # Empty text

    with pytest.raises(InvalidParameterError):
        db.bytes.find_text_between(123, start_ea=0x0)  # Wrong type

    with pytest.raises(InvalidParameterError):
        db.bytes.find_immediate_between('not int')  # Wrong type

    with pytest.raises(InvalidParameterError):
        db.bytes.get_bytes_at(0x330, size=0)

    with pytest.raises(InvalidParameterError):
        db.bytes.get_bytes_at(0x330, size=-5)

    with pytest.raises(InvalidParameterError):
        db.bytes.set_byte_at(0x330, -1)  # Negative value

    with pytest.raises(InvalidParameterError):
        db.bytes.set_byte_at(0x330, 256)  # Too large

    with pytest.raises(InvalidParameterError):
        db.bytes.set_word_at(0x330, -1)

    with pytest.raises(InvalidParameterError):
        db.bytes.set_word_at(0x330, 0x10000)  # Too large

    with pytest.raises(InvalidParameterError):
        db.bytes.set_dword_at(0x330, -1)

    with pytest.raises(InvalidParameterError):
        db.bytes.set_dword_at(0x330, 0x100000000)  # Too large

    with pytest.raises(InvalidParameterError):
        db.bytes.set_qword_at(0x330, -1)

    with pytest.raises(InvalidParameterError):
        db.bytes.set_qword_at(0x330, 0x10000000000000000)  # Too large

    with pytest.raises(InvalidParameterError):
        db.bytes.set_bytes_at(0x330, 'not bytes')

    with pytest.raises(InvalidParameterError):
        db.bytes.set_bytes_at(0x330, b'')  # Empty bytes

    with pytest.raises(InvalidParameterError):
        db.bytes.patch_bytes_at(0x330, 'not bytes')

    with pytest.raises(InvalidParameterError):
        db.bytes.patch_bytes_at(0x330, b'')  # Empty bytes

    with pytest.raises(InvalidParameterError):
        db.bytes.find_bytes_between(b'\x90', start_ea=0x100, end_ea=0x50)  # start > end

    with pytest.raises(InvalidParameterError):
        db.bytes.find_text_between('test', start_ea=0x100, end_ea=0x50)

    with pytest.raises(InvalidParameterError):
        db.bytes.find_immediate_between(0x1234, start_ea=0x100, end_ea=0x50)

    with pytest.raises(InvalidParameterError):
        db.bytes.create_struct_at(0x330, 1, -1)  # Negative tid

    with pytest.raises(InvalidParameterError):
        db.bytes.create_struct_at(0x330, 1, 999999)  # Non-existent tid

    with pytest.raises(InvalidParameterError):
        db.bytes.create_alignment_at(0x330, -1, 2)  # Negative length

    with pytest.raises(InvalidParameterError):
        db.bytes.create_alignment_at(0x330, 10, -1)  # Negative alignment

    with pytest.raises(InvalidParameterError):
        db.bytes.get_cstring_at(0x3D4, max_length=0)

    with pytest.raises(InvalidParameterError):
        db.bytes.get_cstring_at(0x3D4, max_length=-10)

    with pytest.raises(InvalidParameterError):
        db.bytes.get_original_bytes_at(0x330, size=0)

    with pytest.raises(InvalidParameterError):
        db.bytes.get_original_bytes_at(0x330, size=-5)

    with pytest.raises(InvalidParameterError):
        db.bytes.is_forced_operand_at(0x67, -1)
