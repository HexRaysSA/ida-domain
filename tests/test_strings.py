import ida_nalt
import pytest

import ida_domain  # isort: skip
from conftest import min_ida_version

from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.strings import StringType


def test_strings(test_env):
    db = test_env

    assert len(db.strings) == 3

    expected_strings = [
        (0x3A0, 'Source string data'),
        (0x3D4, 'Hello, IDA!\n'),
        (0x3E1, 'Sum: Product: \n'),
    ]

    for i, (expected_addr, expected_string) in enumerate(expected_strings):
        string_item = db.strings[i]
        assert string_item.address == expected_addr
        assert str(string_item) == expected_string

    for i, item in enumerate(db.strings):
        assert item.address == expected_strings[i][0], (
            f'String address mismatch at index {i}, '
            f'{hex(item.address)} != {hex(expected_strings[i][0])}'
        )
        assert str(item) == expected_strings[i][1], (
            f'String mismatch at index {i}, {str(item)} != {expected_strings[i][1]}'
        )


    string_info = db.strings.get_at(0x3D4)
    assert string_info is not None
    assert string_info.address == 0x3D4
    assert string_info.contents == b'Hello, IDA!\n'
    assert str(string_info) == 'Hello, IDA!\n'
    assert string_info.length == 13
    assert string_info.type == StringType.C

    string_info = db.strings.get_at(0x3E1)
    assert string_info is not None
    assert string_info.contents == b'Sum: Product: \n'
    assert str(string_info) == 'Sum: Product: \n'

    length = db.strings.get_at(0x3D4).length
    assert isinstance(length, int) and length == 13

    str_type = db.strings.get_at(0x3D4).type
    assert isinstance(str_type, int)
    assert str_type == StringType.C

    assert db.strings.get_at(0x3D4)
    assert db.strings.get_at(0x3E1)
    assert not db.strings.get_at(0x3DA)

    strings_in_range = list(db.strings.get_between(0x3D0, 0x3F0))
    assert len(strings_in_range) >= 2  # Should include strings at 0x3D4 and 0x3E1

    found_addrs = [item.address for item in strings_in_range]
    assert 0x3D4 in found_addrs
    assert 0x3E1 in found_addrs

    original_count = len(db.strings)
    db.strings.rebuild()
    assert len(db.strings) == original_count  # Should be same count

    string_info = db.strings.get_at(0x3D4)
    assert string_info.type == StringType.C
    assert string_info.contents == b'Hello, IDA!\n'
    assert str(string_info) == 'Hello, IDA!\n'

    with pytest.raises(InvalidEAError):
        db.strings.get_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        list(db.strings.get_between(0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        list(db.strings.get_between(0x200, 0x100))

    non_string_info = db.strings.get_at(0x100)
    assert non_string_info is None

    assert db.strings.get_at(0x3A0)
    assert not db.strings.get_at(0x100)

    with pytest.raises(IndexError):
        db.strings[100]

    with pytest.raises(IndexError):
        db.strings.get_at_index(-1)

    for addr in [0x3A0, 0x3D4, 0x3E1]:
        info = db.strings.get_at(addr)
        assert info is not None
        assert info.address == addr
        assert len(info.contents) > 0
        assert info.length > 0
        assert isinstance(info.type, StringType)
        assert info.type == StringType.C

    # Modify string in place with some latin-1 encoded chars

    string_encoding = 'iso-8859-1'
    string_addr = 0x3A0
    latin_1_str = b'So\xe4\xf6\xfc\xdf string data'
    utf_8_str = b'So\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f string data'
    buf = bytearray()
    buf += 'äöüß'.encode('latin-1')

    encoding_idx = ida_nalt.add_encoding(string_encoding)
    assert encoding_idx

    string_type = ida_nalt.make_str_type(ida_nalt.STRTYPE_C, encoding_idx)
    assert string_type
    ida_nalt.set_str_type(string_addr, string_type)
    db.bytes.set_bytes_at(string_addr + 2, bytes(buf))
    db.strings.rebuild()

    modified_bytes = db.bytes.get_bytes_at(string_addr, len(latin_1_str))
    assert modified_bytes == latin_1_str

    modified_string = db.strings.get_at(string_addr)
    assert modified_string.contents == utf_8_str
    assert str(modified_string) == utf_8_str.decode('utf-8')
    assert modified_string.encoding == string_encoding
    assert modified_string.length == 19
    assert modified_string.internal_type == string_type
    assert modified_string.type == StringType.C
    assert len(db.strings) == 3


@min_ida_version('9.4')
def test_decompiler_strings(tiny_stackstrings_env):
    db = tiny_stackstrings_env

    # The marker text is stored as 16-bit units on the stack: no string literal exists.
    # The only literal is the compiler identification GCC emits into .rdata$zzz.
    assert [item.type for item in db.strings] == [StringType.C]

    func = db.functions.get_by_name('emit_marker')
    assert func is not None
    db.pseudocode.decompile(func.start_ea)
    # Decompiler strings are collected from the decompiler cache when the list is built
    db.strings.rebuild()

    assert len(db.strings) == 2
    items = [item for item in db.strings if item.type == StringType.DECOMP]
    assert len(items) == 1
    item = items[0]
    assert item.decompiler_string == 'ida-domain'
    assert str(item) == 'ida-domain'
    assert item.contents == b'ida-domain'
    assert bytes(item) == b'ida-domain'
    assert item.length == 10
    assert item.internal_type == ida_nalt.STRTYPE_DECOMP
    assert func.start_ea <= item.address < func.end_ea

    assert db.strings.get_at(item.address) == item
    assert item in list(db.strings.get_between(func.start_ea, func.end_ea))

    # Regular strings are unaffected
    for other in db.strings:
        if other.type != StringType.DECOMP:
            assert other.decompiler_string is None
            assert str(other) == other.contents.decode('utf-8')
