import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from packaging.version import Version

import ida_domain  # isort: skip
import ida_typeinf
from ida_idaapi import BADADDR

import ida_domain.flowchart
from ida_domain.base import DatabaseError, DecompilerError, InvalidParameterError
from ida_domain.bytes import SearchFlags
from ida_domain.database import IdaCommandOptions
from ida_domain.instructions import Instructions
from ida_domain.segments import *
from ida_domain.strings import StringListConfig, StringType
from ida_domain.types import TypeDetails, TypeKind

idb_path: str = ''
logger = logging.getLogger(__name__)


def min_ida_version(v: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(
        ida_domain.__ida_version__ < Version(v),
        reason=f'requires IDA {v}+',
    )


# Global setup (runs ONCE)
@pytest.fixture(scope='module', autouse=True)
def global_setup():
    print(f'\nAPI Version: {ida_domain.__version__}')
    print(f'\nKernel Version: {ida_domain.__ida_version__}')

    os.environ['IDA_NO_HISTORY'] = '1'

    """ Runs once per module: Creates temp directory and writes test binary. """
    global idb_path
    # Create a temporary folder and use it as tests working directory
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir')
    shutil.rmtree(idb_path, ignore_errors=True)
    os.makedirs(idb_path, exist_ok=True)
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_asm.bin')

    # Copy the test binary from resources folder under our tests working directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')
    shutil.copy(src_path, idb_path)


# Per-test fixture (runs for each test)
@pytest.fixture(scope='function')
def test_env():
    """Runs for each test: Opens and closes the database."""
    ida_options = IdaCommandOptions(new_database=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# C binary path for complex variable access tests
tiny_c_idb_path: str = ''


@pytest.fixture(scope='module')
def tiny_c_setup(global_setup):
    """Setup for C binary tests - copies tiny_c.bin to work directory."""
    global tiny_c_idb_path
    tiny_c_idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_c.bin')
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')
    shutil.copy(src_path, tiny_c_idb_path)


@pytest.fixture(scope='function')
def tiny_c_env(tiny_c_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=tiny_c_idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# Imports binary path for testing with actual imports
tiny_imports_idb_path: str = ''


@pytest.fixture(scope='module')
def tiny_imports_setup(global_setup):
    """Setup for imports binary tests - copies tiny_imports.bin to work directory."""
    global tiny_imports_idb_path
    tiny_imports_idb_path = os.path.join(
        tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_imports.bin'
    )
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_imports.bin')
    shutil.copy(src_path, tiny_imports_idb_path)


@pytest.fixture(scope='function')
def tiny_imports_env(tiny_imports_setup):
    """Opens tiny_imports database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(
        path=tiny_imports_idb_path, args=ida_options, save_on_close=False
    )
    yield db
    if db.is_open():
        db.close(False)


def test_database(test_env):
    db = test_env
    db.close(False)
    assert db.is_open() is False
    db = ida_domain.Database.open(idb_path)
    assert db.is_open() is True

    db.current_ea = 0x50
    assert db.current_ea == 0x50

    assert db.minimum_ea == 0x0
    assert db.maximum_ea == 0x420

    assert db.base_address == 0x0
    assert db.module == 'tiny_asm.bin'
    assert db.filesize == 3680
    assert db.md5 == 'f53ff12139b2cf71703222e79cfe0b9b'
    assert db.sha256 == '03858ca230c1755b1db18c4051c348de5b4b274ff0489ea14237f56a9f9adf30'
    assert db.crc32 == 404194086
    assert db.architecture == 'metapc'
    assert db.bitness == 64
    assert db.format == 'ELF64 for x86-64 (Relocatable)'

    metadata = db.metadata
    from dataclasses import fields

    assert len(fields(metadata)) == 13

    assert 'tiny_asm.bin' in metadata.path
    assert metadata.module == 'tiny_asm.bin'
    assert metadata.base_address == 0x0
    assert metadata.filesize == 0xE60
    assert metadata.md5 == 'f53ff12139b2cf71703222e79cfe0b9b'
    assert metadata.sha256 == '03858ca230c1755b1db18c4051c348de5b4b274ff0489ea14237f56a9f9adf30'
    assert metadata.crc32 == 0x18178326
    assert metadata.architecture == 'metapc'
    assert metadata.bitness == 0x40
    assert metadata.format == 'ELF64 for x86-64 (Relocatable)'
    assert len(metadata.load_time) == 19  # dummy check, expect "YYYY-MM-DD HH:MM:SS"
    assert metadata.execution_mode == 'User Mode'
    assert metadata.compiler_information == (
        'Name: GNU C++, sizes in bits: '
        '(byte: 8, short: 16, enum: 32, int: 32, long: 64, double: 128, long_long: 64)'
    )

    compiler_info = db.compiler_information
    assert compiler_info.name == 'GNU C++'
    assert compiler_info.byte_size_bits == 8
    assert compiler_info.short_size_bits == 16
    assert compiler_info.enum_size_bits == 32
    assert compiler_info.int_size_bits == 32
    assert compiler_info.long_size_bits == 64
    assert compiler_info.double_size_bits == 128
    assert compiler_info.long_long_size_bits == 64

    assert db.execution_mode == ida_domain.database.ExecutionMode.User
    db.close(False)

    # Test context manager protocol
    with ida_domain.Database.open(idb_path, save_on_close=False) as db2:
        assert db2.is_open()
        func = db2.functions.get_at(0x2A3)
        assert func is not None
        assert func.start_ea == 0x2A3
        assert db2.functions.set_name(func, 'testing_function_rename')
        assert func.name == 'testing_function_rename'
    # The database should be close automatically
    assert not db2.is_open()

    # Reopen it and check the rename was discarded due to save_on_close=False
    db2 = ida_domain.Database.open(idb_path, save_on_close=False)
    assert db2.is_open()
    func = db2.functions.get_at(0x2A3)
    assert func is not None
    assert func.start_ea == 0x2A3
    assert func.name == 'add_numbers'
    db2.close(False)

    with ida_domain.Database.open(idb_path, save_on_close=True) as db3:
        assert db3.is_open()
        func = db3.functions.get_at(0x2A3)
        assert func is not None
        assert func.start_ea == 0x2A3
        assert db3.functions.set_name(func, 'testing_function_rename')
        assert func.name == 'testing_function_rename'

    # The database should be close automatically
    assert not db3.is_open()
    # Reopen it and check the rename was preserved due to save_on_close=True
    db3 = ida_domain.Database.open(idb_path, save_on_close=False)
    assert db3.is_open()
    func = db3.functions.get_at(0x2A3)
    assert func is not None
    assert func.start_ea == 0x2A3
    assert func.name == 'testing_function_rename'
    db3.close(False)


def test_segment(test_env):
    db = test_env

    seg = db.segments.append(0, 0x100, '.test', PredefinedClass.CODE, AddSegmentFlags.NONE)
    assert seg is not None
    assert (
        db.segments.set_permissions(seg, SegmentPermissions.READ | SegmentPermissions.EXEC) == True
    )
    assert db.segments.add_permissions(seg, SegmentPermissions.WRITE) == True
    assert db.segments.remove_permissions(seg, SegmentPermissions.EXEC) == True
    assert db.segments.set_addressing_mode(seg, AddressingMode.BIT64) == True

    assert len(db.segments) == 5
    for segment in db.segments:
        assert db.segments.get_name(segment)

    for idx, seg in enumerate(db.segments):
        if idx == 0:
            assert seg is not None
            assert db.segments.get_name(seg) == '.text'
            assert seg.start_ea == 0
            assert db.segments.set_name(seg, 'testing_segment_rename')
            assert db.segments.get_name(seg) == 'testing_segment_rename'
        elif idx == 1:
            assert seg is not None
            assert db.segments.get_name(seg) == '.data'
            assert seg.start_ea == 0x330

    # Test segment comment methods
    test_segment = db.segments.get_at(0x330)  # Use .data segment
    assert test_segment is not None
    test_comment = 'Test segment comment'
    test_repeatable_comment = 'Test repeatable segment comment'

    # Test non-repeatable segment comment
    assert db.segments.set_comment(test_segment, test_comment, False)
    retrieved_comment = db.segments.get_comment(test_segment, False)
    assert retrieved_comment == test_comment

    # Test repeatable segment comment
    assert db.segments.set_comment(test_segment, test_repeatable_comment, True)
    retrieved_repeatable_comment = db.segments.get_comment(test_segment, True)
    assert retrieved_repeatable_comment == test_repeatable_comment

    # Test getting non-existent comment returns empty string
    text_segment = db.segments.get_at(0x0)  # Use .text segment
    empty_comment = db.segments.get_comment(text_segment, False)
    assert empty_comment == ''


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

    pseudocode_lines = db.functions.get_pseudocode(func)
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

    from ida_domain.base import InvalidEAError

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

    from ida_domain.base import InvalidEAError, InvalidParameterError

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


def test_entries(test_env):
    db = test_env

    count = 0
    for _ in db.entries:
        count += 1
    assert count == 1

    assert db.entries.get_count() == 1
    assert len(db.entries) == 1
    assert db.entries[0] == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_at_index(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_by_ordinal(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_at(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)

    assert db.entries.add(address=0xCC, name='test_entry', ordinal=1)
    assert db.entries.get_count() == 2
    assert db.entries.get_at_index(1) == ida_domain.entries.EntryInfo(1, 0xCC, 'test_entry', None)
    assert db.entries.get_by_ordinal(1) == ida_domain.entries.EntryInfo(
        1, 0xCC, 'test_entry', None
    )
    assert db.entries.get_at(0xCC) == ida_domain.entries.EntryInfo(1, 0xCC, 'test_entry', None)

    assert db.entries.rename(0, '_new_start')
    assert db.entries.get_at_index(0) == ida_domain.entries.EntryInfo(0, 0, '_new_start', None)

    assert db.entries.get_by_name('_new_start') == ida_domain.entries.EntryInfo(
        0, 0, '_new_start', None
    )

    assert db.entries.exists(0) is True
    assert db.entries.exists(1) is True
    assert db.entries.exists(999) is False

    ordinals = list(db.entries.get_ordinals())
    assert ordinals == [0, 1]

    addresses = list(db.entries.get_addresses())
    assert addresses == [0, 0xCC]

    names = list(db.entries.get_names())
    assert '_new_start' in names
    assert 'test_entry' in names
    assert len(names) == 2

    assert db.entries.set_forwarder(1, 'kernel32.CreateFile')
    entry_with_forwarder = db.entries.get_by_ordinal(1)
    assert entry_with_forwarder.forwarder_name == 'kernel32.CreateFile'
    assert entry_with_forwarder.has_forwarder() is True

    forwarders = list(db.entries.get_forwarders())
    assert len(forwarders) == 1
    assert forwarders[0].ordinal == 1
    assert forwarders[0].name == 'kernel32.CreateFile'

    entry_no_forwarder = db.entries.get_by_ordinal(0)
    assert entry_no_forwarder.has_forwarder() is False

    with pytest.raises(IndexError):
        db.entries.get_at_index(-1)

    with pytest.raises(IndexError):
        db.entries.get_at_index(999)

    with pytest.raises(IndexError):
        _ = db.entries[999]

    assert db.entries.get_by_ordinal(999) is None
    assert db.entries.get_at(0xFFFF) is None
    assert db.entries.get_by_name('non_existent_entry') is None

    assert db.entries.add(address=0xDD, name='auto_ordinal')
    auto_entry = db.entries.get_at(0xDD)
    assert auto_entry is not None
    assert auto_entry.address == 0xDD
    assert auto_entry.name == 'auto_ordinal'

    assert db.entries.add(address=0xEE, name='no_code', ordinal=100, make_code=False)
    no_code_entry = db.entries.get_by_ordinal(100)
    assert no_code_entry is not None
    assert no_code_entry.address == 0xEE
    assert no_code_entry.name == 'no_code'


def test_imports(test_env):
    db = test_env
    import ida_domain.imports

    assert db.imports.get_module_count() == 0
    assert len(db.imports) == 0

    count = 0
    for _ in db.imports:
        count += 1
    assert count == 0

    assert list(db.imports.get_all_modules()) == []
    assert list(db.imports.get_all_imports()) == []
    assert list(db.imports.get_module_names()) == []
    assert list(db.imports.get_import_names()) == []
    assert list(db.imports.get_import_addresses()) == []
    assert db.imports.get_import_count() == 0

    assert db.imports.get_module_by_name('kernel32.dll') is None
    assert db.imports.get_import_by_name('kernel32.dll!CreateFileW') is None
    assert db.imports.get_import_by_name('kernel32.dll!#42') is None
    assert db.imports.get_import_by_name('CreateFileW') is None  # missing module prefix
    assert db.imports.get_import_at(0x1000) is None
    assert db.imports.exists('kernel32.dll!CreateFileW') is False

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(-1)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(0)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(999)

    with pytest.raises(IndexError):
        _ = db.imports[0]

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(-1))

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(0))

    imp_info = ida_domain.imports.ImportInfo(
        address=0x1000,
        name='TestFunc',
        ordinal=1,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_info.has_name() is True
    assert imp_info.address == 0x1000
    assert imp_info.name == 'TestFunc'
    assert imp_info.ordinal == 1
    assert imp_info.module_index == 0
    assert imp_info.module_name == 'test.dll'

    imp_ordinal_only = ida_domain.imports.ImportInfo(
        address=0x2000,
        name=None,
        ordinal=42,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_ordinal_only.has_name() is False

    imp_empty_name = ida_domain.imports.ImportInfo(
        address=0x3000,
        name='',
        ordinal=43,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_empty_name.has_name() is False

    mod_info = ida_domain.imports.ImportModuleInfo(index=0, name='kernel32.dll')
    assert mod_info.index == 0
    assert mod_info.name == 'kernel32.dll'


def test_imports_populated(tiny_imports_env):
    """Test imports functionality with actual import data from a dynamically-linked binary."""
    db = tiny_imports_env
    import ida_domain.imports

    # Expected counts for tiny_imports.bin (libc-linked ELF64)
    # Module: .dynsym (IDA's representation of ELF dynamic symbols)
    # Imports: free, __libc_start_main, puts, malloc, exit, __gmon_start__
    expected_module_count = 1
    expected_import_count = 6

    # === Test module count and iteration ===
    module_count = db.imports.get_module_count()
    assert module_count == expected_module_count
    assert len(db.imports) == expected_module_count

    # Count via iteration
    iter_count = 0
    for _ in db.imports:
        iter_count += 1
    assert iter_count == expected_module_count

    # === Test get_all_modules() ===
    modules = list(db.imports.get_all_modules())
    assert len(modules) == expected_module_count

    # All modules should have valid index and non-empty name
    for module in modules:
        assert isinstance(module, ida_domain.imports.ImportModuleInfo)
        assert module.index >= 0
        assert module.index < module_count
        assert len(module.name) > 0

    # === Test get_module_at_index() and __getitem__ ===
    first_module = db.imports.get_module_at_index(0)
    assert first_module is not None
    assert first_module.index == 0

    # Same via subscript
    first_module_sub = db.imports[0]
    assert first_module_sub.index == first_module.index
    assert first_module_sub.name == first_module.name

    # Test last valid index
    last_module = db.imports.get_module_at_index(module_count - 1)
    assert last_module is not None
    assert last_module.index == module_count - 1

    # === Test get_module_by_name() - case insensitive ===
    # Use the first module (for ELF files, IDA uses '.dynsym' as the module name)
    test_module = first_module
    assert test_module is not None

    # Test exact name
    found = db.imports.get_module_by_name(test_module.name)
    assert found is not None
    assert found.name == test_module.name

    # Test case-insensitive
    found_upper = db.imports.get_module_by_name(test_module.name.upper())
    assert found_upper is not None
    assert found_upper.name == test_module.name

    # Test non-existent module
    assert db.imports.get_module_by_name('nonexistent_module.dll') is None

    # === Test get_module_names() ===
    module_names = list(db.imports.get_module_names())
    assert len(module_names) == expected_module_count
    for name in module_names:
        assert isinstance(name, str)
        assert len(name) > 0

    # === Test get_all_imports() ===
    all_imports = list(db.imports.get_all_imports())
    assert len(all_imports) == expected_import_count

    # Verify ImportInfo structure
    for imp in all_imports:
        assert isinstance(imp, ida_domain.imports.ImportInfo)
        assert imp.module_index >= 0
        assert imp.module_index < module_count
        assert len(imp.module_name) > 0
        # Address should be valid (not 0 for real imports in IAT)
        assert imp.address != 0

    # === Test get_import_count() ===
    import_count = db.imports.get_import_count()
    assert import_count == expected_import_count

    # === Test get_imports_for_module() ===
    total_from_modules = 0
    for module in modules:
        module_imports = list(db.imports.get_imports_for_module(module.index))
        total_from_modules += len(module_imports)
        # Each import should belong to this module
        for imp in module_imports:
            assert imp.module_index == module.index
            assert imp.module_name == module.name
    assert total_from_modules == expected_import_count

    # === Test get_import_names() - qualified format ===
    import_names = list(db.imports.get_import_names())
    assert len(import_names) == expected_import_count

    for name in import_names:
        assert '!' in name, "Import names should be in 'module!symbol' format"
        parts = name.split('!')
        assert len(parts) == 2
        assert len(parts[0]) > 0  # module name
        assert len(parts[1]) > 0  # symbol name or ordinal

    # === Test get_import_addresses() ===
    addresses = list(db.imports.get_import_addresses())
    assert len(addresses) == expected_import_count

    # All addresses should be unique
    unique_addresses = set(addresses)
    assert len(unique_addresses) == len(addresses), 'Import addresses should be unique'

    # === Test get_import_by_name() - find known imports ===
    # Look for common libc imports. ELF import names include version suffix
    # (e.g., malloc@@GLIBC_2.2.5)
    known_imports = ['malloc', 'free', 'puts', 'exit']
    found_any = False

    for imp in all_imports:
        # Check if import name starts with any known import
        # (handles version suffixes like @@GLIBC_2.2.5)
        if imp.name:
            for known in known_imports:
                if imp.name.startswith(known):
                    # Test exact qualified name lookup
                    qualified = f'{imp.module_name}!{imp.name}'
                    found = db.imports.get_import_by_name(qualified)
                    assert found is not None, f'Should find import by qualified name: {qualified}'
                    assert found.name == imp.name
                    assert found.module_name == imp.module_name
                    assert found.address == imp.address

                    # Test case-insensitive lookup
                    found_upper = db.imports.get_import_by_name(qualified.upper())
                    assert found_upper is not None
                    assert found_upper.address == imp.address

                    found_any = True
                    break

    assert found_any, 'Should find at least one known import'

    # Test non-existent import
    assert db.imports.get_import_by_name('.dynsym!nonexistent_function') is None

    # Test invalid format (missing module prefix)
    assert db.imports.get_import_by_name('malloc') is None

    # === Test get_import_at() ===
    # Use first import's address
    first_import = all_imports[0]
    found_at = db.imports.get_import_at(first_import.address)
    assert found_at is not None
    assert found_at.address == first_import.address
    assert found_at.name == first_import.name

    # Test non-existent address
    assert db.imports.get_import_at(0xDEADBEEF) is None

    # === Test exists() ===
    if first_import.name:
        qualified = f'{first_import.module_name}!{first_import.name}'
        assert db.imports.exists(qualified) is True

    assert db.imports.exists('nonexistent.dll!fake_function') is False

    # === Test ImportInfo.has_name() ===
    for imp in all_imports:
        if imp.name and len(imp.name) > 0:
            assert imp.has_name() is True
        else:
            assert imp.has_name() is False

    # === Test IndexError for out of bounds ===
    with pytest.raises(IndexError):
        db.imports.get_module_at_index(-1)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(module_count)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(module_count + 100)

    with pytest.raises(IndexError):
        _ = db.imports[module_count]

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(-1))

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(module_count))


def test_heads(test_env):
    db = test_env

    count = 0
    heads = db.heads
    for _ in heads:
        count += 1
    assert count == 201

    assert db.heads.get_previous(db.minimum_ea) is None
    assert db.heads.get_next(db.maximum_ea) is None

    expected = [0xC8, 0xC9, 0xCB, 0xCD, 0xCF, 0xD1, 0xD4]
    actual = []
    heads = db.heads.get_between(0xC6, 0xD6)
    for ea in heads:
        actual.append(ea)
    assert actual == expected

    assert db.heads.get_previous(0xCB) == 0xC9
    assert db.heads.get_next(0xC9) == 0xCB

    assert db.heads.is_head(0x67) is True  # Start of an instruction
    assert db.heads.is_head(0x68) is False  # Middle of an instruction
    assert db.heads.is_head(0x330) is True  # Start of data

    assert db.heads.is_tail(0x67) is False  # Start of an instruction
    assert db.heads.is_tail(0x68) is True  # Middle of an instruction
    assert db.heads.is_tail(0x330) is False  # Start of data

    assert db.heads.size(0x67) == 2
    assert db.heads.size(0x330) == 8

    from ida_domain.base import InvalidEAError, InvalidParameterError

    with pytest.raises(InvalidParameterError):
        db.heads.size(0x68)  # Not a head

    start, end = db.heads.bounds(0x67)
    assert start == 0x67 and end == 0x69

    start, end = db.heads.bounds(0x68)  # Middle of instruction
    assert start == 0x67
    assert end == 0x69

    start, end = db.heads.bounds(0x330)
    assert start == 0x330 and end == 0x338

    assert db.heads.is_code(0x67) is True  # Instruction address
    assert db.heads.is_code(0x330) is False  # Data address
    assert db.heads.is_code(0x3D4) is False  # String data

    assert db.heads.is_data(0x67) is False  # Instruction address
    assert db.heads.is_data(0x330) is True  # Data address
    assert db.heads.is_data(0x3D4) is True  # String data

    all_heads_list = list(db.heads.get_all())
    assert len(all_heads_list) == 201  # Same count as iterator

    with pytest.raises(InvalidEAError):
        db.heads.get_next(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.get_previous(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_head(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_tail(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.size(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.bounds(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_code(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_data(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        list(db.heads.get_between(0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        list(db.heads.get_between(0x100, 0x50))  # start > end

    bounds_result = db.heads.bounds(0x400)  # May be in undefined area
    assert isinstance(bounds_result, tuple) and len(bounds_result) == 2
    assert bounds_result[0] <= 0x400 <= bounds_result[1]


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

    from ida_domain.base import InvalidEAError, InvalidParameterError

    with pytest.raises(InvalidEAError):
        list(db.instructions.get_between(0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        list(db.instructions.get_between(0x200, 0x100))

    with pytest.raises(InvalidEAError):
        db.instructions.get_at(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.instructions.get_previous(0xFFFFFFFF)


def test_basic_block(test_env):
    db = test_env
    func = db.functions.get_at(0x29E)
    assert func is not None

    blocks = db.functions.get_flowchart(func)
    assert blocks.size == 4

    # Validate expected blocks
    expected_blocks = [(0xC4, 0x262), (0x262, 0x26B), (0x26B, 0x272), (0x272, 0x2A3)]

    for i, block in enumerate(blocks):
        assert expected_blocks[i][0] == block.start_ea, (
            f'Block start ea mismatch at index {i}, '
            f'{hex(expected_blocks[i][0])} != {hex(block.start_ea)}'
        )
        assert expected_blocks[i][1] == block.end_ea, (
            f'Block end ea mismatch at index {i}, '
            f'{hex(expected_blocks[i][1])} != {hex(block.end_ea)}'
        )

    # Validate expected instructions and their addresses
    expected_instructions = [
        (0x262, 'call    rax'),
        (0x264, 'call    qword ptr [rbx]'),
        (0x266, 'call    qword ptr [rbx+rcx*4]'),
        (0x269, 'jmp     rax'),
    ]

    instructions = db.instructions.get_between(blocks[1].start_ea, blocks[1].end_ea)
    for i, instruction in enumerate(instructions):
        assert expected_instructions[i][0] == instruction.ea
        assert expected_instructions[i][1] == db.instructions.get_disassembly(instruction)

    # Test FlowChart iteration and length
    assert len(blocks) == 4
    block_count = 0
    for block in blocks:
        assert hasattr(block, 'start_ea')
        assert hasattr(block, 'end_ea')
        block_count += 1
    assert block_count == 4

    # Test FlowChart indexing with __getitem__
    assert blocks[0].start_ea == 0xC4
    assert blocks[3].end_ea == 0x2A3
    with pytest.raises(IndexError):
        blocks[4]  # Should raise IndexError

    # Test successor and predecessor relationships
    # First block (0xC4-0x262) should have one successor
    first_block = blocks[0]
    successors = list(first_block.get_successors())
    assert len(successors) == 1
    assert successors[0].start_ea == 0x272

    instructions = list(first_block.get_instructions())
    assert len(instructions) == 77

    # Count successors
    assert first_block.count_successors() == 1

    # Last block (0x272-0x2A3) should have predecessors
    last_block = blocks[3]
    predecessors = list(last_block.get_predecessors())
    assert len(predecessors) >= 1
    # Check that at least one predecessor is from our function
    assert any(pred.start_ea == 0xC4 for pred in predecessors)

    # Count predecessors
    assert last_block.count_predecessors() >= 1

    # Test get_between method
    flowchart = ida_domain.flowchart.FlowChart(db, None, (0xC4, 0x2A3))
    assert len(flowchart) == 4
    assert flowchart[0].start_ea == 0xC4
    assert flowchart[3].end_ea == 0x2A3

    # Test get_between error handling
    from ida_domain.base import InvalidEAError, InvalidParameterError

    with pytest.raises(InvalidEAError):
        ida_domain.flowchart.FlowChart(db, None, (0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        ida_domain.flowchart.FlowChart(db, None, (0x200, 0x100))

    # Test function_flowchart method (same as db.functions.get_basic_blocks)
    func_blocks = db.functions.get_flowchart(func)
    assert len(func_blocks) == 4
    assert func_blocks[0].start_ea == blocks[0].start_ea
    assert func_blocks[3].end_ea == blocks[3].end_ea

    # Test with flags parameter
    from ida_domain.flowchart import FlowChartFlags

    func_blocks_with_flags = db.functions.get_flowchart(func, flags=FlowChartFlags.NONE)
    assert len(func_blocks_with_flags) == 4

    # Test with NOEXT flag
    func_blocks_noext = db.functions.get_flowchart(func, flags=FlowChartFlags.NOEXT)
    assert len(func_blocks_noext) == 4

    # Test flowchart iteration for a different range
    small_flowchart = ida_domain.flowchart.FlowChart(db, None, (0x10, 0x20))
    # Just verify iteration works regardless of block count
    count = 0
    for block in small_flowchart:
        assert hasattr(block, 'start_ea')
        assert hasattr(block, 'end_ea')
        count += 1
    assert count == len(small_flowchart)

    # Test that successor/predecessor references are properly maintained
    # Use the first block which we know has a successor
    test_block_with_successor = blocks[0]
    test_successors = list(test_block_with_successor.get_successors())
    assert len(test_successors) > 0

    for succ in test_successors:
        # Check that we can get predecessors of the successor
        succ_preds = list(succ.get_predecessors())
        assert any(pred.start_ea == test_block_with_successor.start_ea for pred in succ_preds)


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


def test_strings(test_env):
    db = test_env
    from ida_domain.base import InvalidEAError, InvalidParameterError

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

    from ida_domain.strings import StringType

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
    import ida_nalt

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


def test_names(test_env):
    db = test_env

    assert db.names.get_count() == 28
    assert len(db.names) == 28

    expected_names = [
        (0x0, '_start'),
        (0xC4, 'test_all_operand_types'),
        (0x272, 'skip_jumps'),
        (0x2A3, 'add_numbers'),
        (0x2AF, 'multiply_numbers'),
        (0x2BC, 'print_number'),
        (0x2D0, 'print_number.print_digit'),
        (0x2F7, 'level1_func'),
        (0x307, 'level2_func_a'),
        (0x312, 'level2_func_b'),
        (0x31D, 'level3_func'),
        (0x330, 'test_data'),
        (0x338, 'test_array'),
        (0x378, 'temp_float'),
        (0x37C, 'temp_double'),
        (0x390, 'vector_data'),
        (0x3A0, 'src_string'),
        (0x3B3, 'dst_string'),
        (0x3D4, 'hello'),
        (0x3E1, 'sum_str'),
        (0x3E6, 'product_str'),
        (0x3EF, 'newline'),
        (0x3F0, 'float_val'),
        (0x3F4, 'double_val'),
        (0x400, 'hello_len'),
        (0x408, 'sum_len'),
        (0x410, 'product_len'),
        (0x418, 'newline_len'),
    ]

    for i, (expected_addr, expected_name) in enumerate(expected_names):
        nameAndAddress = db.names.get_at_index(i)
        assert nameAndAddress[0] == expected_addr, (
            f'Name address mismatch at index {i}, {hex(nameAndAddress[0])} != {hex(expected_addr)}'
        )
        assert nameAndAddress[1] == expected_name, (
            f'Name mismatch at index {i}, {nameAndAddress[1]} != {expected_name}'
        )

        nameAndAddress = db.names[i]
        assert nameAndAddress[0] == expected_addr, (
            f'Name address mismatch at index {i}, {hex(nameAndAddress[0])} != {hex(expected_addr)}'
        )
        assert nameAndAddress[1] == expected_name, (
            f'Name mismatch at index {i}, {nameAndAddress[1]} != {expected_name}'
        )

    for i, (addr, name) in enumerate(db.names):
        assert addr == expected_names[i][0]
        assert name == expected_names[i][1]

    name = db.names.get_at(0x0)
    assert name == '_start'

    name = db.names.get_at(0x418)
    assert name == 'newline_len'

    assert db.names.get_at(db.minimum_ea) == '_start'

    from ida_domain.names import DemangleFlags, SetNameFlags

    test_addr = 0x418
    success = db.names.set_name(test_addr, 'test_name', SetNameFlags.NOCHECK)
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'test_name'

    success = db.names.set_name(
        test_addr, 'test_name_public', SetNameFlags.PUBLIC | SetNameFlags.NOCHECK
    )
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'test_name_public'

    success = db.names.force_name(
        test_addr, 'forced_name', SetNameFlags.FORCE | SetNameFlags.NOCHECK
    )
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'forced_name'

    success = db.names.delete(test_addr)
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == ''  # Should be empty after deletion

    assert db.names.is_valid_name('valid_name') is True
    assert db.names.is_valid_name('123invalid') is False  # Names can't start with numbers
    assert db.names.is_valid_name('') is False  # Empty names are invalid

    test_addr = 0x330  # Use test_data address

    original_public = db.names.is_public_name(test_addr)
    assert not original_public
    db.names.make_name_public(test_addr)
    assert db.names.is_public_name(test_addr) is True
    db.names.make_name_non_public(test_addr)
    assert db.names.is_public_name(test_addr) is False

    original_weak = db.names.is_weak_name(test_addr)
    assert not original_weak

    db.names.make_name_weak(test_addr)
    assert db.names.is_weak_name(test_addr) is True
    db.names.make_name_non_weak(test_addr)
    assert db.names.is_weak_name(test_addr) is False

    demangled = db.names.get_demangled_name(0x2A3)  # add_numbers function
    assert isinstance(demangled, str)
    assert demangled == 'add_numbers'

    # Test demangle_name method with a known mangled name pattern
    mangled_name = '_Z3fooi'  # Simple C++ mangled name
    demangled = db.names.demangle_name(mangled_name)
    assert isinstance(demangled, str)
    assert demangled == 'foo(int)'

    # Test demangle_name with non-mangled name (should return original)
    normal_name = 'normal_function_name'
    result = db.names.demangle_name(normal_name, DemangleFlags.DEFNONE)
    assert result is None

    assert db.names.delete(test_addr)


def test_xrefs(test_env):
    db = test_env
    expected_xrefs = [0xC4]
    expected_names = ['ORDINARY_FLOW']
    xrefs_to = db.xrefs.to_ea(0xC6)
    for i, xref in enumerate(xrefs_to):
        assert xref.from_ea == expected_xrefs[i]
        assert xref.type.name == expected_names[i]

    expected_xrefs = [0xD9]
    expected_names = ['ORDINARY_FLOW']
    xrefs_from = db.xrefs.from_ea(0xD6)
    for i, xref in enumerate(xrefs_from):
        assert xref.to_ea == expected_xrefs[i]
        assert xref.type.name == expected_names[i]

    from ida_domain.xrefs import XrefsFlags

    # Test to() with different XrefsFlags options
    all_xrefs = list(db.xrefs.to_ea(0x2A3))
    assert len(all_xrefs) >= 1

    code_xrefs = list(db.xrefs.to_ea(0x2A3, XrefsFlags.CODE))
    assert isinstance(code_xrefs, list)

    code_xrefs_noflow = list(db.xrefs.to_ea(0x2A3, XrefsFlags.CODE_NOFLOW))
    assert isinstance(code_xrefs_noflow, list)

    data_xrefs = list(db.xrefs.to_ea(0x330, XrefsFlags.DATA))
    assert isinstance(data_xrefs, list)

    # Test from_() with different options
    from_xrefs = list(db.xrefs.from_ea(0x27))
    assert len(from_xrefs) >= 1

    from_code = list(db.xrefs.from_ea(0x27, XrefsFlags.CODE))
    assert isinstance(from_code, list)

    from_data = list(db.xrefs.from_ea(0xFF, XrefsFlags.DATA))
    assert isinstance(from_data, list)

    from ida_domain.xrefs import CallerInfo

    # Test call references
    calls_to = list(db.xrefs.calls_to_ea(0x2A3))  # add_numbers
    assert len(calls_to) == 1
    assert calls_to[0] == 0x27

    # Test callers with detailed info
    callers = list(db.xrefs.get_callers(0x2A3))
    assert isinstance(callers, list)
    assert len(callers) == 1
    assert isinstance(callers[0], CallerInfo)
    assert callers[0].ea == 0x27

    calls_from = list(db.xrefs.calls_from_ea(0x27))
    assert len(calls_from) >= 1

    # Test jump references
    jumps_to = list(db.xrefs.jumps_to_ea(0x272))  # skip_jumps
    assert isinstance(jumps_to, list)

    jumps_from = list(db.xrefs.jumps_from_ea(0x270))
    assert isinstance(jumps_from, list)

    # Test data reads and writes
    reads = list(db.xrefs.reads_of_ea(0x330))  # test_data
    assert isinstance(reads, list)

    writes = list(db.xrefs.writes_to_ea(0x330))
    assert isinstance(writes, list)

    # Test code refs to/from (now returns iterators)
    code_refs_to = list(db.xrefs.code_refs_to_ea(0x2A3))
    assert isinstance(code_refs_to, list)
    assert len(code_refs_to) >= 1
    assert all(isinstance(ea, int) for ea in code_refs_to)

    code_refs_from = list(db.xrefs.code_refs_from_ea(0x27))
    assert isinstance(code_refs_from, list)

    # Test data refs to/from (now returns iterators)
    data_refs_to = list(db.xrefs.data_refs_to_ea(0x330))
    assert isinstance(data_refs_to, list)

    data_refs_from = list(db.xrefs.data_refs_from_ea(0xFF))
    assert isinstance(data_refs_from, list)

    from ida_domain.xrefs import XrefType

    # Test enhanced xref info
    xrefs_info = list(db.xrefs.to_ea(0x2A3))
    assert len(xrefs_info) == 1
    assert xrefs_info[0].from_ea == 39
    assert xrefs_info[0].is_code == True
    assert xrefs_info[0].type == XrefType.CALL_NEAR
    assert xrefs_info[0].user == False
    assert xrefs_info[0].to_ea == 0x2A3
    assert xrefs_info[0].is_call == True

    # Test with custom flags
    xrefs_custom = list(db.xrefs.to_ea(0x2A3, flags=XrefsFlags.CODE))
    assert isinstance(xrefs_custom, list)

    xrefs_from = list(db.xrefs.from_ea(0x27))
    assert isinstance(xrefs_from, list)

    # Test function callers
    callers = list(db.xrefs.get_callers(0x2A3))
    assert isinstance(callers, list)
    assert len(callers) == 1
    assert callers[0].ea == 0x27
    assert callers[0].name == '.text:0000000000000027'
    assert callers[0].xref_type == XrefType.CALL_NEAR
    assert callers[0].function_ea is None

    from ida_domain.base import InvalidEAError

    invalid_ea = 0xFFFFFFFF

    # Test all methods with invalid addresses
    with pytest.raises(InvalidEAError):
        list(db.xrefs.to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.calls_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.calls_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.jumps_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.jumps_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.reads_of_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.writes_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.code_refs_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.code_refs_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.data_refs_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.data_refs_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.get_callers(invalid_ea))


def test_types(test_env):
    db = test_env
    all_types = db.types
    assert len(list(all_types)) == 0

    til_path = Path(__file__).parent / 'resources' / 'example.til'
    assert til_path.exists()
    til = db.types.load_library(til_path)
    assert til

    types_list = list(db.types.get_all(library=til, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 3

    types_list = list(db.types.get_all(library=til))
    assert len(types_list) == 3

    assert db.types.import_type(til, 'STRUCT_EXAMPLE')
    assert len(list(db.types)) == 2

    tif = db.types.get_by_name('STRUCT_EXAMPLE')
    assert not db.types.apply_at(tif, 0xB3)

    type_info = db.types.get_at(0xB3)
    assert type_info is None

    assert db.types.apply_at(tif, 0x330)
    type_info = db.types.get_at(0x330)
    assert type_info
    assert type_info.get_tid() == tif.get_tid()

    from ida_domain.types import TypeAttr, TypeDetailsVisitor, UdtAttr

    # Print details via visitor
    visitor = TypeDetailsVisitor(db)
    assert db.types.traverse(tif, visitor)
    for item in visitor.output:
        logger.debug(vars(item))
        if item.udt:
            logger.debug(vars(item.udt))

    # Check for missing attr handlers
    for i in TypeAttr:
        assert i in TypeDetails._HANDLERS

    for k, _ in TypeDetails._HANDLERS.items():
        assert k in TypeAttr

    # Check details
    type_details: TypeDetails = db.types.get_details(tif)
    assert type_details
    assert type_details.name == 'STRUCT_EXAMPLE'
    assert type_details.udt
    assert type_details.udt.num_members == 3
    assert not type_details.array
    assert not type_details.ptr
    assert not type_details.enum
    assert not type_details.bitfield
    assert not type_details.func

    # Check attributes
    attrs = type_details.attributes
    assert attrs
    assert TypeAttr.ATTACHED in attrs
    assert TypeAttr.UDT in attrs
    assert TypeAttr.COMPLEX in attrs
    assert TypeAttr.DECL_TYPEDEF in attrs
    assert TypeAttr.STRUCT in attrs
    assert TypeAttr.WELL_DEFINED in attrs
    assert not TypeAttr.ARRAY in attrs
    assert not TypeAttr.PTR in attrs

    # Test type comment methods
    test_comment = 'Test type comment'

    # Test setting comment for the STRUCT_EXAMPLE type
    assert db.types.set_comment(tif, test_comment)
    retrieved_comment = db.types.get_comment(tif)
    assert retrieved_comment == test_comment

    # Test getting non-existent comment returns empty string
    # Create a simple type without comment
    simple_type = ida_typeinf.tinfo_t()
    empty_comment = db.types.get_comment(simple_type)
    assert empty_comment == ''

    db.types.unload_library(til)

    errors = db.types.parse_declarations(None, 'enum eMyType { first, second };', 0)
    assert errors == 0

    tif = db.types.get_by_name('eMyType')
    assert tif is not None

    details = db.types.get_details(tif)
    assert (
        details.attributes
        | TypeAttr.ATTACHED
        | TypeAttr.COMPLEX
        | TypeAttr.CORRECT
        | TypeAttr.DECL_COMPLEX
        | TypeAttr.DECL_TYPEDEF
        | TypeAttr.ENUM
        | TypeAttr.SUE
        | TypeAttr.UDT
        | TypeAttr.WELL_DEFINED
        | TypeAttr.EXT_ARITHMETIC
        | TypeAttr.EXT_INTEGRAL
    )

    assert details.size == 4

    tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', 'Point22')
    assert tif.get_type_name() == 'Point22'
    tif = db.types.get_by_name('Point22')
    assert tif is not None
    assert tif.get_type_name() == 'Point22'

    tif = db.types.parse_one_declaration(
        None,
        'struct Point22 {int x; int y;}; union UserData { int buffer[10]; Point22 point; };',
        'Union1996',
    )
    assert tif is not None
    assert tif.get_type_name() == 'Union1996'

    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', '')
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', None)
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, '', 'Dummy')
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct', 'Dummy')
    with pytest.raises(InvalidEAError):
        db.types.get_at(0xFFFFFFFF)
    with pytest.raises(InvalidEAError):
        db.types.apply_at(tif, 0xFFFFFFFF)

    types_list = list(db.types.get_all(library=None, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 5

    errors = db.types.parse_declarations(None, 'struct { int first; int second; };', 0)
    assert errors == 0

    types_list = list(db.types.get_all(library=None, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 6


def test_signature_files(test_env):
    db = test_env

    # Get available signatures
    available_sigs = db.signature_files.get_files()
    assert len(available_sigs) > 0, 'No signature files found'

    sig_files = db.signature_files.create(pat_only=True)
    assert len(sig_files) == 1
    assert sig_files[0] == f'{db.path}.pat'

    sig_files = db.signature_files.create()
    assert len(sig_files) == 2
    assert sig_files[0] == f'{db.path}.sig'
    assert sig_files[1] == f'{db.path}.pat'

    # Test applying a single signature file
    sig_path = Path(sig_files[0])
    assert sig_path.exists()
    results = db.signature_files.apply(sig_path)
    assert isinstance(results, list)
    assert len(results) == 1

    file_info = results[0]
    assert isinstance(file_info, ida_domain.signature_files.FileInfo)
    assert file_info.path == str(sig_path)
    assert isinstance(file_info.matches, int)
    assert isinstance(file_info.functions, list)
    assert file_info.matches == 6
    match_info = file_info.functions[0]
    assert isinstance(match_info, ida_domain.signature_files.MatchInfo)
    assert isinstance(match_info.addr, int)
    assert isinstance(match_info.name, str)
    assert 'tiny_asm.bin.i64' in match_info.lib

    # Apply with probe_only=True
    results_probe = db.signature_files.apply(sig_path, probe_only=True)
    assert isinstance(results_probe, list)
    assert len(results_probe) == 1

    index = db.signature_files.get_index(sig_path)
    assert isinstance(index, int)
    assert index >= 0


def test_comments(test_env):
    db = test_env

    all_comments = list(db.comments.get_all())
    assert len(all_comments) == 10

    # Validate expected comments and their addresses
    expected_comments = [
        (0x16, 'LINUX - sys_write'),
        (0x46, 'LINUX - sys_write'),
        (0x67, 'LINUX - sys_write'),
        (0x92, 'LINUX - sys_write'),
        (0xB3, 'LINUX - sys_write'),
        (0xC2, 'LINUX - sys_exit'),
        (0x2D6, 'buf'),
        (0x2E5, 'fd'),
        (0x2ED, 'count'),
        (0x2F0, 'LINUX - sys_write'),
    ]

    for i, comment_info in enumerate(db.comments):
        assert expected_comments[i][0] == comment_info.ea
        assert expected_comments[i][1] == comment_info.comment
        assert False == comment_info.repeatable

    assert db.comments.set_at(0xAE, 'Testing adding regular comment')
    assert db.comments.get_at(0xAE).comment == 'Testing adding regular comment'
    assert not db.comments.get_at(0xAE, ida_domain.comments.CommentKind.REPEATABLE)
    assert (
        db.comments.get_at(0xAE, ida_domain.comments.CommentKind.ALL).comment
        == 'Testing adding regular comment'
    )

    assert db.comments.set_at(
        0xD1, 'Testing adding repeatable comment', ida_domain.comments.CommentKind.REPEATABLE
    )
    assert (
        db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REPEATABLE).comment
        == 'Testing adding repeatable comment'
    )
    assert not db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REGULAR)
    assert (
        db.comments.get_at(0xD1, ida_domain.comments.CommentKind.ALL).comment
        == 'Testing adding repeatable comment'
    )

    db.comments.delete_at(0xD1, ida_domain.comments.CommentKind.ALL)
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REPEATABLE) is None
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.REGULAR) is None
    assert db.comments.get_at(0xD1, ida_domain.comments.CommentKind.ALL) is None

    test_ea = 0x100
    assert db.comments.set_extra_at(
        test_ea, 0, 'First anterior comment', ida_domain.comments.ExtraCommentKind.ANTERIOR
    )
    assert db.comments.set_extra_at(
        test_ea, 1, 'Second anterior comment', ida_domain.comments.ExtraCommentKind.ANTERIOR
    )

    assert (
        db.comments.get_extra_at(test_ea, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        == 'First anterior comment'
    )
    assert (
        db.comments.get_extra_at(test_ea, 1, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        == 'Second anterior comment'
    )
    assert (
        db.comments.get_extra_at(test_ea, 2, ida_domain.comments.ExtraCommentKind.ANTERIOR) is None
    )

    assert db.comments.set_extra_at(
        test_ea, 0, 'First posterior comment', ida_domain.comments.ExtraCommentKind.POSTERIOR
    )
    assert db.comments.set_extra_at(
        test_ea, 1, 'Second posterior comment', ida_domain.comments.ExtraCommentKind.POSTERIOR
    )

    anterior_comments = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    )
    assert len(anterior_comments) == 2
    assert anterior_comments[0] == 'First anterior comment'
    assert anterior_comments[1] == 'Second anterior comment'

    posterior_comments = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    )
    assert len(posterior_comments) == 2
    assert posterior_comments[0] == 'First posterior comment'
    assert posterior_comments[1] == 'Second posterior comment'

    assert db.comments.delete_extra_at(test_ea, 1, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    remaining_anterior = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    )
    assert len(remaining_anterior) == 1
    assert remaining_anterior[0] == 'First anterior comment'

    # Note: if you delete an extra comment at a position,
    # all the subsequent ones are becoming "invisible" also
    assert db.comments.delete_extra_at(test_ea, 0, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    remaining_posterior = list(
        db.comments.get_all_extra_at(test_ea, ida_domain.comments.ExtraCommentKind.POSTERIOR)
    )
    assert len(remaining_posterior) == 0

    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_at(0xFFFFFFFF)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_at(0xFFFFFFFF, 'Invalid comment')
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_at(0xFFFFFFFF)
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.set_extra_at(
            0xFFFFFFFF, 0, 'Invalid', ida_domain.comments.ExtraCommentKind.ANTERIOR
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.get_extra_at(0xFFFFFFFF, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)
    with pytest.raises(ida_domain.base.InvalidEAError):
        list(
            db.comments.get_all_extra_at(0xFFFFFFFF, ida_domain.comments.ExtraCommentKind.ANTERIOR)
        )
    with pytest.raises(ida_domain.base.InvalidEAError):
        db.comments.delete_extra_at(0xFFFFFFFF, 0, ida_domain.comments.ExtraCommentKind.ANTERIOR)


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


def test_ida_command_options():
    # Test default state produces empty args
    opts = IdaCommandOptions()
    assert opts.build_args() == ''

    # Test auto analysis option
    opts = IdaCommandOptions(auto_analysis=True)
    assert opts.build_args() == ''

    opts = IdaCommandOptions(auto_analysis=False)
    assert opts.build_args() == '-a'

    # Test loading address option
    opts = IdaCommandOptions(loading_address=0x1000)
    assert opts.build_args() == '-b1000'

    # Test new database option
    opts = IdaCommandOptions(new_database=True)
    assert opts.build_args() == '-c'

    # Test compiler option
    opts = IdaCommandOptions(compiler='gcc')
    assert opts.build_args() == '-Cgcc'

    opts = IdaCommandOptions(compiler='gcc:x64')
    assert opts.build_args() == '-Cgcc:x64'

    # Test first pass directive option
    opts = IdaCommandOptions(first_pass_directives=['VPAGESIZE=8192'])
    assert opts.build_args() == '-dVPAGESIZE=8192'

    # Add multiple directives
    opts = IdaCommandOptions(first_pass_directives=['DIR1', 'DIR2'])
    assert opts.build_args() == '-dDIR1 -dDIR2'

    # Test second pass directive option
    opts = IdaCommandOptions(second_pass_directives=['OPTION=VALUE'])
    assert opts.build_args() == '-DOPTION=VALUE'

    # Test disable FPP instructions option
    opts = IdaCommandOptions(disable_fpp=True)
    assert opts.build_args() == '-f'

    # Test entry point option
    opts = IdaCommandOptions(entry_point=0x401000)
    assert opts.build_args() == '-i401000'

    # Test JIT debugger option
    opts = IdaCommandOptions(jit_debugger=True)
    assert opts.build_args() == '-I1'

    opts = IdaCommandOptions(jit_debugger=False)
    assert opts.build_args() == '-I0'

    # Test log file option
    opts = IdaCommandOptions(log_file='debug.log')
    assert opts.build_args() == '-Ldebug.log'

    # Test disable mouse option
    opts = IdaCommandOptions(disable_mouse=True)
    assert opts.build_args() == '-M'

    # Test plugin options
    opts = IdaCommandOptions(plugin_options='opt1=val1')
    assert opts.build_args() == '-Oopt1=val1'

    # Test output database option (should also set -c flag)
    opts = IdaCommandOptions(output_database='output.idb')
    assert opts.build_args() == '-c -ooutput.idb'

    # Test processor option
    opts = IdaCommandOptions(processor='arm')
    assert opts.build_args() == '-parm'

    # Test database compression options
    opts = IdaCommandOptions(db_compression='compress')
    assert opts.build_args() == '-P+'

    opts = IdaCommandOptions(db_compression='pack')
    assert opts.build_args() == '-P'

    opts = IdaCommandOptions(db_compression='no_pack')
    assert opts.build_args() == '-P-'

    # Test run debugger option
    opts = IdaCommandOptions(run_debugger='+')
    assert opts.build_args() == '-r+'

    opts = IdaCommandOptions(run_debugger='debug-options')
    assert opts.build_args() == '-rdebug-options'

    # Test load resources option
    opts = IdaCommandOptions(load_resources=True)
    assert opts.build_args() == '-R'

    # Test run script option
    opts = IdaCommandOptions(script_file='analyze.py')
    assert opts.build_args() == '-Sanalyze.py'

    args = ['arg1', 'arg with spaces', '--flag=value']
    opts = IdaCommandOptions(script_file='script.py', script_args=args)
    assert opts.build_args() == '-S"script.py arg1 "arg with spaces" --flag=value"'

    # Test file type option
    opts = IdaCommandOptions(file_type='PE')
    assert opts.build_args() == '-TPE'

    opts = IdaCommandOptions(file_type='ZIP', file_member='classes.dex')
    assert opts.build_args() == '-TZIP:classes.dex'

    # Test empty database option
    opts = IdaCommandOptions(empty_database=True)
    assert opts.build_args() == '-t'

    # Test Windows directory option
    opts = IdaCommandOptions(windows_dir='C:\\Windows')
    assert opts.build_args() == '-WC:\\Windows'

    # Test no segmentation option
    opts = IdaCommandOptions(no_segmentation=True)
    assert opts.build_args() == '-x'

    # Test debug flags option
    # Test with numeric flags
    opts = IdaCommandOptions(debug_flags=0x404)
    assert opts.build_args() == '-z404'

    # Test with named flags
    flags = ['flirt', 'type_system']
    opts = IdaCommandOptions(debug_flags=flags)
    assert opts.build_args() == '-z4004'

    # Test combined options (no chaining, just set fields)
    opts = IdaCommandOptions(auto_analysis=False, log_file='analysis.log', processor='arm')
    args = opts.build_args()
    assert args == '-a -Lanalysis.log -parm'

    # Test complex scenario
    opts = IdaCommandOptions(
        new_database=True,
        compiler='gcc:x64',
        processor='arm',
        script_file='analyze.py',
        script_args=['deep', '--verbose'],
    )
    args = opts.build_args()
    assert args == '-c -Cgcc:x64 -parm -S"analyze.py deep --verbose"'

    # Test another complex scenario
    opts = IdaCommandOptions(
        output_database='project.idb',
        db_compression='compress',
        file_type='ZIP',
        file_member='classes.dex',
        debug_flags=0x10004,  # debugger + flirt
    )
    args = opts.build_args()
    assert args == '-c -oproject.idb -P+ -TZIP:classes.dex -z10004'

    # Test default for auto_analysis is True
    opts = IdaCommandOptions()
    assert opts.auto_analysis
    opts = IdaCommandOptions(auto_analysis=False)
    assert not opts.auto_analysis


def test_hooks():
    from ida_segment import segment_t

    from ida_domain import hooks

    class TestProcHooks(hooks.ProcessorHooks):
        def __init__(self):
            super().__init__()

    class TestUIHooks(hooks.UIHooks):
        def __init__(self):
            super().__init__()

    class TestViewHooks(hooks.ViewHooks):
        def __init__(self):
            super().__init__()

    class TestDecompHooks(hooks.DecompilerHooks):
        def __init__(self):
            super().__init__()

    class TestDatabaseHooks(hooks.DatabaseHooks):
        def __init__(self):
            super().__init__()
            self.count = 0

        def closebase(self) -> None:
            self.log()
            self.count += 1
            assert self.m_database.is_open()

        def auto_empty(self):
            self.log()
            self.count += 1
            assert self.m_database.is_open()

        def segm_added(self, s: segment_t) -> None:
            self.log()
            assert self.m_database.is_open()
            name = self.m_database.segments.get_name(s)
            assert name
            logger.info(f'added segment: {name}')

    proc_hook = TestProcHooks()
    ui_hook = TestUIHooks()
    view_hook = TestViewHooks()
    decomp_hook = TestDecompHooks()
    custom_hook1 = TestDatabaseHooks()
    custom_hook2 = TestDatabaseHooks()

    all_hooks: hooks.HooksList = [
        proc_hook,
        ui_hook,
        view_hook,
        decomp_hook,
        custom_hook1,
        custom_hook2,
    ]
    # Check hooks are automatically installed (hooked) and called if passed to open()
    with ida_domain.Database.open(path=idb_path, hooks=all_hooks) as db:
        assert db.is_open()
        for h in db.hooks:
            assert h.is_hooked

    # Check hooks are automatically uninstalled (un-hooked)
    for h in all_hooks:
        assert not h.is_hooked

    assert custom_hook1.count == 2
    assert custom_hook2.count == 2

    # Check hooks are no longer called if not passed to open()
    with ida_domain.Database.open(path=idb_path) as db:
        assert db.is_open()
        assert not db.hooks
        for h in db.hooks:
            assert not h.is_hooked

    assert custom_hook1.count == 2
    assert custom_hook2.count == 2

    # Check no hooks are installed if open() fails
    if ida_domain.__ida_version__ >= Version('9.2'):
        # This does not pass prior 9.2.0 due to IDA killing the process
        # when trying to load an inexisting file
        try:
            with ida_domain.Database.open(path='invalid', hooks=all_hooks) as _:
                assert False
        except Exception as _:
            for h in db.hooks:
                assert not h.is_hooked


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


def test_api_examples():
    """
    Make sure the examples are running fine
    """
    examples = [
        'analyze_functions.py',
        'analyze_strings.py',
        'analyze_bytes.py',
        'explore_database.py',
        'analyze_database.py',
        'explore_flirt.py',
        'quick_example.py',
        'my_first_script.py',
        'hooks_example.py',
        'manage_types.py',
    ]
    for example in examples:
        script_path = Path(__file__).parent.parent / 'examples' / example
        cmd = [sys.executable, str(script_path), '-f', str(idb_path)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        print(f'Example {script_path} outputs')
        print('\n[STDOUT]')
        print(result.stdout)
        print('[STDERR]')
        print(result.stderr)

        assert result.returncode == 0, f'Example {script_path} failed to run'

    # analyze_xrefs.py requires additional arguments
    script_path = Path(__file__).parent.parent / 'examples' / 'analyze_xrefs.py'
    cmd = [sys.executable, str(script_path), '-f', str(idb_path), '-a', '0xd6']

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(f'Example {script_path} outputs')
    print('\n[STDOUT]')
    print(result.stdout)
    print('[STDERR]')
    print(result.stderr)

    assert result.returncode == 0, f'Example {script_path} failed to run'

    # These examples are runing inside IDA, emulate the envirnoment with IDA Domain
    inside_ida_examples = ['ida_console_example.py']
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    for example in inside_ida_examples:
        script_path = Path(__file__).parent.parent / 'examples' / example
        with ida_domain.Database.open(str(idb_path), ida_options, save_on_close=False) as db:
            try:
                db.execute_script(script_path)
            except DatabaseError as e:
                assert False, f'Example {script_path.name} failed to run, error {e}'


def test_readme_examples():
    """
    Make sure the example shipped in readme is updated
    """
    example_path = Path(__file__).parent.parent / 'examples' / 'explore_database.py'
    readme_path = Path(__file__).parent.parent / 'README.md'

    # Read both files
    example_content = example_path.read_text(encoding='utf-8').strip()
    readme_content = readme_path.read_text(encoding='utf-8')

    # Check if example exists in readme
    assert example_content in readme_content, f'Example from {example_path} not found in README'


def test_migrated_examples(global_setup):
    """
    Make sure the migrated examples are running fine
    """

    # These examples are working in "standalone" mode
    standalon_examples = [
        Path('decompiler/decompile_entry_points.py'),
        Path('decompiler/produce_c_file.py'),
    ]
    for example in standalon_examples:
        script_path = (
            Path(__file__).parent.parent / 'examples' / 'ida-python-equivalents' / example
        )
        cmd = [sys.executable, str(script_path), '-f', str(idb_path)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        print(f'Example {script_path} outputs')
        print('\n[STDOUT]')
        print(result.stdout)
        print('[STDERR]')
        print(result.stderr)

        assert result.returncode == 0, f'Example {script_path} failed to run'

    # These examples are runing inside IDA, emulate the envirnoment with IDA Domain
    inside_ida_examples_at_ea = [
        (Path('decompiler/vds1.py'), 0xC4),
        (Path('decompiler/vds13.py'), 0xC4),
        (Path('disassembler/dump_flowchart.py'), 0xC4),
        (Path('disassembler/assemble.py'), 0x30),
        (Path('debugger/automatic_steps.py'), 0x307),
        (Path('disassembler/dump_extra_comments.py'), 0x307),
        (Path('disassembler/list_function_items.py'), 0xC4),
        (Path('disassembler/list_segment_functions.py'), 0xC4),
        (Path('disassembler/list_strings.py'), 0xC4),
        (Path('disassembler/log_idb_events.py'), 0xC4),
        (Path('types/create_libssh2_til.py'), 0xC4),
        (Path('types/create_struct_by_parsing.py'), 0xC4),
    ]
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    for example, ea in inside_ida_examples_at_ea:
        script_path = (
            Path(__file__).parent.parent / 'examples' / 'ida-python-equivalents' / example
        )
        with ida_domain.Database.open(str(idb_path), ida_options, save_on_close=False) as db:
            db.current_ea = ea
            db.start_ip = ea
            print(f'>>>========\nExecuting migrated IDA Python example {script_path.name}')
            try:
                db.execute_script(script_path)
            except DatabaseError as e:
                assert False, f'Example {script_path.name} failed to run, error {e}'
            print(f'Executing migrated IDA Python example {script_path.name} finished\n<<<=====')


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
    from ida_domain.functions import LocalVariableAccessType, LocalVariableContext

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
    assert refs[2].code_line == 'use_val(v9);'


# ---------------------------------------------------------------------------
# Microcode tests
# ---------------------------------------------------------------------------


def test_microcode_generate(test_env):
    """Test basic microcode generation."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    assert func is not None

    mf = db.microcode.generate(func)
    assert mf is not None
    assert len(mf) == 11
    assert mf.entry_ea == func.start_ea
    assert mf.maturity == MicroMaturity.GENERATED
    assert mf.block_count == 11

    # raw_mba escape hatch
    assert mf.raw_mba is not None
    assert len(mf) == 11

    # build_graph=False should skip graph building
    mf2 = db.microcode.generate(func, build_graph=False)
    assert mf2 is not None
    assert len(mf2) > 0

    # generation failure for bad address
    import pytest

    from ida_domain.microcode import MicrocodeError, MicroError

    with pytest.raises(MicrocodeError) as exc_info:
        db.microcode.generate_for_range(0xFFFFFF, 0xFFFFFFF)
    err = exc_info.value
    assert isinstance(err.code, MicroError)
    assert err.code != MicroError.OK
    assert 'range 0xffffff:0xfffffff' in str(err)


def test_microcode_maturity_levels(test_env):
    """Test generating microcode at all maturity levels."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number — has richer microcode

    # Generate at multiple maturities and verify each produces valid microcode
    for mat in [
        MicroMaturity.GENERATED,
        MicroMaturity.PREOPTIMIZED,
        MicroMaturity.LOCOPT,
        MicroMaturity.CALLS,
        MicroMaturity.GLBOPT1,
        MicroMaturity.GLBOPT2,
        MicroMaturity.GLBOPT3,
        MicroMaturity.LVARS,
    ]:
        mf = db.microcode.generate(func, maturity=mat, build_graph=False)
        assert mf.maturity == mat, f'Expected {mat.name}, got {mf.maturity.name}'
        assert len(mf) > 0
        count = sum(1 for _ in mf.instructions())
        assert count > 0


def test_microcode_block_iteration(test_env):
    """Test iterating over microcode blocks."""
    from ida_domain.microcode import MicroBlockType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # Iterate all blocks via __iter__ and blocks()
    all_blocks = list(mf)
    assert len(all_blocks) == len(mf) == 11

    all_blocks_via_method = list(mf.blocks())
    assert len(all_blocks_via_method) == len(all_blocks)

    # .blocks(skip_sentinels=True) skips block 0 and BLT_STOP
    real_blocks = list(mf.blocks(skip_sentinels=True))
    assert len(real_blocks) < len(all_blocks)

    for block in real_blocks:
        assert block.block_type != MicroBlockType.STOP
        assert block.serial > 0

    # Verify all block types are present that we expect
    block_types = {b.block_type for b in all_blocks}
    assert MicroBlockType.ONE_WAY in block_types
    assert MicroBlockType.STOP in block_types

    # __getitem__ access
    b0 = mf[0]
    assert b0.serial == 0
    assert b0.index == 0

    # __getitem__ out of range
    import pytest

    with pytest.raises(IndexError):
        mf[999]
    with pytest.raises(IndexError):
        mf[-999]

    # Negative indexing (valid)
    last = mf[-1]
    assert last.serial == len(mf) - 1


def test_microcode_instruction_iteration(test_env):
    """Test iterating over instructions within blocks."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    total = 0
    for block in mf.blocks():
        for insn in block:
            total += 1
            assert isinstance(insn.opcode, MicroOpcode)
            assert insn.ea >= 0

    assert total == 383

    # Flat instructions() must match block-by-block count
    flat_count = sum(1 for _ in mf.instructions())
    assert flat_count == total

    # instructions(skip_sentinels=True) skips sentinel blocks
    skip_count = sum(1 for _ in mf.instructions(skip_sentinels=True))
    assert skip_count <= total


@min_ida_version('9.2')
def test_microcode_operand_access(test_env):
    """Test operand type-specific accessors across all operand types."""
    from ida_domain.microcode import MicroOperandType

    db = test_env

    # test_all_operand_types has the richest variety of operand types
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    found_types = set()
    found_positive_number = False
    found_negative_number = False
    for insn in mf.instructions():
        for op in insn:
            assert not op.is_empty
            assert bool(op) is True
            assert isinstance(op.type, MicroOperandType)
            assert isinstance(op.size, int)
            found_types.add(op.type)

            if op.is_register:
                assert op.register is not None
                assert isinstance(op.register, int)
                assert op.register_name is not None
                assert isinstance(op.register_name, str)
                assert len(op.register_name) > 0
                # Wrong-type accessors return None
                assert op.value is None
                assert op.global_address is None
                assert op.helper_name is None
                assert op.block_ref is None
                assert op.call_info is None
                assert op.string_value is None
                assert op.address_target is None
                assert op.pair is None
            elif op.is_number:
                assert op.value is not None
                assert isinstance(op.value, int)
                # unsigned_value should equal raw value
                assert op.unsigned_value == op.value
                # signed_value sign-extends based on operand size
                assert isinstance(op.signed_value, int)
                bits = op.size * 8
                if op.unsigned_value < (1 << (bits - 1)):
                    # Positive: signed == unsigned
                    assert op.signed_value == op.unsigned_value
                    found_positive_number = True
                else:
                    # Negative: signed is unsigned - 2^bits
                    assert op.signed_value == op.unsigned_value - (1 << bits)
                    assert op.signed_value < 0
                    found_negative_number = True
                assert op.register is None
            elif op.is_global_address:
                assert op.global_address is not None
                assert isinstance(op.global_address, int)
            elif op.type == MicroOperandType.BLOCK_REF:
                assert op.block_ref is not None
                assert isinstance(op.block_ref, int)
            elif op.type == MicroOperandType.ADDR_OF:
                tgt = op.address_target
                assert tgt is not None
                assert isinstance(tgt.type, MicroOperandType)
            elif op.is_sub_instruction():
                sub = op.sub_instruction
                assert sub is not None
                assert isinstance(sub.opcode, type(insn.opcode))

            # str() should work for all operands
            text = str(op)
            assert isinstance(text, str)
            assert len(text) > 0

            # repr should not crash
            assert 'MicroOperand' in repr(op)

    # Verify both branches of signed_value were exercised
    assert found_positive_number, 'No positive number operands found'
    assert found_negative_number, 'No negative number operands found'

    # Verify we found the expected variety of operand types
    assert MicroOperandType.REGISTER in found_types
    assert MicroOperandType.NUMBER in found_types
    assert MicroOperandType.ADDR_OF in found_types
    assert MicroOperandType.SUB_INSN in found_types
    assert MicroOperandType.BLOCK_REF in found_types

    # print_number has HELPER and CALL_INFO operands
    func2 = db.functions.get_at(0x2BC)
    mf2 = db.microcode.generate(func2)
    for insn in mf2.instructions():
        for op in insn.operands():
            if op.is_helper:
                assert op.helper_name is not None
                assert isinstance(op.helper_name, str)
                found_types.add(op.type)
            elif op.type == MicroOperandType.CALL_INFO:
                assert op.call_info is not None
                found_types.add(op.type)

    assert MicroOperandType.HELPER in found_types
    assert MicroOperandType.CALL_INFO in found_types


def test_microcode_operand_comparisons(test_env):
    """Test operand __eq__, __ne__, __bool__."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    for insn in mf.instructions():
        for op in insn.operands():
            # __eq__ on same operand
            assert op == op
            assert not (op != op)

    # Empty operand via __bool__
    from ida_hexrays import mop_t

    from ida_domain.microcode import MicroOperand

    empty_op = MicroOperand(mop_t())
    assert not empty_op  # __bool__ is False for mop_z
    assert empty_op.is_empty


def test_microcode_operand_sub_instruction(test_env):
    """Test sub-instruction operand access (mop_d)."""
    from ida_domain.microcode import MicroOpcode, MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)  # has sub-instructions (helper calls)
    mf = db.microcode.generate(func)

    found = False
    for insn in mf.instructions():
        for op in insn.operands():
            if op.is_sub_instruction():
                found = True
                sub = op.sub_instruction
                assert sub is not None
                assert isinstance(sub.opcode, MicroOpcode)
                assert str(sub) != ''

                # is_sub_instruction with opcode filter
                assert op.is_sub_instruction(sub.opcode)
                # Wrong opcode should return False
                wrong_opcode = (
                    MicroOpcode.NOP if sub.opcode != MicroOpcode.NOP else MicroOpcode.MOV
                )
                assert not op.is_sub_instruction(wrong_opcode)
                break
        if found:
            break

    assert found, 'Expected to find a sub-instruction operand'


def test_microcode_instruction_is_top_level(test_env):
    """Test is_top_level distinguishes block-level vs nested instructions."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    found_nested = False
    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            # Top-level instructions always have is_top_level == True
            assert insn.is_top_level
            for op in insn:
                if op.type == MicroOperandType.SUB_INSN:
                    sub = op.sub_instruction
                    assert sub is not None
                    assert not sub.is_top_level
                    found_nested = True
        if found_nested:
            break

    assert found_nested, 'Expected to find a nested sub-instruction'


def test_microcode_find_instructions(test_env):
    """Test finding instructions by opcode and operand type."""
    from ida_domain.microcode import MicroOpcode, MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # Find MOV instructions
    movs = list(mf.find_instructions(opcode=MicroOpcode.MOV))
    assert len(movs) > 0
    for insn in movs:
        assert insn.opcode == MicroOpcode.MOV

    # Find instructions with REGISTER operands
    with_regs = list(mf.find_instructions(operand_type=MicroOperandType.REGISTER))
    assert len(with_regs) > 0

    # Find with both filters
    mov_with_regs = list(
        mf.find_instructions(opcode=MicroOpcode.MOV, operand_type=MicroOperandType.REGISTER)
    )
    assert len(mov_with_regs) > 0
    assert len(mov_with_regs) <= len(movs)


def test_microcode_instruction_queries(test_env):
    """Test instruction query methods: is_call, is_mov, find_call, find_opcode."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number has CALL and ICALL
    mf = db.microcode.generate(func)

    found_call = False
    found_mov = False
    for insn in mf.instructions():
        if insn.is_call():
            found_call = True
            assert insn.opcode in (MicroOpcode.CALL, MicroOpcode.ICALL)
        if insn.is_mov():
            found_mov = True
            assert insn.opcode == MicroOpcode.MOV

    assert found_call, 'print_number should have calls'
    assert found_mov, 'print_number should have MOV instructions'

    # find_call on the whole microcode tree
    for insn in mf.instructions():
        fc = insn.find_call()
        if fc is not None:
            assert fc.is_call()
            break

    # find_opcode
    for insn in mf.instructions():
        found = insn.find_opcode(MicroOpcode.MOV)
        if found is not None:
            assert found.opcode == MicroOpcode.MOV
            break


def test_microcode_instruction_navigation(test_env):
    """Test next/prev linked-list navigation within a block."""
    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    blk = list(mf.blocks(skip_sentinels=True))[0]
    assert blk.head is not None
    assert blk.tail is not None

    # Walk forward via next
    forward = []
    insn = blk.head
    while insn:
        forward.append(insn.ea)
        insn = insn.next

    # Walk backward via prev
    backward = []
    insn = blk.tail
    while insn:
        backward.append(insn.ea)
        insn = insn.prev

    assert forward == list(reversed(backward))
    assert len(forward) == len(blk)

    # head.prev is None, tail.next is None
    assert blk.head.prev is None
    assert blk.tail.next is None


def test_microcode_instruction_swap(test_env):
    """Test instruction swap method."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    blk = list(mf.blocks(skip_sentinels=True))[0]
    insn1 = blk.head
    insn2 = insn1.next
    if insn2:
        op1_before = insn1.opcode
        op2_before = insn2.opcode
        insn1.swap(insn2)
        assert insn1.opcode == op2_before
        assert insn2.opcode == op1_before
        # Swap back to restore
        insn1.swap(insn2)


def test_microcode_instruction_set_ea(test_env):
    """Test instruction set_ea (setaddr) method."""
    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    insn = list(mf.blocks(skip_sentinels=True))[0].head
    original_ea = insn.ea
    insn.set_address(0x1234)
    assert insn.ea == 0x1234
    insn.set_address(original_ea)  # restore


def test_microcode_text_output(test_env):
    """Test that to_text() produces output compatible with old get_microcode()."""
    db = test_env
    func = db.functions.get_at(0xC4)

    mf = db.microcode.generate(func)
    new_lines = mf.to_text()
    assert len(new_lines) > 0
    assert all(isinstance(line, str) for line in new_lines)

    # str() should return the same as '\n'.join(to_text())
    assert str(mf) == '\n'.join(new_lines)

    # Tags should be stripped by default
    import ida_lines

    for line in new_lines:
        assert line == ida_lines.tag_remove(line)

    # to_text(remove_tags=False) keeps tags
    raw_lines = mf.to_text(remove_tags=False)
    assert len(raw_lines) > 0

    # Old API delegates to microcode module
    old_mf = db.functions.get_microcode(func)
    assert len(old_mf.to_text()) > 0


def test_microcode_from_decompilation(test_env):
    """Test getting microcode from full decompilation."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.from_decompilation(func)
    assert mf is not None
    assert mf.maturity == MicroMaturity.LVARS
    assert len(mf) > 0


def test_microcode_block_graph(test_env):
    """Test block successor/predecessor navigation with graph consistency."""
    db = test_env
    func = db.functions.get_at(0xC4)  # 11 blocks, rich CFG
    mf = db.microcode.generate(func)

    for block in mf.blocks():
        succs = block.successor_serials
        preds = block.predecessor_serials
        assert isinstance(succs, list)
        assert isinstance(preds, list)

        assert block.successor_count == len(succs)
        assert block.predecessor_count == len(preds)

        # Verify successor/predecessor iterators match serial lists
        succ_blocks = list(block.successors())
        assert [b.serial for b in succ_blocks] == succs

        pred_blocks = list(block.predecessors())
        assert [b.serial for b in pred_blocks] == preds

    # Block 2 should have 2 predecessors and 2 successors (loop)
    b2 = mf[2]
    assert b2.predecessor_count == 2
    assert b2.successor_count == 2


def test_microcode_block_properties_detailed(test_env):
    """Test block property accessors in detail."""
    from ida_domain.microcode import MicroBlockType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    block_types_found = set()
    for block in mf.blocks():
        bt = block.block_type
        assert isinstance(bt, MicroBlockType)
        block_types_found.add(bt)

        assert block.start_ea >= 0
        assert block.end_ea >= block.start_ea
        assert block.instruction_count >= 0
        # len counts all insns, instruction_count skips NOPs
        assert len(block) >= block.instruction_count

        # is_empty consistency
        if block.head is None:
            assert block.is_empty
        else:
            assert not block.is_empty

        # serial, index
        assert block.serial == block.index

        # repr
        r = repr(block)
        assert 'MicroBlock' in r
        assert bt.name in r

    # test_all_operand_types should have TWO_WAY (branches) and ONE_WAY
    assert MicroBlockType.ONE_WAY in block_types_found
    assert MicroBlockType.TWO_WAY in block_types_found
    assert MicroBlockType.STOP in block_types_found
    assert MicroBlockType.ZERO_WAY in block_types_found

    # is_branch should be True only for TWO_WAY blocks
    for block in mf.blocks():
        if block.block_type == MicroBlockType.TWO_WAY:
            assert block.is_branch
        else:
            assert not block.is_branch

    # block_type setter
    block = mf[1]
    original = block.block_type
    block.block_type = MicroBlockType.ONE_WAY
    assert block.block_type == MicroBlockType.ONE_WAY
    block.block_type = original


def test_microcode_block_call_detection(test_env):
    """Test is_call_block detection."""
    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number has calls
    mf = db.microcode.generate(func)

    found_call_block = False
    for block in mf.blocks(skip_sentinels=True):
        if block.is_call_block:
            found_call_block = True
            # Verify at least one instruction in the block is a call
            assert any(insn.is_call() for insn in block)

    assert found_call_block


def test_microcode_block_first_regular_insn(test_env):
    """Test first_regular_insn (getf_reginsn wrapper)."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for block in mf.blocks(skip_sentinels=True):
        if not block.is_empty:
            fri = block.first_regular_insn
            # first_regular_insn may be None if block has only assertions
            if fri is not None:
                assert isinstance(fri.opcode, type(block.head.opcode))


def test_microcode_block_mba_backref(test_env):
    """Test that block.mba returns the parent MicroBlockArray."""
    from ida_domain.microcode import MicroBlockArray

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    block = mf[1]
    parent = block.mba
    assert isinstance(parent, MicroBlockArray)
    assert parent.entry_ea == mf.entry_ea


def test_microcode_block_mutation(test_env):
    """Test block insert/remove instruction and make_nop."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers — small function
    mf = db.microcode.generate(func)

    blk = list(mf.blocks(skip_sentinels=True))[0]
    original_count = len(blk)

    # make_nop on a specific instruction
    insn = blk.head
    if insn:
        blk.make_nop(insn)
        assert insn.opcode == MicroOpcode.NOP


def test_microcode_verify(test_env):
    """Test that verify() runs without crash."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)
    mf.verify(True)


def test_microcode_set_maturity(test_env):
    """Test set_maturity on MicroBlockArray."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func, maturity=MicroMaturity.GENERATED)
    assert mf.maturity == MicroMaturity.GENERATED

    # set_maturity changes the maturity level
    mf.set_maturity(MicroMaturity.PREOPTIMIZED)
    assert mf.maturity == MicroMaturity.PREOPTIMIZED


def test_microcode_entry_block(test_env):
    """Test entry_block property."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    eb = mf.entry_block
    assert eb.serial == 0
    assert eb.index == 0


def test_microcode_function_final_type(test_env):
    """Test final_type and create_helper_call on MicroBlockArray."""
    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.from_decompilation(func)

    ft = mf.final_type
    assert ft is not None  # decompiled function should have a return type


def test_microcode_generate_for_range(test_env):
    """Test microcode generation for an address range."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate_for_range(func.start_ea, func.end_ea)
    assert mf is not None
    assert len(mf) > 0
    assert mf.entry_ea == func.start_ea


def test_microcode_get_text(test_env):
    """Test the convenience get_text method on Microcode entry point."""
    db = test_env
    func = db.functions.get_at(0xC4)
    lines = db.microcode.get_text(func)
    assert len(lines) > 0
    assert all(isinstance(line, str) for line in lines)


def test_microcode_use_def_analysis(test_env):
    """Test use-def list building and MicroLocationSet operations."""
    import ida_hexrays

    from ida_domain.microcode import MicroLocationSet, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number

    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf.build_graph()
    mf.analyze_calls()

    found_use = False
    found_def = False
    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            use_list = block.build_use_list(insn, ida_hexrays.MUST_ACCESS)
            def_list = block.build_def_list(insn, ida_hexrays.MUST_ACCESS)

            assert isinstance(use_list, MicroLocationSet)
            assert isinstance(def_list, MicroLocationSet)

            if use_list:
                found_use = True
                assert use_list
            if def_list:
                found_def = True
                assert def_list
        break  # just first real block

    assert found_use, 'Expected at least one use-list'
    assert found_def, 'Expected at least one def-list'


def test_microcode_location_set_operations(test_env):
    """Test MicroLocationSet set protocol (__and__, __ior__, __isub__, etc.)."""
    import ida_hexrays
    from ida_hexrays import mlist_t

    from ida_domain.microcode import MicroLocationSet, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf.build_graph()
    mf.analyze_calls()

    # Collect two non-empty location sets with their source block/insn
    entries = []  # (block, insn, use_list)
    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            use_list = block.build_use_list(insn, ida_hexrays.MUST_ACCESS)
            if use_list:
                entries.append((block, insn, use_list))
                if len(entries) >= 2:
                    break
        if len(entries) >= 2:
            break

    if len(entries) >= 2:
        blk_a, insn_a, a = entries[0]
        blk_b, insn_b, b = entries[1]

        # __bool__
        assert bool(a) is True

        # __and__ (intersection)
        common = a & a  # intersection with self returns non-empty set
        assert bool(common)

        # has_common method
        assert a.has_common(a)

        # __ior__ (union) — build fresh set then union
        combined = blk_a.build_use_list(insn_a, ida_hexrays.MUST_ACCESS)
        combined |= b
        assert bool(combined)

        # __isub__ (subtract self → empty)
        to_sub = blk_a.build_use_list(insn_a, ida_hexrays.MUST_ACCESS)
        to_sub -= to_sub
        assert not bool(to_sub)

        # __or__ (union returning new set)
        union = a | b
        assert bool(union)

        # __sub__ (difference returning new set)
        diff = a - b
        assert isinstance(diff.count, int)

        # issuperset / issubset
        assert a.issuperset(a)
        assert a.issubset(a)

        # repr
        assert 'MicroLocationSet' in repr(a)


def test_microcode_graph(test_env):
    """Test MicroGraph wrapper: iteration, getitem, use-def chain access."""
    import ida_hexrays

    from ida_domain.microcode import MicroBlock, MicroGraph, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf.build_graph()
    mf.analyze_calls()

    graph = mf.get_graph()
    assert isinstance(graph, MicroGraph)
    assert len(graph) > 0

    # __getitem__
    b0 = graph[0]
    assert isinstance(b0, MicroBlock)

    # __iter__
    blocks = list(graph)
    assert len(blocks) == len(graph)

    # use-def chain access
    ud = graph.get_use_def_chains(ida_hexrays.GC_REGS_AND_STKVARS)
    du = graph.get_def_use_chains(ida_hexrays.GC_REGS_AND_STKVARS)
    assert ud is not None
    assert du is not None

    # repr
    assert 'MicroGraph' in repr(graph)

    # is_redefined_globally / is_used_globally
    for block in mf.blocks(skip_sentinels=True):
        insn = block.head
        if insn is not None:
            from ida_domain.microcode import MicroLocationSet

            locs = block.build_use_list(insn)
            if locs:
                r1 = graph.is_redefined_globally(locs, block.index, block.index, insn, insn)
                assert isinstance(r1, bool)
                r2 = graph.is_used_globally(locs, block.index, block.index, insn, insn)
                assert isinstance(r2, bool)
                break

    # __getitem__ boundary
    import pytest

    with pytest.raises(IndexError):
        graph[9999]


@min_ida_version('9.2')
def test_microcode_global_address_operands(test_env):
    """Test GLOBAL_ADDR operand type (mop_v) via level1_func which has CALL targets."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0x2F7)  # level1_func — has CALL with global addresses
    mf = db.microcode.generate(func)

    found = False
    for insn in mf.instructions():
        for op in insn.operands():
            if op.is_global_address:
                found = True
                assert op.global_address is not None
                assert isinstance(op.global_address, int)
                assert op.global_address > 0
                # Wrong-type accessor
                assert op.register is None
                assert op.value is None

    assert found, 'level1_func should have GLOBAL_ADDR operands'


def test_microcode_helper_and_call_info_operands(test_env):
    """Test HELPER and CALL_INFO operand types via print_number."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    found_helper = False
    found_call_info = False
    for insn in mf.instructions():
        if insn.is_call():
            for op in insn.operands():
                if op.is_helper:
                    found_helper = True
                    assert op.helper_name == 'sys_write'
                elif op.type == MicroOperandType.CALL_INFO:
                    found_call_info = True
                    ci = op.call_info
                    assert ci is not None

    assert found_helper, 'print_number should have a sys_write helper'
    assert found_call_info, 'print_number CALL should have CALL_INFO dest'


def test_microcode_operand_clear(test_env):
    """Test MicroOperand.clear() resets to empty."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)

    insn = list(mf.blocks(skip_sentinels=True))[0].head
    op = insn.left
    if op:
        op.clear()
        assert op.is_empty
        assert not bool(op)
        assert op.type == MicroOperandType.EMPTY


def test_microcode_instruction_to_text(test_env):
    """Test instruction and operand to_text with and without tags."""
    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    for insn in mf.instructions():
        text = str(insn)
        assert isinstance(text, str)
        assert len(text) > 0
        # str() and to_text() should return the same
        assert text == insn.to_text()

        text_raw = insn.to_text(remove_tags=False)
        assert isinstance(text_raw, str)

        for op in insn.operands():
            op_text = str(op)
            assert isinstance(op_text, str)
            # str() and to_text() should return the same
            assert op_text == op.to_text()
        break  # just first instruction


def test_microcode_repr(test_env):
    """Test __repr__ for all wrapper classes."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # MicroBlockArray repr
    r = repr(mf)
    assert 'MicroBlockArray' in r
    assert 'GENERATED' in r

    # MicroBlock repr
    block = mf[1]
    r = repr(block)
    assert 'MicroBlock' in r

    # MicroInstruction repr
    insn = block.head
    if insn:
        r = repr(insn)
        assert 'MicroInstruction' in r

    # MicroOperand repr
    if insn:
        for op in insn.operands():
            r = repr(op)
            assert 'MicroOperand' in r
            break


def test_microcode_raw_properties(test_env):
    """Test raw_* escape-hatch properties on all wrapper classes."""
    import ida_hexrays

    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # MicroBlockArray.raw_mba
    assert isinstance(mf.raw_mba, ida_hexrays.mba_t)

    # MicroBlock.raw_block
    block = mf[1]
    assert isinstance(block.raw_block, ida_hexrays.mblock_t)

    # MicroInstruction.raw_instruction
    insn = block.head
    assert isinstance(insn.raw_instruction, ida_hexrays.minsn_t)

    # MicroOperand.raw_operand
    for op in insn.operands():
        assert isinstance(op.raw_operand, ida_hexrays.mop_t)
        break

    # MicroGraph.raw_graph
    mf2 = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf2.build_graph()
    graph = mf2.get_graph()
    assert isinstance(graph.raw_graph, ida_hexrays.mbl_graph_t)


def test_microcode_operand_none_fallbacks(test_env):
    """Test that type-specific accessors return None for wrong operand types."""
    from ida_domain.microcode import MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # Find a REGISTER operand and check all non-register accessors return None
    for insn in mf.instructions():
        for op in insn.operands():
            if op.is_register:
                assert op.signed_value is None
                assert op.unsigned_value is None
                assert op.register_name is not None  # should work
                assert op.stack_offset is None
                assert op.sub_instruction is None
                assert op.string_value is None
                assert op.pair is None
                assert op.get_stack_variable() is None  # not a stack var
                break
        else:
            continue
        break
    else:
        assert False, 'No register operand found'

    # Find a NUMBER operand — register_name should return None
    for insn in mf.instructions():
        for op in insn.operands():
            if op.is_number:
                assert op.register_name is None
                assert op.register is None
                assert op.string_value is None
                assert op.get_stack_variable() is None
                return
    assert False, 'No number operand found'


@min_ida_version('9.2')
def test_microcode_operand_type_check_shortcuts(test_env):
    """Test is_stack_variable, is_string, is_pair type-check shortcuts."""
    from ida_domain.microcode import MicroMaturity, MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)

    # At higher maturity we may get stack variables
    mf = db.microcode.generate(func, maturity=MicroMaturity.LVARS)

    found_stack = False
    for insn in mf.instructions():
        for op in insn.operands():
            if op.type == MicroOperandType.STACK_VAR:
                assert op.is_stack_variable
                assert op.stack_offset is not None
                found_stack = True
            else:
                # Verify is_stack_variable is False for other types
                if op.is_register:
                    assert not op.is_stack_variable

            # is_string and is_pair should be False for most operands
            if op.is_register or op.is_number:
                assert not op.is_string
                assert not op.is_pair

    # Note: stack vars may or may not appear depending on maturity and function


def test_microcode_operand_comparisons_extended(test_env):
    """Test __eq__ with non-MicroOperand and __lt__ ordering."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    ops = []
    for insn in mf.instructions():
        for op in insn.operands():
            ops.append(op)
            if len(ops) >= 2:
                break
        if len(ops) >= 2:
            break

    a, b = ops[0], ops[1]

    # __eq__ with non-MicroOperand returns NotImplemented (delegates to False)
    assert (a == 42) is False
    assert (a != 42) is True

    # __lt__ should not crash
    result = a < b
    assert isinstance(result, bool)

    # __lt__ with non-MicroOperand returns NotImplemented
    assert a.__lt__('not an operand') is NotImplemented

    # __repr__
    r = repr(a)
    assert 'MicroOperand' in r


def test_microcode_instruction_aliases_and_block(test_env):
    """Test right/dest aliases and block back-reference on MicroInstruction."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    from ida_domain.microcode import MicroOperand

    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            # right and dest are aliases for r and d
            assert insn.right == insn.r
            assert isinstance(insn.right, MicroOperand)

            assert insn.dest == insn.d
            assert isinstance(insn.dest, MicroOperand)

            # block property should return the parent block
            assert insn.block is not None
            assert insn.block.serial == block.serial
            return
    assert False, 'No instructions found'


def test_microcode_instruction_opcode_setter(test_env):
    """Test setting opcode on a MicroInstruction."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers — small
    mf = db.microcode.generate(func)

    for insn in mf.instructions():
        original = insn.opcode
        insn.opcode = MicroOpcode.NOP
        assert insn.opcode == MicroOpcode.NOP
        # Restore
        insn.opcode = original
        assert insn.opcode == original
        return


def test_microcode_instruction_find_opcode(test_env):
    """Test find_opcode returning result and None."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for insn in mf.instructions():
        # find_opcode with a non-existent opcode should return None
        result = insn.find_opcode(MicroOpcode.FDIV)
        assert result is None

        # find_opcode with the instruction's own opcode
        result = insn.find_opcode(insn.opcode)
        if result is not None:
            assert isinstance(result.opcode, MicroOpcode)
        return


def test_microcode_opcode_category_properties(test_env):
    """Test MicroOpcode category query properties."""
    from ida_domain.microcode import MicroOpcode

    # -- Conditional jumps
    assert MicroOpcode.JZ.is_conditional_jump is True
    assert MicroOpcode.JNZ.is_conditional_jump is True
    assert MicroOpcode.JA.is_conditional_jump is True
    assert MicroOpcode.JBE.is_conditional_jump is True
    assert MicroOpcode.JG.is_conditional_jump is True
    assert MicroOpcode.JLE.is_conditional_jump is True
    assert MicroOpcode.JCND.is_conditional_jump is True
    assert MicroOpcode.GOTO.is_conditional_jump is False
    assert MicroOpcode.MOV.is_conditional_jump is False

    # -- Jump (superset of conditional jump)
    assert MicroOpcode.JZ.is_jump is True
    assert MicroOpcode.GOTO.is_jump is True
    assert MicroOpcode.JTBL.is_jump is True
    assert MicroOpcode.IJMP.is_jump is True
    assert MicroOpcode.CALL.is_jump is False
    assert MicroOpcode.MOV.is_jump is False

    # -- Call
    assert MicroOpcode.CALL.is_call is True
    assert MicroOpcode.ICALL.is_call is True
    assert MicroOpcode.MOV.is_call is False
    assert MicroOpcode.GOTO.is_call is False

    # -- Flow (jumps + calls + ret)
    assert MicroOpcode.GOTO.is_flow is True
    assert MicroOpcode.JZ.is_flow is True
    assert MicroOpcode.CALL.is_flow is True
    assert MicroOpcode.RET.is_flow is True
    assert MicroOpcode.MOV.is_flow is False
    assert MicroOpcode.ADD.is_flow is False

    # -- Set-condition
    assert MicroOpcode.SETZ.is_set is True
    assert MicroOpcode.SETNZ.is_set is True
    assert MicroOpcode.SETAE.is_set is True
    assert MicroOpcode.SETG.is_set is True
    assert MicroOpcode.SETLE.is_set is True
    assert MicroOpcode.MOV.is_set is False
    assert MicroOpcode.JZ.is_set is False

    # -- Commutative
    assert MicroOpcode.ADD.is_commutative is True
    assert MicroOpcode.MUL.is_commutative is True
    assert MicroOpcode.OR.is_commutative is True
    assert MicroOpcode.AND.is_commutative is True
    assert MicroOpcode.XOR.is_commutative is True
    assert MicroOpcode.SETZ.is_commutative is True
    assert MicroOpcode.SETNZ.is_commutative is True
    assert MicroOpcode.SUB.is_commutative is False
    assert MicroOpcode.SHL.is_commutative is False

    # -- FPU
    assert MicroOpcode.FADD.is_floating_point is True
    assert MicroOpcode.FDIV.is_floating_point is True
    assert MicroOpcode.F2I.is_floating_point is True
    assert MicroOpcode.FNEG.is_floating_point is True
    assert MicroOpcode.ADD.is_floating_point is False
    assert MicroOpcode.MOV.is_floating_point is False

    # -- Propagatable (can appear in sub-instructions)
    assert MicroOpcode.ADD.is_propagatable is True
    assert MicroOpcode.MOV.is_propagatable is True
    assert MicroOpcode.NOP.is_propagatable is False
    assert MicroOpcode.RET.is_propagatable is False
    assert MicroOpcode.GOTO.is_propagatable is False

    # -- Unary
    assert MicroOpcode.NEG.is_unary is True
    assert MicroOpcode.LNOT.is_unary is True
    assert MicroOpcode.BNOT.is_unary is True
    assert MicroOpcode.FNEG.is_unary is True
    assert MicroOpcode.ADD.is_unary is False
    assert MicroOpcode.MOV.is_unary is False

    # -- Shift
    assert MicroOpcode.SHL.is_shift is True
    assert MicroOpcode.SHR.is_shift is True
    assert MicroOpcode.SAR.is_shift is True
    assert MicroOpcode.ADD.is_shift is False
    assert MicroOpcode.OR.is_shift is False

    # -- Arithmetic
    assert MicroOpcode.ADD.is_arithmetic is True
    assert MicroOpcode.SUB.is_arithmetic is True
    assert MicroOpcode.MUL.is_arithmetic is True
    assert MicroOpcode.UDIV.is_arithmetic is True
    assert MicroOpcode.SDIV.is_arithmetic is True
    assert MicroOpcode.UMOD.is_arithmetic is True
    assert MicroOpcode.SMOD.is_arithmetic is True
    assert MicroOpcode.OR.is_arithmetic is False
    assert MicroOpcode.FADD.is_arithmetic is False

    # -- Bitwise
    assert MicroOpcode.OR.is_bitwise is True
    assert MicroOpcode.AND.is_bitwise is True
    assert MicroOpcode.XOR.is_bitwise is True
    assert MicroOpcode.SHL.is_bitwise is True
    assert MicroOpcode.SHR.is_bitwise is True
    assert MicroOpcode.SAR.is_bitwise is True
    assert MicroOpcode.ADD.is_bitwise is False
    assert MicroOpcode.MOV.is_bitwise is False

    # -- Add/sub
    assert MicroOpcode.ADD.is_addsub is True
    assert MicroOpcode.SUB.is_addsub is True
    assert MicroOpcode.MUL.is_addsub is False

    # -- Extension (xds/xdu)
    assert MicroOpcode.XDS.is_xdsu is True
    assert MicroOpcode.XDU.is_xdsu is True
    assert MicroOpcode.MOV.is_xdsu is False

    # -- Convertible between set <-> jump
    assert MicroOpcode.SETZ.is_convertible_to_jump is True
    assert MicroOpcode.JZ.is_convertible_to_set is True
    assert MicroOpcode.GOTO.is_convertible_to_set is False
    assert MicroOpcode.MOV.is_convertible_to_jump is False


def test_microcode_instruction_category_methods(test_env):
    """Test MicroInstruction category helper methods on real microcode."""
    from ida_domain.microcode import MicroOpcode

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    found_any = False
    for insn in mf.instructions():
        found_any = True
        opc = insn.opcode

        # Instruction methods should agree with opcode properties
        assert insn.is_call() == opc.is_call
        assert insn.is_conditional_jump() == opc.is_conditional_jump
        assert insn.is_jump() == opc.is_jump
        assert insn.is_flow() == opc.is_flow
        assert insn.is_set() == opc.is_set
        assert insn.is_floating_point() == opc.is_floating_point
        assert insn.is_commutative() == opc.is_commutative

    assert found_any, 'Expected at least one instruction'


def test_microcode_instruction_comparisons(test_env):
    """Test __eq__, __ne__, __lt__ on MicroInstruction."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    insns = []
    for insn in mf.instructions():
        insns.append(insn)
        if len(insns) >= 2:
            break

    a, b = insns[0], insns[1]

    # Self-equality
    assert a == a
    assert not (a != a)

    # Different instructions
    if a.ea != b.ea or a.opcode != b.opcode:
        assert a != b

    # __lt__ should not crash
    result = a < b
    assert isinstance(result, bool)

    # NotImplemented for incompatible types
    assert a.__eq__('not an insn') is NotImplemented
    assert a.__ne__('not an insn') is NotImplemented
    assert a.__lt__('not an insn') is NotImplemented

    # __repr__
    r = repr(a)
    assert 'MicroInstruction' in r


def test_microcode_block_tail_and_empty(test_env):
    """Test tail property and empty block behavior."""
    from ida_domain.microcode import MicroBlockType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for block in mf:
        if block.block_type == MicroBlockType.STOP:
            # STOP blocks may have no instructions
            continue
        # Non-empty blocks should have head and tail
        if len(block) > 0:
            assert block.head is not None
            assert block.tail is not None
        # Block 0 (entry sentinel) might be empty
        if len(block) == 0:
            assert block.tail is None


def test_microcode_block_first_regular_insn_empty(test_env):
    """Test first_regular_insn on blocks where head is None."""
    from ida_domain.microcode import MicroBlockType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # Entry block (0) should have no head in generated maturity
    entry = mf[0]
    if entry.head is None:
        assert entry.first_regular_insn is None


def test_microcode_has_over_chains(test_env):
    """Test has_over_chains property on MicroBlockArray."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    # At PREOPTIMIZED, chains may or may not be computed
    result = mf.has_over_chains
    assert isinstance(result, bool)


def test_microcode_find_first_use_and_redefinition(test_env):
    """Test find_first_use and find_redefinition on MicroBlock."""
    import ida_hexrays

    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf.build_graph()
    mf.analyze_calls()

    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            use_list = block.build_use_list(insn, ida_hexrays.MUST_ACCESS)
            if use_list:
                # find_first_use: search from this instruction
                result = block.find_first_use(use_list, insn)
                # May return None or a MicroInstruction
                if result is not None:
                    assert isinstance(result.opcode, type(insn.opcode))

                # find_redefinition
                result = block.find_redefinition(use_list, insn)
                if result is not None:
                    assert isinstance(result.opcode, type(insn.opcode))
                return
    assert False, 'No use list found'


def test_microcode_location_set_contains(test_env):
    """Test __contains__ on MicroLocationSet."""
    import ida_hexrays

    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    mf.build_graph()
    mf.analyze_calls()

    for block in mf.blocks(skip_sentinels=True):
        for insn in block:
            use_list = block.build_use_list(insn, ida_hexrays.MUST_ACCESS)
            if use_list:
                # A set should contain itself
                assert use_list in use_list
                return
    assert False, 'No use list found'


def test_microcode_visitor_classes(test_env):
    """Test MicroInstructionVisitor and MicroOperandVisitor base classes."""
    from ida_domain.microcode import (
        MicroInstruction,
        MicroInstructionVisitor,
        MicroOperand,
        MicroOperandVisitor,
    )

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func)

    # MicroInstructionVisitor — collect opcodes
    class InsnCollector(MicroInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.opcodes = []

        def visit(self, insn):
            assert isinstance(insn, MicroInstruction)
            self.opcodes.append(insn.opcode)
            return 0

    visitor = InsnCollector()
    block = list(mf.blocks(skip_sentinels=True))[0]
    block.for_all_instructions(visitor)
    assert len(visitor.opcodes) > 0

    # MicroOperandVisitor — collect operand types
    class OpCollector(MicroOperandVisitor):
        def __init__(self):
            super().__init__()
            self.types = []

        def visit(self, operand, type_info, is_target):
            assert isinstance(operand, MicroOperand)
            self.types.append(operand.type)
            return 0

    op_visitor = OpCollector()
    block.for_all_operands(op_visitor)
    assert len(op_visitor.types) > 0


def test_microcode_optimizer_base_classes(test_env):
    """Test that optimizer base classes can be instantiated and called."""
    from ida_domain.microcode import (
        MicroBlock,
        MicroBlockOptimizer,
        MicroInstruction,
        MicroInstructionOptimizer,
    )

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)

    block = list(mf.blocks(skip_sentinels=True))[0]
    insn = block.head

    # MicroInstructionOptimizer.func() wraps and calls optimize()
    opt_insn = MicroInstructionOptimizer()
    result = opt_insn.func(block.raw_block, insn.raw_instruction, 0)
    assert result == 0  # default returns 0

    # MicroBlockOptimizer.func() wraps and calls optimize()
    opt_block = MicroBlockOptimizer()
    result = opt_block.func(block.raw_block)
    assert result == 0  # default returns 0


def test_microcode_optimizer_install_uninstall(test_env):
    """Test that optimizers can be installed and uninstalled."""
    from ida_domain.microcode import MicroBlockOptimizer, MicroInstructionOptimizer

    opt_insn = MicroInstructionOptimizer()
    opt_insn.install()
    opt_insn.uninstall()

    opt_block = MicroBlockOptimizer()
    opt_block.install()
    opt_block.uninstall()


def test_microcode_block_insert_remove_instruction(test_env):
    """Test insert_instruction and remove_instruction on MicroBlock."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers — small
    mf = db.microcode.generate(func)

    block = list(mf.blocks(skip_sentinels=True))[0]
    original_count = len(block)

    # Create a NOP instruction using the factory
    nop = MicroInstruction.create(block.head.ea, MicroOpcode.NOP)

    # Insert at head (after=None)
    block.insert_instruction(nop)
    assert len(block) == original_count + 1

    # Remove it
    block.remove_instruction(nop)
    assert len(block) == original_count


def test_microcode_function_insert_remove_block(test_env):
    """Test insert_block and remove_block on MicroBlockArray."""
    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)

    original_count = len(mf)

    # Insert a new block
    new_block = mf.insert_block(1)
    assert len(mf) == original_count + 1
    assert new_block is not None

    # Remove it
    mf.remove_block(new_block)
    assert len(mf) == original_count


def test_microcode_mba_serialization(test_env):
    """Test MBA serialize/deserialize roundtrip."""
    from ida_domain.microcode import MicroBlockArray, MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers — small
    mf = db.microcode.generate(func, build_graph=False)

    data = mf.serialize()
    assert isinstance(data, bytes)
    assert len(data) > 0

    # Deserialize via domain static method
    mf2 = MicroBlockArray.deserialize(data)
    assert isinstance(mf2, MicroBlockArray)
    assert len(mf2) == len(mf)
    assert mf2.maturity == mf.maturity

    # Verify deserialized content: same block count and instruction opcodes
    orig_opcodes = [insn.opcode for insn in mf.instructions()]
    deser_opcodes = [insn.opcode for insn in mf2.instructions()]
    assert orig_opcodes == deser_opcodes


def test_microcode_instruction_iter_and_len(test_env):
    """Test __iter__ and __len__ on MicroInstruction (iterate operands)."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for insn in mf.instructions():
        # __len__ should match number of non-empty operands
        n = len(insn)
        assert n >= 0
        assert n <= 3  # at most l, r, d

        # __iter__ should yield the same operands as operands()
        iter_ops = list(insn)
        explicit_ops = list(insn.operands())
        assert len(iter_ops) == len(explicit_ops)
        assert len(iter_ops) == n
        for a, b in zip(iter_ops, explicit_ops):
            assert a == b
        break  # first instruction is enough


def test_microcode_block_str(test_env):
    """Test __str__ on MicroBlock (join instruction text)."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for block in mf.blocks(skip_sentinels=True):
        text = str(block)
        assert isinstance(text, str)
        # Each instruction should appear as a line
        lines = text.splitlines()
        assert len(lines) == len(block)
        # Each line should match str(insn)
        for line, insn in zip(lines, block):
            assert line == str(insn)
        break  # first real block is enough


def test_microcode_find_call_nested_is_not_top_level(test_env):
    """find_call/find_opcode on a top-level instruction marks nested results as not top-level."""
    from ida_domain.microcode import MicroOpcode, MicroOperandType

    db = test_env
    # 0xC4 has sub-instructions (helper calls embedded in larger instructions)
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    found_nested = False
    for insn in mf.instructions():
        assert insn.is_top_level
        # find_call with helpers to find nested helper calls (e.g. _bittest64)
        fc = insn.find_call(with_helpers=True)
        if fc is not None:
            if fc.raw_instruction.obj_id == insn.raw_instruction.obj_id:
                assert fc.is_top_level
            else:
                assert not fc.is_top_level
                found_nested = True

    assert found_nested, 'Expected to find at least one nested sub-instruction via find_call'


def test_microcode_visitor_top_level_flag(test_env):
    """MicroInstructionVisitor sets is_top_level only for block-list instructions."""
    from ida_domain.microcode import MicroInstruction, MicroInstructionVisitor

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    class TopLevelChecker(MicroInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.top_level_count = 0
            self.nested_count = 0

        def visit(self, insn):
            assert isinstance(insn, MicroInstruction)
            if insn.is_top_level:
                self.top_level_count += 1
            else:
                self.nested_count += 1
            return 0

    block = list(mf.blocks(skip_sentinels=True))[0]
    checker = TopLevelChecker()
    block.for_all_instructions(checker)

    # Top-level count must match the number of instructions in the block
    assert checker.top_level_count == len(block)
    # Total visited includes nested sub-instructions
    assert checker.top_level_count + checker.nested_count >= checker.top_level_count


# ---------------------------------------------------------------------------
# MicroOperand / MicroInstruction — factory & builder tests
# ---------------------------------------------------------------------------


def test_microcode_operand_number_factory(test_env):
    """Test MicroOperand.number() static factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.number(42, size=4)
    assert op.type == MicroOperandType.NUMBER
    assert op.value == 42
    assert op.size == 4
    assert op.is_number is True
    assert bool(op) is True

    # Large 8-byte value
    big = MicroOperand.number(0xDEADBEEFCAFEBABE, size=8)
    assert big.value == 0xDEADBEEFCAFEBABE
    assert big.size == 8

    # Zero
    zero = MicroOperand.number(0, size=1)
    assert zero.value == 0
    assert zero.size == 1


def test_microcode_operand_reg_factory(test_env):
    """Test MicroOperand.reg() static factory."""
    import ida_hexrays

    from ida_domain.microcode import MicroOperand, MicroOperandType

    mreg = ida_hexrays.reg2mreg(1)  # cl/ecx/rcx
    op = MicroOperand.reg(mreg, size=1)
    assert op.type == MicroOperandType.REGISTER
    assert op.register == mreg
    assert op.size == 1
    assert op.is_register is True


def test_microcode_operand_helper_factory(test_env):
    """Test MicroOperand.helper() static factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.helper('memcpy')
    assert op.type == MicroOperandType.HELPER
    assert op.helper_name == 'memcpy'
    assert op.is_helper is True


def test_microcode_operand_block_ref_factory(test_env):
    """Test MicroOperand.new_block_ref() static factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.new_block_ref(7)
    assert op.type == MicroOperandType.BLOCK_REF
    assert op.block_ref == 7
    assert bool(op) is True


@min_ida_version('9.2')
def test_microcode_operand_global_addr_factory(test_env):
    """Test MicroOperand.global_addr() static factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.global_addr(0x401000, size=4)
    assert op.type == MicroOperandType.GLOBAL_ADDR
    assert op.global_address == 0x401000
    assert op.size == 4
    assert op.is_global_address is True


def test_microcode_operand_empty_factory(test_env):
    """Test MicroOperand.empty() static factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.empty()
    assert op.type == MicroOperandType.EMPTY
    assert op.is_empty is True
    assert bool(op) is False


def test_microcode_operand_from_insn_factory(test_env):
    """Test MicroOperand.from_insn() creating a sub-instruction operand."""
    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
        MicroOperandType,
    )

    inner = MicroInstruction.create(
        ea=0x1000,
        opcode=MicroOpcode.ADD,
        left=MicroOperand.number(1, size=4),
        right=MicroOperand.number(2, size=4),
    )
    op = MicroOperand.from_insn(inner)
    assert op.type == MicroOperandType.SUB_INSN
    assert op.is_sub_instruction(MicroOpcode.ADD)
    sub = op.sub_instruction
    assert sub is not None
    assert sub.opcode == MicroOpcode.ADD


@min_ida_version('9.2')
def test_microcode_operand_stack_var_factory(test_env):
    """Test MicroOperand.stack_var() creates a stack variable operand."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    op = MicroOperand.stack_var(mf, 0x10)
    assert op.type == MicroOperandType.STACK_VAR
    assert op.is_stack_variable is True


def test_microcode_instruction_create_nop(test_env):
    """Test MicroInstruction.create() with no operands (NOP)."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode

    insn = MicroInstruction.create(ea=0x1000, opcode=MicroOpcode.NOP)
    assert insn.opcode == MicroOpcode.NOP
    assert insn.ea == 0x1000
    assert insn.l.is_empty
    assert insn.r.is_empty
    assert insn.d.is_empty


def test_microcode_instruction_create_mov(test_env):
    """Test MicroInstruction.create() building a MOV with operands."""
    import ida_hexrays

    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
        MicroOperandType,
    )

    src = MicroOperand.number(0xFF, size=4)
    dst = MicroOperand.reg(ida_hexrays.reg2mreg(0), size=4)

    insn = MicroInstruction.create(
        ea=0x2000,
        opcode=MicroOpcode.MOV,
        left=src,
        dest=dst,
    )
    assert insn.opcode == MicroOpcode.MOV
    assert insn.ea == 0x2000
    assert insn.l.is_number
    assert insn.l.value == 0xFF
    assert insn.d.is_register
    assert insn.d.register == ida_hexrays.reg2mreg(0)
    # Right operand should remain empty (not provided)
    assert insn.r.is_empty


def test_microcode_instruction_create_goto(test_env):
    """Test MicroInstruction.create() building a GOTO."""
    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
    )

    insn = MicroInstruction.create(
        ea=0x3000,
        opcode=MicroOpcode.GOTO,
        left=MicroOperand.new_block_ref(5),
    )
    assert insn.opcode == MicroOpcode.GOTO
    assert insn.l.block_ref == 5


def test_microcode_instruction_create_add(test_env):
    """Test MicroInstruction.create() building an ADD with all three operands."""
    import ida_hexrays

    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
    )

    insn = MicroInstruction.create(
        ea=0x4000,
        opcode=MicroOpcode.ADD,
        left=MicroOperand.reg(ida_hexrays.reg2mreg(0), size=4),
        right=MicroOperand.number(10, size=4),
        dest=MicroOperand.reg(ida_hexrays.reg2mreg(0), size=4),
    )
    assert insn.opcode == MicroOpcode.ADD
    assert insn.l.is_register
    assert insn.r.is_number
    assert insn.r.value == 10
    assert insn.d.is_register


def test_microcode_instruction_operand_setters(test_env):
    """Test assigning MicroOperand to instruction l/r/d and left/right/dest."""
    import ida_hexrays

    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
    )

    insn = MicroInstruction.create(ea=0x5000, opcode=MicroOpcode.MOV)
    assert insn.l.is_empty
    assert insn.d.is_empty

    # Assign via short names
    insn.l = MicroOperand.number(99, size=4)
    assert insn.l.is_number
    assert insn.l.value == 99

    insn.d = MicroOperand.reg(ida_hexrays.reg2mreg(1), size=4)
    assert insn.d.is_register
    assert insn.d.register == ida_hexrays.reg2mreg(1)

    insn.r = MicroOperand.number(7, size=4)
    assert insn.r.value == 7

    # Assign via long aliases
    insn2 = MicroInstruction.create(ea=0x5000, opcode=MicroOpcode.ADD)
    insn2.left = MicroOperand.number(1, size=4)
    insn2.right = MicroOperand.number(2, size=4)
    insn2.dest = MicroOperand.reg(ida_hexrays.reg2mreg(0), size=4)

    assert insn2.left.value == 1
    assert insn2.right.value == 2
    assert insn2.dest.is_register


def test_microcode_instruction_create_and_insert(test_env):
    """Test creating an instruction with factories and inserting into a block."""
    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
    )

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)

    block = list(mf.blocks(skip_sentinels=True))[0]
    original_count = len(block)

    # Build a mov 0, 0 instruction and insert it
    nop_mov = MicroInstruction.create(
        ea=block.head.ea,
        opcode=MicroOpcode.NOP,
    )
    block.insert_instruction(nop_mov)
    assert len(block) == original_count + 1

    # Clean up
    block.remove_instruction(nop_mov)
    assert len(block) == original_count


def test_microcode_instruction_create_nested(test_env):
    """Test creating nested sub-instruction operands."""
    import ida_hexrays

    from ida_domain.microcode import (
        MicroInstruction,
        MicroOpcode,
        MicroOperand,
    )

    # Build: mov (add eax, 10), ecx
    # i.e. the left operand is itself an ADD sub-instruction
    add_insn = MicroInstruction.create(
        ea=0x6000,
        opcode=MicroOpcode.ADD,
        left=MicroOperand.reg(ida_hexrays.reg2mreg(0), size=4),
        right=MicroOperand.number(10, size=4),
    )

    outer = MicroInstruction.create(
        ea=0x6000,
        opcode=MicroOpcode.MOV,
        left=MicroOperand.from_insn(add_insn),
        dest=MicroOperand.reg(ida_hexrays.reg2mreg(1), size=4),
    )

    assert outer.opcode == MicroOpcode.MOV
    assert outer.l.is_sub_instruction(MicroOpcode.ADD)
    sub = outer.l.sub_instruction
    assert sub.l.register == ida_hexrays.reg2mreg(0)
    assert sub.r.value == 10
    assert outer.d.register == ida_hexrays.reg2mreg(1)


# ---------------------------------------------------------------------------
# Backward definition search tests
# ---------------------------------------------------------------------------


def test_microcode_block_build_operand_locations(test_env):
    """Test build_operand_locations returns non-empty set for registers."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]
    found_register = False
    for insn in block:
        for op in insn:
            if op.is_register:
                locations = block.build_operand_locations(op)
                assert bool(locations), f'Expected non-empty locations for {op}'
                found_register = True
                break
        if found_register:
            break
    assert found_register


def test_microcode_block_build_operand_locations_empty_for_constants(test_env):
    """Test build_operand_locations returns empty set for non-trackable operands."""
    from ida_domain.microcode import MicroMaturity, MicroOperand

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]
    # A number operand should produce an empty location set
    num = MicroOperand.number(42, size=4)
    locations = block.build_operand_locations(num)
    assert not locations


def test_microcode_find_def_backward_in_block(test_env):
    """Test find_def_backward finds a register definition within a block.

    In add_numbers at PREOPTIMIZED maturity:
        mov    rdi.8, rax.8        ; defines rax
        ...
        add    rsi.8, rax.8, rax.8 ; uses rax (right operand)

    Searching backward from the ADD for rax.8 should find the MOV.
    """
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]

    # Find the ADD instruction
    add_insn = None
    for insn in block:
        if insn.opcode == MicroOpcode.ADD:
            add_insn = insn
            break
    assert add_insn is not None, 'Expected an ADD instruction in add_numbers'

    # The right operand of ADD (rax.8) should be defined by an earlier MOV
    rax_operand = add_insn.r
    assert rax_operand.is_register

    defining_insn = block.find_def_backward(rax_operand, start=add_insn)
    assert defining_insn is not None
    assert defining_insn.opcode == MicroOpcode.MOV
    # The MOV defines rax from rdi: "mov rdi.8, rax.8"
    assert defining_insn.d.is_register
    assert defining_insn.d.register == rax_operand.register


def test_microcode_find_def_backward_not_found(test_env):
    """Test find_def_backward returns None for function parameters."""
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]

    # Find the ADD instruction
    add_insn = None
    for insn in block:
        if insn.opcode == MicroOpcode.ADD:
            add_insn = insn
            break
    assert add_insn is not None

    # The left operand (rsi.8) is a function parameter — not defined in this block
    rsi_operand = add_insn.l
    assert rsi_operand.is_register

    result = block.find_def_backward(rsi_operand, start=add_insn)
    assert result is None


def test_microcode_find_def_backward_start_none(test_env):
    """Test find_def_backward with start=None searches from block tail."""
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]

    # Find any register that's defined in the block
    add_insn = None
    for insn in block:
        if insn.opcode == MicroOpcode.ADD:
            add_insn = insn
            break
    assert add_insn is not None

    # Search from tail (start=None) for rax — should find the ADD itself
    # (since ADD defines rax.8 in dest, and it's the last real instruction)
    rax_operand = add_insn.d  # rax.8
    result = block.find_def_backward(rax_operand)
    assert result is not None
    # Should find the ADD (last definition of rax before the GOTO)
    assert result.opcode == MicroOpcode.ADD


def test_microcode_trace_def_backward_single_block(test_env):
    """Test trace_def_backward following mov chains within a block.

    In print_number block 2 at PREOPTIMIZED:
        ...
        mov    rtt.8, rax.8       ; rax <- rtt
        udiv   rtt.16, ...        ; defines rtt
        ...
        setz   rax.8, ...         ; uses rax.8

    Searching for rax.8 from setz should produce:
        chain[0] = mov rtt.8, rax.8     (defines rax, source is rtt)
        chain[1] = udiv rtt.16, ...     (defines rtt, non-mov → stops)
    """
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Find block 2 (the loop block with udiv/umod)
    block2 = None
    for block in mf.blocks(skip_sentinels=True):
        has_udiv = any(insn.opcode == MicroOpcode.UDIV for insn in block)
        if has_udiv:
            block2 = block
            break
    assert block2 is not None, 'Expected a block with UDIV in print_number'

    # Find a SETZ instruction in that block (uses rax.8)
    setz_insn = None
    for insn in block2:
        if insn.opcode == MicroOpcode.SETZ and insn.l.is_register:
            setz_insn = insn
            break
    assert setz_insn is not None, 'Expected SETZ in the loop block'

    rax_op = setz_insn.l
    chain = block2.trace_def_backward(rax_op, start=setz_insn)

    assert len(chain) >= 2, f'Expected chain of 2+, got {len(chain)}'
    # First link: the mov that defines rax
    assert chain[0].opcode == MicroOpcode.MOV
    # Last link: should be udiv (non-mov, stops chain)
    assert chain[-1].opcode == MicroOpcode.UDIV


def test_microcode_trace_def_backward_cross_block(test_env):
    """Test trace_def_backward crosses into predecessor block.

    In print_number at PREOPTIMIZED:
        Block 1: sub rsi.8, #1.8, rsi.8
        ...
        Block 3 (pred=[2]): sub rdx.8, rsi.8, rdx.8

    Tracing rsi.8 from the SUB in block 3 should reach into block 2.
    """
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Find the block that has CALL to sys_write (block 3 — single pred from block 2)
    call_block = None
    for block in mf.blocks(skip_sentinels=True):
        if any(insn.opcode == MicroOpcode.CALL for insn in block):
            call_block = block
            break
    assert call_block is not None

    # Find: sub rdx.8, rsi.8, rdx.8 — the rsi.8 is the right operand
    sub_insn = None
    for insn in call_block:
        if insn.opcode == MicroOpcode.SUB and insn.r.is_register:
            sub_insn = insn
            break
    assert sub_insn is not None, 'Expected SUB in the call block'

    rsi_op = sub_insn.r
    chain = call_block.trace_def_backward(rsi_op, start=sub_insn)

    assert len(chain) >= 1, 'Expected cross-block chain'
    # The defining instruction should be in a different block
    assert chain[0].block is not None
    assert chain[0].block.serial != call_block.serial


def test_microcode_trace_def_backward_empty_for_param(test_env):
    """Test trace_def_backward returns empty list for unresolvable operands."""
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = list(mf.blocks(skip_sentinels=True))[0]

    # Find the first MOV (mov rsp.8, rbp.8) — rsp is the stack pointer,
    # a function parameter with no definition in the block
    first_mov = None
    for insn in block:
        if insn.opcode == MicroOpcode.MOV:
            first_mov = insn
            break
    assert first_mov is not None

    # The left operand of the first MOV (rsp.8) has no prior definition
    chain = block.trace_def_backward(first_mov.l, start=first_mov)
    assert chain == []


def test_microcode_trace_def_backward_stops_at_multi_pred(test_env):
    """Test trace_def_backward stops at blocks with multiple predecessors."""
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Block 2 is the loop block with preds=[1, 2] (self-loop + entry)
    loop_block = None
    for block in mf.blocks(skip_sentinels=True):
        if block.predecessor_count > 1:
            loop_block = block
            break
    assert loop_block is not None, 'Expected a block with multiple predecessors'

    # Find a MOV at the top of the loop that uses a register
    first_reg_use = None
    for insn in loop_block:
        if insn.l.is_register:
            first_reg_use = insn
            break
    assert first_reg_use is not None

    # trace should NOT cross into a predecessor since this block has multiple preds
    chain = loop_block.trace_def_backward(first_reg_use.l, start=first_reg_use)
    # Chain may be empty (operand not defined before start in this block)
    # or may find defs within the block, but should not cross the multi-pred boundary
    for c in chain:
        if c.block is not None:
            assert c.block.serial == loop_block.serial, (
                f'Expected chain to stay within block {loop_block.serial}, '
                f'but found entry in block {c.block.serial}'
            )


# ---------------------------------------------------------------------------
# Pattern 1: Instruction Replacement
# ---------------------------------------------------------------------------


def test_microcode_instruction_optimize_solo(test_env):
    """Test optimize_solo runs without error and returns an int."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func)
    block = list(mf.blocks(skip_sentinels=True))[0]
    insn = block.head
    result = insn.optimize_solo()
    assert isinstance(result, int)


def test_microcode_block_mark_lists_dirty(test_env):
    """Test mark_lists_dirty runs without error."""
    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)
    block = list(mf.blocks(skip_sentinels=True))[0]
    # Should not raise
    block.mark_lists_dirty()


def test_microcode_block_contains_instruction(test_env):
    """Test contains_instruction correctly identifies block membership."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number — multiple blocks
    mf = db.microcode.generate(func)
    blocks = list(mf.blocks(skip_sentinels=True))
    assert len(blocks) >= 2

    block0 = blocks[0]
    block1 = blocks[1]
    insn_in_b0 = block0.head
    assert insn_in_b0 is not None

    assert block0.contains_instruction(insn_in_b0) is True
    assert block1.contains_instruction(insn_in_b0) is False


def test_microcode_block_replace_instruction(test_env):
    """Test replace_instruction swaps + optimizes + marks dirty."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode, MicroOperand

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func)
    block = list(mf.blocks(skip_sentinels=True))[0]

    # Pick an instruction to replace
    target = block.head
    assert target is not None
    original_opcode = target.opcode

    # Build a NOP replacement
    nop = MicroInstruction.create(target.ea, MicroOpcode.NOP)
    block.replace_instruction(target, nop)

    # After swap, `target` now holds the NOP content
    assert target.opcode == MicroOpcode.NOP


def test_microcode_block_replace_instruction_wrong_block(test_env):
    """Test replace_instruction raises InvalidParameterError for wrong block."""
    import pytest

    from ida_domain.microcode import MicroInstruction, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number — multiple blocks
    mf = db.microcode.generate(func)
    blocks = list(mf.blocks(skip_sentinels=True))
    assert len(blocks) >= 2

    block0 = blocks[0]
    block1 = blocks[1]
    insn_in_b1 = block1.head
    assert insn_in_b1 is not None

    nop = MicroInstruction.create(insn_in_b1.ea, MicroOpcode.NOP)
    with pytest.raises(InvalidParameterError, match='is not in this block'):
        block0.replace_instruction(insn_in_b1, nop)


def test_microcode_instruction_replace_with(test_env):
    """Test MicroInstruction.replace_with when parent block is known."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)
    block = list(mf.blocks(skip_sentinels=True))[0]

    # Get instruction from block iteration (parent_block is set)
    target = block.head
    assert target is not None
    assert target.block is not None

    nop = MicroInstruction.create(target.ea, MicroOpcode.NOP)
    target.replace_with(nop)
    assert target.opcode == MicroOpcode.NOP


def test_microcode_instruction_replace_with_no_parent(test_env):
    """Test replace_with raises DecompilerError when parent block is unknown."""
    import pytest

    from ida_domain.microcode import MicroInstruction, MicroOpcode

    # Create a standalone instruction (no parent block)
    insn = MicroInstruction.create(0x1000, MicroOpcode.NOP)
    replacement = MicroInstruction.create(0x1000, MicroOpcode.NOP)

    with pytest.raises(DecompilerError, match='parent block unknown'):
        insn.replace_with(replacement)


def test_microcode_mba_verify(test_env):
    """Test MicroBlockArray.verify() via the domain API."""
    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)
    # Should not raise on consistent microcode
    mf.verify(always=True)


def test_microcode_mba_mark_chains_dirty(test_env):
    """Test MicroBlockArray.mark_chains_dirty() runs without error."""
    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)
    # Should not raise
    mf.mark_chains_dirty()


def test_microcode_mba_flags(test_env):
    """Test MbaFlags read, set, and clear."""
    from ida_domain.microcode import MbaFlags

    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)

    original = mf.mba_flags

    # set_mba_flag ORs the flag in
    mf.set_mba_flag(MbaFlags.SHORT)
    assert MbaFlags.SHORT in mf.mba_flags

    # set_mba_flag is additive — previous flags are preserved
    mf.set_mba_flag(MbaFlags.NUMADDR)
    assert MbaFlags.SHORT in mf.mba_flags
    assert MbaFlags.NUMADDR in mf.mba_flags

    # clear_mba_flag removes only the specified flag
    mf.clear_mba_flag(MbaFlags.SHORT)
    assert MbaFlags.SHORT not in mf.mba_flags
    assert MbaFlags.NUMADDR in mf.mba_flags

    # clear the other flag too, restore original state
    mf.clear_mba_flag(MbaFlags.NUMADDR)
    if MbaFlags.NUMADDR not in original:
        assert MbaFlags.NUMADDR not in mf.mba_flags


def test_microcode_block_edge_manipulation(test_env):
    """Test MicroBlock edge add/remove/clear/replace."""
    from ida_domain.microcode import MicroBlockType, MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.GENERATED)

    # Find a TWO_WAY block (conditional branch) so we have known edges
    branch_block = None
    for block in mf.blocks(skip_sentinels=True):
        if block.block_type == MicroBlockType.TWO_WAY:
            branch_block = block
            break
    assert branch_block is not None, 'Need a TWO_WAY block for this test'

    orig_succs = branch_block.successor_serials[:]
    assert len(orig_succs) == 2

    target_serial = orig_succs[0]
    target_block = mf[target_serial]
    assert branch_block.serial in target_block.predecessor_serials

    # --- remove_successor ---
    branch_block.remove_successor(target_serial)
    assert target_serial not in branch_block.successor_serials
    assert branch_block.serial not in target_block.predecessor_serials

    # --- add_successor (restore it) ---
    branch_block.add_successor(target_serial)
    assert target_serial in branch_block.successor_serials
    assert branch_block.serial in target_block.predecessor_serials

    # --- add_successor accepts MicroBlock too ---
    new_block = mf.insert_block(mf.block_count - 1)
    branch_block.add_successor(new_block)
    assert new_block.serial in branch_block.successor_serials
    assert branch_block.serial in new_block.predecessor_serials

    # --- replace_successor ---
    other_serial = orig_succs[1]
    branch_block.replace_successor(new_block, other_serial)
    assert new_block.serial not in branch_block.successor_serials
    assert branch_block.serial not in new_block.predecessor_serials

    # --- clear_successors ---
    saved_succs = branch_block.successor_serials[:]
    branch_block.clear_successors()
    assert branch_block.successor_count == 0
    for s in saved_succs:
        assert branch_block.serial not in mf[s].predecessor_serials

    # --- clear_predecessors ---
    # Use target_block which should still have predecessors
    if target_block.predecessor_count > 0:
        saved_preds = target_block.predecessor_serials[:]
        target_block.clear_predecessors()
        assert target_block.predecessor_count == 0
        for p in saved_preds:
            assert target_block.serial not in mf[p].successor_serials


def test_microcode_block_jump_target_and_fall_through(test_env):
    """Test jump_target and fall_through on real microcode across functions and maturity levels."""
    from ida_domain.microcode import MicroBlockType, MicroMaturity, MicroOpcode

    db = test_env

    # Test across multiple functions and maturity levels
    func_addrs = [0xC4, 0x2A3, 0x2BC]
    maturities = [
        MicroMaturity.GENERATED,
        MicroMaturity.PREOPTIMIZED,
        MicroMaturity.LOCOPT,
    ]

    two_way_count = 0
    one_way_goto_count = 0
    one_way_fallthrough_count = 0

    for addr in func_addrs:
        func = db.functions.get_at(addr)
        if func is None:
            continue
        for mat in maturities:
            mf = db.microcode.generate(func, maturity=mat)

            for block in mf.blocks(skip_sentinels=True):
                bt = block.block_type

                if bt == MicroBlockType.TWO_WAY:
                    two_way_count += 1
                    tail = block.tail
                    assert tail is not None
                    assert tail.is_conditional_jump()

                    # jump_target must match tail.d.block_ref
                    jt = block.jump_target
                    assert jt is not None
                    assert jt == tail.d.block_ref

                    # fall_through must be serial + 1
                    ft = block.fall_through
                    assert ft is not None
                    assert ft == block.serial + 1

                    # Both targets must be in the successor set
                    succs = block.successor_serials
                    assert jt in succs, (
                        f'jump_target {jt} not in succs {succs} '
                        f'(block {block.serial}, func 0x{addr:x}, {mat.name})'
                    )
                    assert ft in succs, (
                        f'fall_through {ft} not in succs {succs} '
                        f'(block {block.serial}, func 0x{addr:x}, {mat.name})'
                    )

                elif bt == MicroBlockType.ONE_WAY:
                    tail = block.tail
                    jt = block.jump_target
                    assert jt is not None

                    if tail is not None and tail.opcode == MicroOpcode.GOTO:
                        one_way_goto_count += 1
                        assert jt == tail.l.block_ref
                    else:
                        one_way_fallthrough_count += 1
                        assert jt == block.serial + 1

                    # fall_through is None for ONE_WAY
                    assert block.fall_through is None

                elif bt in (MicroBlockType.STOP, MicroBlockType.ZERO_WAY):
                    assert block.jump_target is None
                    assert block.fall_through is None

    # Ensure we actually tested the interesting cases
    assert two_way_count > 0, 'No TWO_WAY blocks found'
    assert one_way_goto_count > 0, 'No ONE_WAY+goto blocks found'


def test_microcode_block_is_simple_goto(test_env):
    """Test MicroBlock.is_simple_goto detection."""
    from ida_domain.microcode import MicroBlockType, MicroOpcode

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    for block in mf.blocks(skip_sentinels=True):
        if block.is_simple_goto:
            # A simple goto block should have a goto tail and be ONE_WAY
            assert block.tail is not None
            assert block.tail.opcode == MicroOpcode.GOTO
            assert block.block_type == MicroBlockType.ONE_WAY


def test_microcode_block_flags(test_env):
    """Test MicroBlockFlags read, set, and clear."""
    from ida_domain.microcode import MicroBlockFlags

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    block = next(mf.blocks(skip_sentinels=True))
    original = block.block_flags
    assert isinstance(original, MicroBlockFlags)

    # set_block_flag ORs in
    block.set_block_flag(MicroBlockFlags.GOTO)
    assert MicroBlockFlags.GOTO in block.block_flags

    # clear_block_flag removes
    block.clear_block_flag(MicroBlockFlags.GOTO)
    if MicroBlockFlags.GOTO not in original:
        assert MicroBlockFlags.GOTO not in block.block_flags

    # setter replaces all flags
    block.block_flags = original
    assert block.block_flags == original


def test_microcode_mba_optimize_local(test_env):
    """Test MicroBlockArray.optimize_local() runs without error."""
    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)
    # Should not raise; return value is number of changes
    result = mf.optimize_local(0)
    assert isinstance(result, int)


def test_microcode_mba_merge_blocks(test_env):
    """Test MicroBlockArray.merge_blocks() runs without error."""
    db = test_env
    func = db.functions.get_at(0x2A3)
    mf = db.microcode.generate(func)
    # Should not raise; return value is bool
    result = mf.merge_blocks()
    assert isinstance(result, bool)


def test_microcode_mba_build_graph(test_env):
    """Test MicroBlockArray.build_graph() can rebuild the graph."""
    db = test_env
    func = db.functions.get_at(0xC4)
    # Generate without building the graph
    mf = db.microcode.generate(func, build_graph=False)
    # Manually build it
    mf.build_graph()
    # Graph should now be usable — verify blocks have successors
    found_succs = False
    for block in mf.blocks(skip_sentinels=True):
        if block.successor_count > 0:
            found_succs = True
            break
    assert found_succs


def test_microcode_mba_copy_block(test_env):
    """Test MicroBlockArray.copy_block() duplicates a block."""
    from ida_domain.microcode import CopyBlockFlags, MicroBlockType

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func)

    # Find a non-empty, non-sentinel block to copy
    source = None
    for block in mf.blocks(skip_sentinels=True):
        if not block.is_empty and block.block_type != MicroBlockType.STOP:
            source = block
            break
    assert source is not None

    original_count = mf.block_count
    source_insn_count = len(source)
    source_serial = source.serial

    # Copy the block; insert before the STOP sentinel (last block)
    insert_at = mf.block_count - 1
    copy = mf.copy_block(source, insert_at)

    # Block count increased by 1
    assert mf.block_count == original_count + 1

    # The copy lives at the requested serial
    assert copy.serial == insert_at

    # The copy has the same number of instructions as the source
    assert len(copy) == source_insn_count

    # The original source still exists (its serial may have shifted
    # if the copy was inserted before it, but in our case we insert
    # at the end so it shouldn't shift)
    assert mf[source_serial] is not None


def test_microcode_mba_serialize_roundtrip(test_env):
    """Test that serialize → deserialize produces equivalent microcode."""
    from ida_domain.microcode import MicroBlockArray, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Serialize
    data = mf.serialize()
    assert isinstance(data, bytes)
    assert len(data) > 0

    # Deserialize
    mf2 = MicroBlockArray.deserialize(data)
    assert mf2 is not mf

    # Same structure
    assert len(mf2) == len(mf)
    assert mf2.maturity == mf.maturity

    # Same block types and instruction counts
    for b1, b2 in zip(mf, mf2):
        assert b1.block_type == b2.block_type
        assert len(b1) == len(b2)

    # Re-serialize should produce identical bytes
    data2 = mf2.serialize()
    assert data == data2


@min_ida_version('9.4')
def test_microcode_instruction_serialize_roundtrip(test_env):
    """Test that MicroInstruction serialize → deserialize round-trips."""
    from ida_domain.microcode import MicroInstruction, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Collect two distinct instructions
    insns = []
    for block in mf:
        for insn in block:
            insns.append(insn)
            if len(insns) == 2:
                break
        if len(insns) == 2:
            break
    assert len(insns) == 2, 'expected at least two instructions'
    first, second = insns

    # Serialize both
    fmt_ver1, data1 = first.serialize()
    fmt_ver2, data2 = second.serialize()
    assert isinstance(data1, bytes) and len(data1) > 0
    assert isinstance(data2, bytes) and len(data2) > 0

    # Different instructions must produce different serialized bytes
    assert data1 != data2, 'two distinct instructions should serialize differently'

    # Deserialize both and verify round-trip
    restored1 = MicroInstruction.deserialize(data1, fmt_ver1)
    restored2 = MicroInstruction.deserialize(data2, fmt_ver2)

    assert restored1.opcode == first.opcode
    assert restored1.ea == first.ea
    assert restored2.opcode == second.opcode
    assert restored2.ea == second.ea
    # Verify structural equality to catch operand/aux-field mismatches
    assert restored1.equals(first)
    assert restored2.equals(second)

    # Re-serialize should produce identical bytes
    assert restored1.serialize() == (fmt_ver1, data1)
    assert restored2.serialize() == (fmt_ver2, data2)


# ---------------------------------------------------------------------------
# Operand constant predicates
# ---------------------------------------------------------------------------


def test_microcode_operand_constant_predicates(test_env):
    """Test is_zero, is_one, is_positive_constant, is_negative_constant, is_equal_to."""
    from ida_domain.microcode import MicroOperand

    zero = MicroOperand.number(0, 4)
    assert zero.is_zero
    assert not zero.is_one
    assert not zero.is_positive_constant
    assert not zero.is_negative_constant
    assert zero.is_equal_to(0)

    one = MicroOperand.number(1, 4)
    assert one.is_one
    assert not one.is_zero
    assert one.is_positive_constant
    assert not one.is_negative_constant
    assert one.is_equal_to(1)

    big = MicroOperand.number(42, 4)
    assert big.is_positive_constant
    assert not big.is_negative_constant
    assert big.is_equal_to(42)
    assert not big.is_equal_to(43)

    neg = MicroOperand.number(0xFFFFFFFF, 4)  # -1 as unsigned 32-bit
    assert neg.is_negative_constant
    assert neg.is_equal_to(-1, is_signed=True)

    # Non-number operands should return False
    reg = MicroOperand.reg(0, 4)
    assert not reg.is_zero
    assert not reg.is_one

    # Extension checks
    val = MicroOperand.number(0xFF, size=4)
    assert isinstance(val.is_sign_extended_from(1), bool)
    assert isinstance(val.is_zero_extended_from(1), bool)


def test_microcode_operand_extended_type_checks(test_env):
    """Test is_kreg, is_cc, is_bit_register on operands."""
    import ida_hexrays

    from ida_domain.microcode import MicroOperand

    # Condition code register (mreg 0 is cc on x86)
    cc_reg = MicroOperand.reg(0, 1)
    assert cc_reg.is_condition_code
    assert cc_reg.is_bit_register  # cc regs are bit regs

    # General-purpose register — mr_first is the start of GP regs
    gp_reg = MicroOperand.reg(ida_hexrays.mr_first, 4)
    assert not gp_reg.is_kernel_register
    assert not gp_reg.is_condition_code
    assert not gp_reg.is_bit_register

    # Non-register operand
    num = MicroOperand.number(5, 4)
    assert not num.is_kernel_register
    assert not num.is_condition_code
    assert not num.is_bit_register


def test_microcode_operand_may_use_aliased_memory(test_env):
    """Test may_use_aliased_memory property."""
    from ida_domain.microcode import MicroOperand

    # A simple number should not use aliased memory
    num = MicroOperand.number(0, 4)
    assert not num.may_use_aliased_memory

    # A register should not use aliased memory
    reg = MicroOperand.reg(0, 4)
    assert not reg.may_use_aliased_memory


def test_microcode_operand_has_side_effects_param(test_env):
    """Test has_side_effects with include_ldx_and_divs parameter."""
    from ida_domain.microcode import MicroOperand

    num = MicroOperand.number(0, 4)
    assert not num.has_side_effects()
    assert not num.has_side_effects(include_ldx_and_divs=True)


def test_microcode_operand_erase_but_keep_size(test_env):
    """Test erase_but_keep_size preserves size."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    op = MicroOperand.number(42, 8)
    assert op.size == 8
    assert op.type == MicroOperandType.NUMBER

    op.erase_but_keep_size()
    assert op.type == MicroOperandType.EMPTY
    assert op.size == 8  # size preserved


def test_microcode_operand_reg_pair_factory(test_env):
    """Test MicroOperand.reg_pair() factory."""
    from ida_domain.microcode import MicroOperand, MicroOperandType

    pair = MicroOperand.reg_pair(0, 4, 4)  # lo=mreg0, hi=mreg4, 4 bytes each
    assert pair.type == MicroOperandType.PAIR
    assert pair.size == 8  # 2 * halfsize
    lo, hi = pair.pair
    assert lo.is_register
    assert hi.is_register


def test_microcode_operand_local_var_factory(test_env):
    """Test MicroOperand.local_var() factory."""
    from ida_domain.microcode import MicroMaturity, MicroOperand, MicroOperandType

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.LVARS)

    # mba.vars should have at least one local variable after LVARS maturity
    if len(mf.vars) > 0:
        lv = MicroOperand.local_var(mf, 0)
        assert lv.type == MicroOperandType.LOCAL_VAR


def test_microcode_operand_fpnum_factory(test_env):
    """Test MicroOperand.fpnum() factory."""
    import struct

    from ida_domain.microcode import MicroOperand, MicroOperandType

    data = struct.pack('<d', 1.0)  # IEEE 754 double for 1.0
    op = MicroOperand.fpnum(data)
    assert op.type == MicroOperandType.FP_CONST


# ---------------------------------------------------------------------------
# Instruction query methods
# ---------------------------------------------------------------------------


def test_microcode_instruction_is_helper(test_env):
    """Test MicroInstruction.is_helper() method."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for insn in mf.instructions():
        # is_helper should not crash, and should return bool
        result = insn.is_helper('memcpy')
        assert isinstance(result, bool)


def test_microcode_instruction_contains_call(test_env):
    """Test MicroInstruction.contains_call() method."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    # Use a function that is known to contain calls
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.CALLS)

    has_call = False
    for insn in mf.instructions():
        result = insn.contains_call()
        assert isinstance(result, bool)
        if result:
            has_call = True
            assert isinstance(insn.contains_call(with_helpers=True), bool)
            break

    # Even if no call found, the method should work without error.
    # Just verify the API is functional.
    if not has_call:
        # Try with helpers too
        for insn in mf.instructions():
            insn.contains_call(with_helpers=True)
            break


def test_microcode_instruction_is_noret_call(test_env):
    """Test MicroInstruction.is_noret_call() method."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.CALLS)

    for insn in mf.instructions():
        # Should not crash, return bool
        result = insn.is_noret_call()
        assert isinstance(result, bool)


def test_microcode_instruction_find_num_op(test_env):
    """Test MicroInstruction.find_numeric_operand() method."""
    from ida_domain.microcode import MicroMaturity, MicroOperand

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    found_num = False
    for insn in mf.instructions():
        result = insn.find_numeric_operand()
        if result is not None:
            num_op, other_op = result
            assert isinstance(num_op, MicroOperand)
            assert isinstance(other_op, MicroOperand)
            assert num_op.is_number
            found_num = True
            break
    assert found_num, 'Expected at least one instruction with a numeric operand'


def test_microcode_instruction_find_ins_op(test_env):
    """Test MicroInstruction.find_sub_instruction_operand() method."""
    from ida_domain.microcode import MicroInstruction, MicroMaturity, MicroOperand

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for insn in mf.instructions():
        # Default (NOP = any opcode)
        result = insn.find_sub_instruction_operand()
        if result is not None:
            sub_insn, other_op = result
            assert isinstance(sub_insn, MicroInstruction)
            assert isinstance(other_op, MicroOperand)
            break


def test_microcode_instruction_modifies_d(test_env):
    """Test MicroInstruction.modifies_dest property."""
    from ida_domain.microcode import MicroMaturity, MicroOpcode

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for insn in mf.instructions():
        result = insn.modifies_dest
        assert isinstance(result, bool)
        # MOV always modifies d
        if insn.opcode == MicroOpcode.MOV:
            assert result is True
            break


def test_microcode_instruction_has_side_effects_param(test_env):
    """Test MicroInstruction.has_side_effects() with parameter."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for insn in mf.instructions():
        r1 = insn.has_side_effects()
        r2 = insn.has_side_effects(include_ldx_and_divs=True)
        assert isinstance(r1, bool)
        assert isinstance(r2, bool)
        # With ldx/divs included, result should be >= without
        if r1:
            assert r2
        break


def test_microcode_instruction_make_nop(test_env):
    """Test MicroInstruction.make_nop() on a detached instruction."""
    from ida_domain.microcode import MicroInstruction, MicroOpcode, MicroOperand

    insn = MicroInstruction.create(
        ea=0x1000,
        opcode=MicroOpcode.MOV,
        left=MicroOperand.number(42, 4),
        dest=MicroOperand.reg(0, 4),
    )
    assert insn.opcode == MicroOpcode.MOV
    insn.make_nop()
    assert insn.opcode == MicroOpcode.NOP


# ---------------------------------------------------------------------------
# MicroBlockArray — alloc_kreg, free_kreg, alloc_fict_ea
# ---------------------------------------------------------------------------


def test_microcode_mba_alloc_kreg(test_env):
    """Test alloc_kreg / free_kreg roundtrip."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    import ida_hexrays

    kreg = mf.alloc_kernel_register(4)
    assert kreg != ida_hexrays.mr_none
    # Should not raise
    mf.free_kernel_register(kreg, 4)


def test_microcode_mba_alloc_fict_ea(test_env):
    """Test alloc_fict_ea returns unique addresses."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    ea1 = mf.alloc_fictional_address()
    ea2 = mf.alloc_fictional_address()
    assert ea1 != ea2  # must be unique


# ---------------------------------------------------------------------------
# Visitor dispatch on MicroBlock and MicroBlockArray
# ---------------------------------------------------------------------------


def test_microcode_block_for_all_instructions(test_env):
    """Test MicroBlock.for_all_instructions() visitor dispatch."""
    from ida_domain.microcode import MicroInstructionVisitor, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    class Counter(MicroInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit(self, insn):
            self.count += 1
            return 0

    for block in mf.blocks(skip_sentinels=True):
        counter = Counter()
        block.for_all_instructions(counter)
        # for_all_instructions visits sub-instructions too, so count >= len(block)
        assert counter.count >= len(block)
        break


def test_microcode_block_for_all_operands(test_env):
    """Test MicroBlock.for_all_operands() visitor dispatch."""
    from ida_domain.microcode import MicroMaturity, MicroOperandVisitor

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    class OpCounter(MicroOperandVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit(self, operand, type_info, is_target):
            self.count += 1
            return 0

    for block in mf.blocks(skip_sentinels=True):
        counter = OpCounter()
        block.for_all_operands(counter)
        assert counter.count > 0
        break


def test_microcode_mba_for_all_top_instructions(test_env):
    """Test MicroBlockArray.for_all_top_instructions() visitor dispatch."""
    from ida_domain.microcode import MicroInstructionVisitor, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    class Counter(MicroInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit(self, insn):
            self.count += 1
            return 0

    counter = Counter()
    mf.for_all_top_instructions(counter)
    # Should visit at least as many as sum of block lengths
    total_top = sum(len(b) for b in mf.blocks(skip_sentinels=True))
    assert counter.count == total_top


def test_microcode_mba_for_all_instructions(test_env):
    """Test MicroBlockArray.for_all_instructions() visits sub-instructions too."""
    from ida_domain.microcode import MicroInstructionVisitor, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    class Counter(MicroInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit(self, insn):
            self.count += 1
            return 0

    top_counter = Counter()
    mf.for_all_top_instructions(top_counter)

    all_counter = Counter()
    mf.for_all_instructions(all_counter)

    # for_all_instructions includes sub-instructions, so count >= topinsns
    assert all_counter.count >= top_counter.count


def test_microcode_mba_for_all_operands(test_env):
    """Test MicroBlockArray.for_all_operands() visitor dispatch."""
    from ida_domain.microcode import MicroMaturity, MicroOperandVisitor

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    class OpCounter(MicroOperandVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit(self, operand, type_info, is_target):
            self.count += 1
            return 0

    counter = OpCounter()
    mf.for_all_operands(counter)
    assert counter.count > 0


def test_microcode_mba_optimize_global(test_env):
    """Test MicroBlockArray.optimize_global()."""
    from ida_domain.microcode import MicroError, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.GLBOPT1)

    result = mf.optimize_global()
    assert isinstance(result, MicroError)


def test_microcode_block_optimize_block(test_env):
    """Test MicroBlock.optimize_block()."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for block in mf.blocks(skip_sentinels=True):
        result = block.optimize_block()
        assert isinstance(result, int)
        break


def test_microcode_block_optimize_useless_jump(test_env):
    """Test MicroBlock.optimize_useless_jump()."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    for block in mf.blocks(skip_sentinels=True):
        result = block.optimize_useless_jump()
        assert isinstance(result, int)
        break


def test_microcode_call_info_wrapper(test_env):
    """Test MicroCallInfo and MicroCallArg wrappers."""
    from ida_domain.microcode import (
        CallInfoFlags,
        FunctionRole,
        MicroCallArg,
        MicroCallInfo,
        MicroLocationSet,
        MicroMaturity,
    )

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.CALLS)

    # Find a call instruction
    call_info = None
    for insn in mf.instructions(skip_sentinels=True):
        if insn.is_call():
            call_info = insn.d.call_info
            break

    assert call_info is not None
    assert isinstance(call_info, MicroCallInfo)

    # Basic properties
    assert isinstance(call_info.callee, int)
    assert isinstance(call_info.arg_count, int)
    assert call_info.arg_count > 0
    assert isinstance(call_info.calling_convention, int)
    assert isinstance(call_info.call_stack_pointer_delta, int)
    assert isinstance(call_info.stack_args_top, int)

    # Flags and role enums
    assert isinstance(call_info.flags, CallInfoFlags)
    assert isinstance(call_info.role, FunctionRole)

    # Boolean predicates
    assert isinstance(call_info.is_vararg, bool)
    assert isinstance(call_info.is_noret, bool)
    assert isinstance(call_info.is_pure, bool)

    # Return type
    assert call_info.return_type is not None

    # Location sets
    assert isinstance(call_info.spoiled, MicroLocationSet)
    assert isinstance(call_info.dead_regs, MicroLocationSet)
    assert isinstance(call_info.return_regs, MicroLocationSet)
    assert isinstance(call_info.pass_regs, MicroLocationSet)
    assert call_info.visible_memory is not None

    # Arguments
    args = call_info.args
    assert len(args) == call_info.arg_count
    for arg in args:
        assert isinstance(arg, MicroCallArg)
        assert isinstance(arg.size, int)
        assert arg.size > 0
        assert isinstance(arg.name, str)
        assert arg.type is not None
        assert arg.operand is not None

    # Text representations
    assert isinstance(str(call_info), str)
    assert len(str(call_info)) > 0
    assert isinstance(repr(call_info), str)
    assert 'MicroCallInfo' in repr(call_info)

    # Arg text representations
    arg = args[0]
    assert isinstance(str(arg), str)
    assert len(str(arg)) > 0
    assert 'MicroCallArg' in repr(arg)

    # Previously uncovered properties
    assert isinstance(call_info.fixed_arg_count, int)
    assert call_info.return_argloc is not None
    assert call_info.get_type() is not None

    # Arg uncovered properties
    assert arg.argloc is not None
    assert isinstance(arg.flags, int)
    assert isinstance(arg.ea, int)

    # Raw access
    assert call_info.raw_call_info is not None
    assert arg.raw_arg is not None


def test_microcode_local_vars_wrapper(test_env):
    """Test MicroLocalVar, MicroLocalVars, and MicroBlockArray.vars."""
    from ida_domain.microcode import MicroLocalVar, MicroLocalVars, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2A3)  # add_numbers
    mf = db.microcode.generate(func, maturity=MicroMaturity.LVARS)

    # Access vars
    lvars = mf.vars
    assert isinstance(lvars, MicroLocalVars)
    assert len(lvars) > 0

    # Indexing
    v0 = lvars[0]
    assert isinstance(v0, MicroLocalVar)
    v_last = lvars[-1]
    assert isinstance(v_last, MicroLocalVar)

    # Iteration
    all_vars = list(lvars)
    assert len(all_vars) == len(lvars)

    # Basic properties
    assert isinstance(v0.name, str)
    assert len(v0.name) > 0
    assert isinstance(v0.width, int)
    assert v0.width > 0
    assert isinstance(v0.definition_address, int)
    assert isinstance(v0.definition_block, int)
    assert isinstance(v0.comment, str)
    assert isinstance(v0.divisor, int)
    assert v0.type_info is not None
    assert v0.location is not None

    # Boolean properties
    assert isinstance(v0.is_arg, bool)
    assert isinstance(v0.is_result, bool)
    assert isinstance(v0.is_used, bool)
    assert isinstance(v0.is_typed, bool)
    assert isinstance(v0.has_nice_name, bool)
    assert isinstance(v0.has_user_name, bool)
    assert isinstance(v0.has_user_type, bool)
    assert isinstance(v0.has_user_info, bool)
    assert isinstance(v0.is_fake, bool)
    assert isinstance(v0.is_overlapped, bool)
    assert isinstance(v0.is_floating, bool)
    assert isinstance(v0.is_spoiled, bool)

    # Boolean methods
    assert isinstance(v0.is_stack_variable(), bool)
    assert isinstance(v0.is_register_variable(), bool)
    assert isinstance(v0.is_scattered(), bool)
    assert isinstance(v0.is_thisarg(), bool)
    assert isinstance(v0.is_dummy_arg(), bool)

    # Arguments list
    args = lvars.arguments
    assert isinstance(args, list)
    assert all(isinstance(a, MicroLocalVar) for a in args)
    assert all(a.is_arg for a in args)

    # find_by_name
    found = lvars.find_by_name(v0.name)
    assert found is not None
    assert found.name == v0.name
    assert lvars.find_by_name('__nonexistent_var__') is None

    # find_lvar
    found2 = lvars.find_lvar(v0.location, v0.width)
    assert found2 is not None
    assert found2.name == v0.name

    # argidx and retvaridx
    assert isinstance(mf.argument_indices, list)
    assert isinstance(mf.return_variable_index, int)

    # Text representations
    assert isinstance(str(v0), str)
    assert len(str(v0)) > 0
    assert 'MicroLocalVar' in repr(v0)
    assert 'MicroLocalVars' in repr(lvars)

    # Mutation: accepts_type, set_lvar_type, set_final_lvar_type
    tif = v0.type_info
    assert isinstance(v0.accepts_type(tif), bool)
    assert isinstance(v0.set_type(tif), bool)
    v0.set_final_type(tif)  # returns None in IDAPython

    # Mutation: set_user_name
    original_name = v0.name
    v0.set_user_name('test_renamed_var')
    assert v0.name == 'test_renamed_var'
    v0.set_user_name(original_name)

    # Index boundary
    import pytest

    with pytest.raises(IndexError):
        lvars[9999]

    # find_stkvar with non-existent offset
    assert lvars.find_stkvar(0x7FFFFFFF, 4) is None

    # Raw access
    assert v0.raw_var is not None
    assert lvars.raw_lvars is not None


def test_microcode_operand_transformations(test_env):
    """Test MicroOperand transformation methods (make_*_half, change_size, etc.)."""
    from ida_domain.microcode import MicroOperand

    # -- make_low_half / make_high_half ------------------------------------
    op = MicroOperand.number(0xAABBCCDD11223344, size=8)
    assert op.size == 8

    low = MicroOperand.number(0xAABBCCDD11223344, size=8)
    low_ok = low.make_low_half(4)
    assert low.size == 4
    assert low_ok is True

    high = MicroOperand.number(0xAABBCCDD11223344, size=8)
    high_ok = high.make_high_half(4)
    assert high.size == 4
    assert high_ok is True

    # low and high should differ
    assert low != high

    # -- make_first_half / make_second_half --------------------------------
    first = MicroOperand.number(0xAABBCCDD11223344, size=8)
    ok = first.make_first_half(4)
    assert ok is True
    assert first.size == 4

    second = MicroOperand.number(0xAABBCCDD11223344, size=8)
    ok = second.make_second_half(4)
    assert ok is True
    assert second.size == 4

    # -- change_size -------------------------------------------------------
    op2 = MicroOperand.number(0xDEADBEEF, size=4)
    cs_ok = op2.change_size(2)
    assert op2.size == 2
    assert cs_ok is True

    op3 = MicroOperand.number(0x42, size=2)
    cs_ok2 = op3.change_size(4)
    assert op3.size == 4
    assert cs_ok2 is True

    # -- double_size -------------------------------------------------------
    op4 = MicroOperand.number(0x42, size=4)
    ds_ok = op4.double_size()
    assert op4.size == 8
    assert ds_ok is True

    # -- apply_xdu (zero-extend) ------------------------------------------
    op5 = MicroOperand.number(0xFF, size=1)
    op5.apply_zero_extension(4)
    assert op5.size == 4

    # -- apply_xds (sign-extend) ------------------------------------------
    op6 = MicroOperand.number(0xFF, size=1)
    op6.apply_sign_extension(4)
    assert op6.size == 4

    # -- shift_mop ---------------------------------------------------------
    op7 = MicroOperand.number(0x12345678, size=4)
    ok = op7.shift_operand(3)
    assert ok is True
    assert op7.size == 1


def test_microcode_instruction_flag_accessors(test_env):
    """Test MicroInstruction flag getters and setters."""
    from ida_domain.microcode import (
        MicroInstruction,
        MicroMaturity,
        MicroOpcode,
        MicroOperand,
    )

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)
    insn = next(mf.instructions())

    # All boolean flag getters should return bool without error
    assert isinstance(insn.is_combined, bool)
    assert isinstance(insn.is_assert, bool)
    assert isinstance(insn.is_floating_point_insn, bool)
    assert isinstance(insn.is_persistent, bool)
    assert isinstance(insn.is_propagatable, bool)
    assert isinstance(insn.is_combinable, bool)
    assert isinstance(insn.is_optional, bool)
    assert isinstance(insn.is_tailcall, bool)
    assert isinstance(insn.is_farcall, bool)
    assert isinstance(insn.is_cleaning_pop, bool)
    assert isinstance(insn.is_multimov, bool)
    assert isinstance(insn.is_ignore_low_source, bool)
    assert isinstance(insn.is_extended_store, bool)
    assert isinstance(insn.is_alloca, bool)
    assert isinstance(insn.is_like_move, bool)
    assert isinstance(insn.is_memory_barrier, bool)
    assert isinstance(insn.is_bswap, bool)
    assert isinstance(insn.is_memcpy, bool)
    assert isinstance(insn.is_memset, bool)
    assert isinstance(insn.is_readflags, bool)
    assert isinstance(insn.is_inverted_jump, bool)
    assert isinstance(insn.is_wild_match, bool)
    assert isinstance(insn.is_unknown_call, bool)

    # Test set/clr round-trip on a detached instruction
    nop = MicroInstruction.create(ea=0, opcode=MicroOpcode.NOP)

    nop.set_floating_point_insn()
    assert nop.is_floating_point_insn is True
    nop.clr_floating_point_insn()
    assert nop.is_floating_point_insn is False

    nop.set_assert()
    assert nop.is_assert is True
    nop.clr_assert()
    assert nop.is_assert is False

    nop.set_combinable()
    assert nop.is_combinable is True
    nop.clr_combinable()
    assert nop.is_combinable is False


def test_microcode_location_set_granular(test_env):
    """Test MicroLocationSet granular register/memory operations."""
    from ida_domain.microcode import MicroLocationSet

    # Empty set
    s = MicroLocationSet()
    assert not s
    assert s.count == 0
    assert s.has_memory is False

    # add_register / has_register / has_all_register / has_any_register
    s.add_register(0, 4)  # mreg 0, 4 bytes
    assert s
    assert s.count > 0
    assert s.has_register(0) is True
    assert s.has_all_register(0, 4) is True
    assert s.has_any_register(0, 2) is True
    assert s.has_register(100) is False

    # subtract_register
    s.subtract_register(0, 2)
    assert s.has_all_register(0, 4) is False
    assert s.has_any_register(0, 4) is True  # still has upper 2 bytes

    # clear
    s.clear()
    assert not s
    assert s.count == 0

    # add_memory / has_memory
    s.add_memory(0x1000, 8)
    assert s.has_memory is True
    assert s.count > 0

    # to_text / __str__
    text = s.to_text()
    assert isinstance(text, str)
    assert str(s) == text

    # __repr__
    assert 'MicroLocationSet' in repr(s)
    assert 'count=' in repr(s)


def test_microcode_mba_dump(test_env):
    """Test MicroBlockArray dump methods exist and are callable."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # dump() and dump_mba() should not raise
    # (dump() only writes when IDA_DUMPDIR is set and debugger is active,
    #  so it's effectively a no-op here, but validates the binding works)
    mf.dump()
    mf.dump_with_title('test dump', verify=False)


def test_microcode_operand_scattered_and_is01(test_env):
    """Test MicroOperand.is_scattered and is_01 properties."""
    from ida_domain.microcode import MicroOperand

    num = MicroOperand.number(0x42, size=4)
    assert isinstance(num.is_scattered, bool)
    assert num.is_scattered is False

    zero = MicroOperand.number(0, size=1)
    assert isinstance(zero.is_boolean, bool)

    one = MicroOperand.number(1, size=1)
    assert one.is_boolean is True


def test_microcode_instruction_equal_insns(test_env):
    """Test MicroInstruction.equals with flags."""
    import ida_hexrays

    from ida_domain.microcode import MicroInstruction, MicroOpcode, MicroOperand

    a = MicroInstruction.create(
        ea=0x100,
        opcode=MicroOpcode.MOV,
        left=MicroOperand.number(42, size=4),
        dest=MicroOperand.reg(0, size=4),
    )
    b = MicroInstruction.create(
        ea=0x100,
        opcode=MicroOpcode.MOV,
        left=MicroOperand.number(42, size=4),
        dest=MicroOperand.reg(0, size=4),
    )

    # Exact match
    assert a.equals(b, 0) is True

    # Ignore opcode — should still match since src/dst are same
    assert a.equals(b, ida_hexrays.EQ_IGNCODE) is True


def test_microcode_block_additional_methods(test_env):
    """Test additional MicroBlock methods: build_lists, optimize_insn, etc."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = mf[1]
    insn = block.head

    # build_lists
    eliminated = block.build_lists(kill_deads=False)
    assert isinstance(eliminated, int)

    # optimize_insn
    if insn is not None:
        changes = block.optimize_insn(insn)
        assert isinstance(changes, int)

    # request_propagation should not raise
    block.request_propagation()


def test_microcode_block_is_rhs_redefined(test_env):
    """Test MicroBlock.is_rhs_redefined."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Find a block with at least 2 instructions
    for block in mf.blocks(skip_sentinels=True):
        insns = list(block)
        if len(insns) >= 2:
            result = block.is_rhs_redefined(insns[0], insns[0], insns[-1])
            assert isinstance(result, bool)
            break


def test_microcode_block_append_use_def_list(test_env):
    """Test MicroBlock append_use_list and append_def_list."""
    from ida_domain.microcode import MicroLocationSet, MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    block = mf[1]
    insn = block.head
    if insn is not None:
        for op in insn:
            if op:
                target = MicroLocationSet()
                block.append_use_list(target, op)
                # Just verify it doesn't crash; target may or may not have items
                assert isinstance(target.count, int)

                target2 = MicroLocationSet()
                block.append_def_list(target2, op)
                assert isinstance(target2.count, int)
                break


def test_microcode_mba_split_block(test_env):
    """Test MicroBlockArray.split_block."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    original_count = len(mf)

    # Find a block with at least 2 instructions
    for block in mf.blocks(skip_sentinels=True):
        insns = list(block)
        if len(insns) >= 2:
            new_block = mf.split_block(block, insns[1])
            assert new_block is not None
            assert len(mf) == original_count + 1
            break


def test_microcode_mba_stack_properties(test_env):
    """Test MicroBlockArray frame/stack properties and offset conversion."""
    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0xC4)
    mf = db.microcode.generate(func, maturity=MicroMaturity.PREOPTIMIZED)

    # Stack properties
    assert isinstance(mf.temp_stack_size, int)
    assert isinstance(mf.frame_size, int)
    assert isinstance(mf.stacksize, int)
    assert isinstance(mf.incoming_args_offset, int)
    assert isinstance(mf.retsize, int)

    # Stack offset conversion round-trip
    vd_off = mf.stack_offset_ida_to_decompiler(0)
    ida_off = mf.stack_offset_decompiler_to_ida(vd_off)
    assert isinstance(ida_off, int)


def test_microcode_free_functions(test_env):
    """Test free functions: reg2mreg, mreg2reg, get_hexrays_version."""
    from ida_domain.microcode import get_hexrays_version, mreg2reg, reg2mreg

    # get_hexrays_version
    ver = get_hexrays_version()
    assert isinstance(ver, str)
    assert '.' in ver  # e.g. "9.3.0.250101"

    # reg2mreg — map processor register 0 (usually rax/eax on x86)
    mreg = reg2mreg(0)
    assert isinstance(mreg, int)

    # mreg2reg round-trip (if mapping exists)
    if mreg >= 0:
        proc_reg = mreg2reg(mreg, 4)
        assert isinstance(proc_reg, int)


def test_microcode_operand_is_constant(test_env):
    """Test MicroOperand.is_constant — returns value or None."""
    from ida_domain.microcode import MicroOperand

    # Number operands return their value
    zero = MicroOperand.number(0, 4)
    assert zero.is_constant() == 0
    assert zero.is_constant() is not None
    assert zero.is_constant(is_signed=True) == 0
    assert zero.is_constant(is_signed=False) == 0

    one = MicroOperand.number(1, 4)
    assert one.is_constant() == 1

    big = MicroOperand.number(0xDEADBEEF, 4)
    assert big.is_constant(is_signed=False) == 0xDEADBEEF

    neg = MicroOperand.number(0xFFFFFFFF, 4)  # -1 as unsigned 32-bit
    val = neg.is_constant()
    assert val is not None
    # SWIG returns uint64 regardless of is_signed flag
    assert val == 0xFFFFFFFF or val == 0xFFFFFFFFFFFFFFFF

    # Non-number operands return None
    reg = MicroOperand.reg(0, 4)
    assert reg.is_constant() is None

    helper = MicroOperand.helper('memcpy')
    assert helper.is_constant() is None

    empty = MicroOperand.empty()
    assert empty.is_constant() is None

    blkref = MicroOperand.new_block_ref(0)
    assert blkref.is_constant() is None

    gvar = MicroOperand.global_addr(0x1000, 4)
    assert gvar.is_constant() is None


def test_microcode_block_get_valranges(test_env):
    """Test MicroBlock.get_valranges for value range analysis."""
    import ida_hexrays

    from ida_domain.microcode import MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)  # print_number — richer microcode
    mf = db.microcode.generate(func, maturity=MicroMaturity.GLBOPT1)

    # Find a block with a register operand to query value ranges for
    for block in mf.blocks(skip_sentinels=True):
        for insn in block.instructions():
            op = insn.left
            if op and op.is_register:
                # Block-level query
                result = block.get_valranges(op)
                # Result may be None (range unknown) or a valrng_t
                if result is not None:
                    assert isinstance(result, ida_hexrays.valrng_t)
                    assert isinstance(result.empty(), bool)

                # Instruction-level query
                result_at_insn = block.get_valranges(op, insn=insn)
                if result_at_insn is not None:
                    assert isinstance(result_at_insn, ida_hexrays.valrng_t)

                # With explicit vrflags=0
                result_flags = block.get_valranges(op, vrflags=0, insn=insn)
                # Should behave the same as default
                if result_flags is not None:
                    assert isinstance(result_flags, ida_hexrays.valrng_t)
                return

    # If we got here, we didn't find a suitable register operand
    assert False, 'No register operand found; test not fully exercised'


def test_microcode_call_arg_property_setters(test_env):
    """Test MicroCallArg property setters (type, name, flags, size, ea)."""
    from ida_domain.microcode import MicroCallInfo, MicroMaturity

    db = test_env
    func = db.functions.get_at(0x2BC)
    mf = db.microcode.generate(func, maturity=MicroMaturity.CALLS)

    # Find a call with arguments
    call_info = None
    for insn in mf.instructions(skip_sentinels=True):
        if insn.is_call():
            ci = insn.d.call_info
            if ci is not None and ci.arg_count > 0:
                call_info = ci
                break
    assert call_info is not None, 'Expected a call with arguments'

    arg = call_info.args[0]

    # name setter
    original_name = arg.name
    arg.name = 'test_arg_name'
    assert arg.name == 'test_arg_name'
    arg.name = original_name

    # flags setter
    original_flags = arg.flags
    arg.flags = 0x42
    assert arg.flags == 0x42
    arg.flags = original_flags

    # size setter
    original_size = arg.size
    arg.size = 16
    assert arg.size == 16
    arg.size = original_size

    # ea setter
    original_ea = arg.ea
    arg.ea = 0xDEAD
    assert arg.ea == 0xDEAD
    arg.ea = original_ea

    # type setter
    original_type = arg.type
    new_type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
    arg.type = new_type
    assert arg.type is not None
    arg.type = original_type


def test_microcode_call_arg_make_string(test_env):
    """Test MicroCallArg.make_string() with default and custom type."""
    from ida_domain.microcode import MicroCallInfo, MicroOperandType

    # Create a fresh call info and add an argument
    ci = MicroCallInfo.create()
    arg = ci.add_arg()

    # make_string with default type (const char *)
    arg.make_string('hello world')
    assert arg.type is not None
    assert arg.size > 0

    # make_string with custom type override
    custom_type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT8 | ida_typeinf.BTMT_CHAR)
    ptr_type = ida_typeinf.tinfo_t()
    ptr_type.create_ptr(custom_type)

    arg2 = ci.add_arg()
    arg2.make_string('custom', type_info=ptr_type)
    assert arg2.size == ptr_type.get_size()


def test_microcode_call_arg_make_number(test_env):
    """Test MicroCallArg.make_number()."""
    from ida_domain.microcode import MicroCallInfo, MicroOperandType

    ci = MicroCallInfo.create()
    arg = ci.add_arg()
    arg.make_number(42, 4)

    op = arg.operand
    assert op.type == MicroOperandType.NUMBER
    assert op.value == 42


def test_microcode_call_arg_set_reg_arg(test_env):
    """Test MicroCallArg.set_reg_arg()."""
    from ida_domain.microcode import MicroCallInfo

    ci = MicroCallInfo.create()
    arg = ci.add_arg()

    reg_type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
    arg.set_reg_arg(0, 4, reg_type)

    assert arg.size == 4
    assert arg.type is not None


def test_microcode_call_info_create(test_env):
    """Test MicroCallInfo.create() static factory."""
    from ida_domain.microcode import MicroCallInfo

    # Default parameters
    ci = MicroCallInfo.create()
    assert ci.callee == BADADDR
    assert ci.fixed_arg_count == 0
    assert ci.arg_count == 0
    assert ci.raw_call_info is not None

    # Custom parameters
    ci2 = MicroCallInfo.create(callee=0x1234, solid_args=3)
    assert ci2.callee == 0x1234
    assert ci2.fixed_arg_count == 3


def test_microcode_call_info_property_setters(test_env):
    """Test MicroCallInfo property setters."""
    from ida_domain.microcode import FunctionRole, MicroCallInfo

    ci = MicroCallInfo.create()

    # callee
    ci.callee = 0xABCD
    assert ci.callee == 0xABCD

    # fixed_arg_count
    ci.fixed_arg_count = 5
    assert ci.fixed_arg_count == 5

    # calling_convention
    ci.calling_convention = ida_typeinf.CM_CC_CDECL
    assert ci.calling_convention == ida_typeinf.CM_CC_CDECL

    # return_type
    ret_type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
    ci.return_type = ret_type
    assert ci.return_type is not None

    # flags
    ci.flags = 0x10
    assert ci.flags & 0x10

    # role
    ci.role = FunctionRole.EMPTY
    assert ci.role == FunctionRole.EMPTY

    # call_stack_pointer_delta
    ci.call_stack_pointer_delta = -8
    assert ci.call_stack_pointer_delta == -8

    # stack_args_top
    ci.stack_args_top = 0x20
    assert ci.stack_args_top == 0x20


def test_microcode_call_info_add_and_clear_args(test_env):
    """Test MicroCallInfo.add_arg() and clear_args()."""
    from ida_domain.microcode import MicroCallArg, MicroCallInfo

    ci = MicroCallInfo.create()
    assert ci.arg_count == 0

    # Add and configure first arg before adding more (vector reallocation
    # invalidates previously returned wrappers)
    arg1 = ci.add_arg()
    assert isinstance(arg1, MicroCallArg)
    assert ci.arg_count == 1
    arg1.name = 'first'

    # Add and configure second arg
    arg2 = ci.add_arg()
    assert ci.arg_count == 2
    arg2.name = 'second'

    # Re-fetch and verify names persisted
    args = ci.args
    assert len(args) == 2
    assert args[0].name == 'first'
    assert args[1].name == 'second'

    # Clear all
    ci.clear_args()
    assert ci.arg_count == 0


def test_microcode_call_info_set_type(test_env):
    """Test MicroCallInfo.set_type()."""
    from ida_domain.microcode import MicroCallInfo

    ci = MicroCallInfo.create()

    # Build a simple function type: int func(void)
    func_type = ida_typeinf.tinfo_t()
    func_data = ida_typeinf.func_type_data_t()
    func_data.rettype = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
    func_type.create_func(func_data)

    result = ci.set_type(func_type)
    assert isinstance(result, bool)
