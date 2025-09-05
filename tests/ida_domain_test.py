import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import ida_domain  # isort: skip
import ida_typeinf
from ida_idaapi import BADADDR

import ida_domain.flowchart
from ida_domain.base import InvalidParameterError
from ida_domain.bytes import SearchFlags
from ida_domain.database import IdaCommandOptions
from ida_domain.instructions import Instructions
from ida_domain.segments import *
from ida_domain.strings import StringListConfig, StringType
from ida_domain.types import TypeDetails, TypeKind

idb_path: str = ''
logger = logging.getLogger(__name__)


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
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'test.bin')

    # Copy the test binary from resources folder under our tests working directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'test.bin')
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
    assert db.module == 'test.bin'
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

    assert 'test.bin' in metadata.path
    assert metadata.module == 'test.bin'
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
    with ida_domain.Database.open(idb_path) as db2:
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

    microcode_lines = db.functions.get_microcode(func)
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

    db.strings.rebuild(config=StringListConfig(min_len=5))

    for i in db.strings:
        logger.debug(i)

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
    assert 'test.bin.i64' in match_info.lib

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
    if ida_domain.__ida_version__ >= 920:
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


def test_readme_examples():
    """
    Make sure the example shipped in readme is updated
    """
    example_path = Path(__file__).parent.parent / 'examples' / 'explore_database.py'
    readme_path = Path(__file__).parent.parent / 'README.md'

    # Read both files
    example_content = example_path.read_text().strip()
    readme_content = readme_path.read_text()

    # Check if example exists in readme
    assert example_content in readme_content, f'Example from {example_path} not found in README'


def test_migrated_examples():
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
            except RuntimeError as e:
                assert False, f'Example {script_path.name} failed to run, error {e}'
            print(f'Executing migrated IDA Python example {script_path.name} finised\n<<<=====')
