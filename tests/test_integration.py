import subprocess
import sys
from pathlib import Path

import pytest

import ida_domain  # isort: skip
import conftest

from ida_domain.base import DatabaseError
from ida_domain.database import IdaCommandOptions
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
        cmd = [sys.executable, str(script_path), '-f', str(conftest.idb_path)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        print(f'Example {script_path} outputs')
        print('\n[STDOUT]')
        print(result.stdout)
        print('[STDERR]')
        print(result.stderr)

        assert result.returncode == 0, f'Example {script_path} failed to run'

    # analyze_xrefs.py requires additional arguments
    script_path = Path(__file__).parent.parent / 'examples' / 'analyze_xrefs.py'
    cmd = [sys.executable, str(script_path), '-f', str(conftest.idb_path), '-a', '0xd6']

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
        idb = str(conftest.idb_path)
        with ida_domain.Database.open(idb, ida_options, save_on_close=False) as db:
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
        cmd = [sys.executable, str(script_path), '-f', str(conftest.idb_path)]

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
        idb = str(conftest.idb_path)
        with ida_domain.Database.open(idb, ida_options, save_on_close=False) as db:
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
