"""
Run the scripts shipped in examples/.

Every tracked example must be listed in exactly one of the tables below (or in
NOT_RUN with a reason); test_all_examples_are_run fails otherwise. Pick the table
by how the script is meant to be run:

- STANDALONE: ``python script.py -f <binary> [args]``; the script opens the database
- INSIDE_IDA: executed in an already open database with the cursor at ``ea``
- PLUGINS: IDA plugins. Installed, exercised, then removed
- OWN_TEST: scripts that need a test of their own (UI actions, faked UI state, ...),
  mapped to the name of that test
"""

import gc
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

import ida_domain  # isort: skip
import conftest
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin

from ida_domain.base import DatabaseError, DecompilerError
from ida_domain.comments import ExtraCommentKind
from ida_domain.database import IdaCommandOptions
from ida_domain.pseudocode import Pseudocode, PseudocodeError

EXAMPLES_DIR = Path(__file__).parent.parent / 'examples'


def _standalone(script, *args):
    return pytest.param(script, list(args), id=' '.join([script, *args]))


def _inside(script, binary, ea, exit_code=0, marks=()):
    at = 'no-ea' if ea is None else f'{ea:#x}'
    return pytest.param(script, binary, ea, exit_code, marks=marks, id=f'{script}-{binary}-{at}')


STANDALONE = [
    _standalone('analyze_bytes.py'),
    _standalone('analyze_database.py'),
    _standalone('analyze_functions.py'),
    _standalone('analyze_strings.py'),
    _standalone('analyze_xrefs.py', '-a', '0xd6'),
    _standalone('explore_database.py'),
    _standalone('explore_flirt.py'),
    _standalone('hooks_example.py'),
    _standalone('manage_types.py'),
    _standalone('my_first_script.py'),
    _standalone('quick_example.py'),
    _standalone('ida-python-equivalents/decompiler/decompile_entry_points.py'),
    _standalone('ida-python-equivalents/decompiler/produce_c_file.py'),
]

# There was a problem with leak in decompiler that crashes below 9.4
_PFUNC_LEAK = conftest.min_ida_version('9.4')
_DECOMPILER = 'ida-python-equivalents/decompiler'
_DISASSEMBLER = 'ida-python-equivalents/disassembler'
INSIDE_IDA = [
    _inside('ida_console_example.py', 'tiny_asm', None),
    _inside('ida-python-equivalents/debugger/automatic_steps.py', 'tiny_asm', 0x307),
    _inside(f'{_DECOMPILER}/vds1.py', 'tiny_asm', 0xC4),
    _inside(f'{_DECOMPILER}/vds1.py', 'tiny_asm', 0x330),
    _inside(f'{_DECOMPILER}/vds1.py', 'tiny_c', 0x120),
    _inside(f'{_DECOMPILER}/vds4.py', 'tiny_asm', 0xC4, marks=_PFUNC_LEAK),
    _inside(f'{_DECOMPILER}/vds4.py', 'tiny_asm', 0x330, exit_code=1),
    _inside(f'{_DECOMPILER}/vds7.py', 'tiny_asm', 0xC4, marks=_PFUNC_LEAK),
    _inside(f'{_DECOMPILER}/vds7.py', 'tiny_asm', 0x330, exit_code=1),
    _inside(f'{_DECOMPILER}/vds13.py', 'tiny_asm', 0xC4),
    _inside(f'{_DECOMPILER}/vds13.py', 'tiny_asm', 0x330, exit_code=1),
    _inside(f'{_DECOMPILER}/vds13.py', 'tiny_c', 0x120, exit_code=1),
    _inside(f'{_DECOMPILER}/vds_modify_user_lvars.py', 'tiny_asm', 0xC4, marks=_PFUNC_LEAK),
    _inside(f'{_DECOMPILER}/vds_modify_user_lvars.py', 'tiny_asm', 0x330, exit_code=1),
    _inside(f'{_DISASSEMBLER}/assemble.py', 'tiny_asm', 0x30),
    _inside(f'{_DISASSEMBLER}/dump_flowchart.py', 'tiny_asm', 0xC4),
    _inside(f'{_DISASSEMBLER}/dump_flowchart.py', 'tiny_asm', 0x330),
    _inside(f'{_DISASSEMBLER}/list_function_items.py', 'tiny_asm', 0xC4),
    _inside(f'{_DISASSEMBLER}/list_function_items.py', 'tiny_asm', 0x330),
    _inside(f'{_DISASSEMBLER}/list_segment_functions.py', 'tiny_asm', 0xC4),
    _inside(f'{_DISASSEMBLER}/list_segment_functions.py', 'tiny_asm', 0x0),
    _inside(f'{_DISASSEMBLER}/list_strings.py', 'tiny_asm', 0xC4),
    _inside(f'{_DISASSEMBLER}/log_idb_events.py', 'tiny_asm', 0xC4),
    _inside('ida-python-equivalents/types/create_libssh2_til.py', 'tiny_asm', 0xC4),
    _inside('ida-python-equivalents/types/create_struct_by_parsing.py', 'tiny_asm', 0xC4),
]

PLUGINS = [
    f'{_DECOMPILER}/vds10.py',
    f'{_DECOMPILER}/vds11.py',
    f'{_DECOMPILER}/vds19.py',
]

OWN_TEST = {
    f'{_DISASSEMBLER}/dump_extra_comments.py': 'test_dump_extra_comments_actions',
    f'{_DECOMPILER}/vds12.py': 'test_vds12_with_faked_ui',
}

# {script: reason it cannot be run}
NOT_RUN: dict = {}


def _binary_path(binary: str) -> str:
    return {'tiny_asm': conftest.idb_path, 'tiny_c': conftest.tiny_c_idb_path}[binary]


def _exec_in_own_namespace(script_path: Path) -> dict:
    """Execute a script in a fresh namespace so nothing it creates outlives the test."""
    namespace = {'__name__': '__example__', '__file__': str(script_path)}
    exec(compile(script_path.read_text(encoding='utf-8'), str(script_path), 'exec'), namespace)
    return namespace


def test_all_examples_are_run():
    """Every tracked example is listed in one of the tables above (or in NOT_RUN)."""
    try:
        tracked = subprocess.run(
            ['git', 'ls-files', '*.py'],
            cwd=EXAMPLES_DIR,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip('not a git checkout')

    listed = [p.values[0] for p in STANDALONE + INSIDE_IDA] + PLUGINS
    listed += list(OWN_TEST) + list(NOT_RUN)
    missing = sorted(set(tracked) - set(listed))
    stale = sorted(set(listed) - set(tracked))
    assert not missing, (
        f'Examples not run by any test, add them to a table in {__file__}: {missing}'
    )
    assert not stale, f'Listed examples that do not exist: {stale}'
    no_test = sorted(name for name in OWN_TEST.values() if not callable(globals().get(name)))
    assert not no_test, f'OWN_TEST names tests that do not exist: {no_test}'


def test_examples_path():
    examples = ida_domain.examples_path()

    assert examples.is_dir()
    assert examples.joinpath('quick_example.py').is_file()
    assert examples.joinpath('ida-python-equivalents', 'decompiler', 'vds1.py').is_file()


def test_readme_examples():
    """
    Make sure the example shipped in readme is updated
    """
    example_path = EXAMPLES_DIR / 'explore_database.py'
    readme_path = Path(__file__).parent.parent / 'README.md'

    example_content = example_path.read_text(encoding='utf-8').strip()
    readme_content = readme_path.read_text(encoding='utf-8')

    assert example_content in readme_content, f'Example from {example_path} not found in README'


@pytest.mark.parametrize('script, args', STANDALONE)
def test_standalone(script, args):
    script_path = EXAMPLES_DIR / script
    cmd = [sys.executable, str(script_path), '-f', str(conftest.idb_path), *args]

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(f'Example {script_path} outputs')
    print('\n[STDOUT]')
    print(result.stdout)
    print('[STDERR]')
    print(result.stderr)

    assert result.returncode == 0, f'Example {script_path} failed to run'


def _run_bulk_example_with_failing_decompile(script, db, monkeypatch, tmp_path, failing_ea):
    """
    Run a bulk decompile example on the open ``db`` with decompilation of the function
    at ``failing_ea`` failing; the test binaries have no function that fails on its own.
    Returns the generated C file text.
    """
    real_decompile = Pseudocode.decompile

    def decompile(self, ea_or_func, *args, **kwargs):
        ea = ea_or_func.start_ea if isinstance(ea_or_func, ida_funcs.func_t) else ea_or_func
        if ea == failing_ea:
            raise PseudocodeError(f'injected failure at {ea:#x}')
        return real_decompile(self, ea_or_func, *args, **kwargs)

    input_file = tmp_path / 'input.bin'
    monkeypatch.setattr(Pseudocode, 'decompile', decompile)
    monkeypatch.setattr(ida_domain.Database, 'open', lambda *args, **kwargs: db)
    monkeypatch.setattr(sys, 'argv', [script, '-f', str(input_file)])

    namespace = _exec_in_own_namespace(EXAMPLES_DIR / script)
    try:
        assert namespace['main']() == 0
    finally:
        namespace.clear()

    return Path(f'{input_file}.c').read_text()


def test_produce_c_file_survives_decompilation_failure(test_env, monkeypatch, tmp_path, capsys):
    """One function fails to decompile: it is reported and the others are still written"""
    failing_ea = 0x2AF  # multiply_numbers; the other 7 functions of tiny_asm decompile

    c_text = _run_bulk_example_with_failing_decompile(
        f'{_DECOMPILER}/produce_c_file.py', test_env, monkeypatch, tmp_path, failing_ea
    )

    assert f'injected failure at {failing_ea:#x}' in c_text
    assert '// Function: level3_func' in c_text, 'functions after the failure are skipped'
    assert 'Successfully decompiled 7 of 8 functions' in capsys.readouterr().out


def test_decompile_entry_points_survives_decompilation_failure(tiny_c_env, monkeypatch, tmp_path):
    """The first entry point fails to decompile: it is reported and the next one is written"""
    failing_ea = 0x0  # use_val; the other entry point (complex_assignments, 0x1a) decompiles

    c_text = _run_bulk_example_with_failing_decompile(
        f'{_DECOMPILER}/decompile_entry_points.py', tiny_c_env, monkeypatch, tmp_path, failing_ea
    )

    assert f'injected failure at {failing_ea:#x}' in c_text
    assert '// Function at 0x1A' in c_text, 'entry points after the failure are skipped'


@pytest.mark.parametrize('script, binary, ea, exit_code', INSIDE_IDA)
def test_inside_ida(tiny_c_setup, script, binary, ea, exit_code):
    script_path = EXAMPLES_DIR / script
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(_binary_path(binary), ida_options, save_on_close=False) as db:
        if ea is not None:
            db.current_ea = ea
            db.start_ip = ea
        if exit_code == 0:
            db.execute_script(script_path)
        else:
            with pytest.raises(DatabaseError, match=f'exit code {exit_code}'):
                db.execute_script(script_path)


@conftest.min_ida_version('9.2')
@pytest.mark.parametrize('script', PLUGINS)
def test_plugin(tiny_pseudocode_env, script):
    """
    Make sure the decompiler plugins install, run their optimizer callbacks
    without errors while decompiling, and uninstall cleanly
    """
    db = tiny_pseudocode_env
    namespace = _exec_in_own_namespace(EXAMPLES_DIR / script)

    plugin = namespace['PLUGIN_ENTRY']()
    assert plugin.init() == ida_idaapi.PLUGIN_KEEP

    # The decompiler only prints exceptions raised inside optimizer callbacks
    errors = []
    calls = 0
    optimize = plugin.optimizer.optimize

    def recording_optimize(*args):
        nonlocal calls
        calls += 1
        try:
            return optimize(*args)
        except Exception:
            errors.append(traceback.format_exc())
            raise

    plugin.optimizer.optimize = recording_optimize
    try:
        plugin.run(1)  # uninstall
        plugin.run(2)  # install again
        for func in db.functions:
            try:
                db.pseudocode.decompile(func)
            except DecompilerError:
                pass  # some functions of the test binary don't decompile
    finally:
        plugin.term()
        del plugin, optimize, recording_optimize
        namespace.clear()
        gc.collect()

    assert calls > 0, f'{script} optimizer was never called'
    assert not errors, f'{script} optimizer raised:\n{errors[0]}'


def test_dump_extra_comments_actions(test_env, capsys):
    """
    Invoke the actions registered by dump_extra_comments.py; running it only
    registers them, so it never reaches their code on its own
    """
    db = test_env
    ea = 0x307
    db.comments.set_extra_at(ea, 0, 'anterior line', ExtraCommentKind.ANTERIOR)
    db.current_ea = ea

    namespace = _exec_in_own_namespace(EXAMPLES_DIR / _DISASSEMBLER / 'dump_extra_comments.py')
    try:
        for kind in ExtraCommentKind:
            assert namespace['dump_at_point_handler_t'](kind.value).activate(None) == 1
    finally:
        namespace.clear()

    out = capsys.readouterr().out
    assert "Got [0]: 'anterior line'" in out
    assert f'No posterior comments at 0x{ea:x}' in out


@conftest.min_ida_version('9.2')
def test_vds12_with_faked_ui(test_env, monkeypatch):
    """
    Run vds12.py with the cursor on `rax` in `add rax, rsi`; the operand under the
    cursor and the chooser are faked, everything else runs for real
    """
    db = test_env

    def get_current_operand(gco):
        gco.name = 'rax'
        gco.regnum = ida_idp.str2reg('rax')
        gco.size = 8
        gco.flags = ida_hexrays.GCO_REG | ida_hexrays.GCO_USE | ida_hexrays.GCO_DEF
        return True

    shown = []

    def show(chooser, modal=False):
        shown.append([chooser.OnGetLine(i) for i in range(chooser.OnGetSize())])
        return -1  # cancelled

    monkeypatch.setattr(ida_hexrays, 'get_current_operand', get_current_operand)
    monkeypatch.setattr(ida_kernwin.Choose, 'Show', show)
    db.current_ea = 0x2AA

    namespace = _exec_in_own_namespace(EXAMPLES_DIR / _DECOMPILER / 'vds12.py')
    namespace.clear()
    gc.collect()

    assert shown == [
        [
            ['def', '000002a7', 'mov     rax, rdi'],
            ['use/def', '000002aa', 'add     rax, rsi'],
        ]
    ]
