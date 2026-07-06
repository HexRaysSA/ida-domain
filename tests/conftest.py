import os
import shutil
import tempfile
import warnings

import pytest
from packaging.version import Version

import ida_domain  # isort: skip

from ida_domain.database import IdaCommandOptions

idb_path: str = ''
tiny_c_idb_path: str = ''
tiny_imports_idb_path: str = ''
tiny_pseudocode_idb_path: str = ''

_deprecation_warnings: dict = {}


def _annotation_escape(s: str) -> str:
    return s.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def _property_escape(s: str) -> str:
    return _annotation_escape(s).replace(':', '%3A').replace(',', '%2C')


def pytest_warning_recorded(warning_message: warnings.WarningMessage, when, nodeid, location):
    """Collect deprecation warnings so they can be surfaced as GitHub Actions annotations."""
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        return
    if not issubclass(
        warning_message.category,
        (DeprecationWarning, PendingDeprecationWarning, FutureWarning),
    ):
        return
    try:
        path = os.path.relpath(warning_message.filename).replace(os.sep, '/')
    except ValueError:
        path = warning_message.filename
    key = (path, warning_message.lineno, str(warning_message.message))
    _deprecation_warnings.setdefault(key, (warning_message.category.__name__, nodeid))


def pytest_terminal_summary(terminalreporter):
    """Emit collected deprecation warnings as ::warning workflow commands.

    Done here rather than in pytest_warning_recorded because stdout is captured
    while tests run; the runner only picks up commands written to the real stdout.
    """
    for (path, lineno, message), (category, nodeid) in _deprecation_warnings.items():
        props = [f'title={_property_escape(category)}']
        if not path.startswith('..') and not os.path.isabs(path):
            props = [f'file={_property_escape(path)}', f'line={lineno}'] + props
        text = _annotation_escape(f'{message} (triggered by {nodeid})')
        terminalreporter.write_line(f'::warning {",".join(props)}::{text}')

    output_path = os.environ.get('GITHUB_OUTPUT')
    if _deprecation_warnings and output_path:
        with open(output_path, 'a', encoding='utf-8') as f:
            f.write(f'deprecation_warning_count={len(_deprecation_warnings)}\n')


def min_ida_version(v: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(
        ida_domain.__ida_version__ < Version(v),
        reason=f"requires IDA {v}+",
    )


# Global setup (runs ONCE)
@pytest.fixture(scope='session', autouse=True)
def global_setup():
    """Runs once per session: Creates temp directory and writes test binary."""
    print(f'\nAPI Version: {ida_domain.__version__}')
    print(f'\nKernel Version: {ida_domain.__ida_version__}')

    os.environ['IDA_NO_HISTORY'] = '1'

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


@pytest.fixture(scope='session')
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


@pytest.fixture(scope='session')
def tiny_pseudocode_setup(global_setup):
    """Setup for tiny_pseudocode binary tests - copies tiny_pseudocode.bin to work directory."""
    global tiny_pseudocode_idb_path
    tiny_pseudocode_idb_path = os.path.join(
        tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_pseudocode.bin'
    )
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_pseudocode.bin')
    shutil.copy(src_path, tiny_pseudocode_idb_path)


@pytest.fixture(scope='function')
def tiny_pseudocode_env(tiny_pseudocode_setup):
    """Opens tiny_pseudocode database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(
        path=tiny_pseudocode_idb_path, args=ida_options, save_on_close=False
    )
    yield db
    if db.is_open():
        db.close(False)


@pytest.fixture(scope='session')
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
