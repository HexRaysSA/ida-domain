import os
import shutil
import tempfile

import pytest
from packaging.version import Version

import ida_domain  # isort: skip

from ida_domain.database import IdaCommandOptions

idb_path: str = ''
tiny_c_idb_path: str = ''
tiny_imports_idb_path: str = ''


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
