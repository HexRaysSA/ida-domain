"""
Pytest configuration and shared fixtures for ida-domain tests.

This module provides centralized test database management:
- Session-scoped fixture to create all .i64 databases once at test startup
- Module-scoped fixtures for each test binary that tests can depend on

The .i64 database files are created dynamically from the .bin source files
using whatever IDA version is available, ensuring version compatibility.
"""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions

# Directory containing test resources (binaries)
RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources')

# Work directory for test databases
WORK_DIR = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir')

# Test binaries that need pre-analysis
TEST_BINARIES = [
    'test_imports.bin',
    'test_switches.bin',
    'test_try_blocks.bin',
    'test_stack_frames.bin',
    'test_types.bin',
    'tiny_asm.bin',
    'tiny_c.bin',
]


def _ensure_database_exists(bin_name: str) -> str:
    """
    Ensure a database exists for the given binary, creating it if necessary.

    This is a fallback mechanism that creates databases on-demand if the
    session fixture didn't run or failed silently.

    Args:
        bin_name: Name of the binary (e.g., 'test_types.bin')

    Returns:
        Path to the .i64 database file

    Raises:
        pytest.fail if the database cannot be created
    """
    src_path = os.path.join(RESOURCES_DIR, bin_name)
    work_bin_path = os.path.join(WORK_DIR, bin_name)
    i64_path = work_bin_path + '.i64'

    # Check if database already exists
    if os.path.exists(i64_path) and os.path.getsize(i64_path) > 1024:
        return i64_path

    # Database doesn't exist - need to create it
    print(f'\n[CREATING DATABASE] {bin_name}.i64 was not pre-created, creating now...')

    if not os.path.exists(src_path):
        pytest.fail(
            f'FATAL: Source binary not found: {src_path}\n'
            f'Cannot create database without source binary.'
        )

    # Create work directory if needed
    os.makedirs(WORK_DIR, exist_ok=True)

    # Copy binary
    if not os.path.exists(work_bin_path):
        shutil.copy2(src_path, work_bin_path)

    # Remove any corrupted database
    if os.path.exists(i64_path):
        os.remove(i64_path)

    # Create database
    try:
        os.environ['IDA_NO_HISTORY'] = '1'

        ida_options = IdaCommandOptions(
            new_database=True,
            auto_analysis=True,
        )

        db = ida_domain.Database.open(
            path=work_bin_path,
            args=ida_options,
            save_on_close=True,
        )

        db.close(save=True)

        # Verify creation
        if not os.path.exists(i64_path):
            pytest.fail(
                f'FATAL: Failed to create {bin_name}.i64\n'
                f'IDA did not create the database file at {i64_path}'
            )

        size = os.path.getsize(i64_path)
        if size <= 1024:
            os.remove(i64_path)
            pytest.fail(
                f'FATAL: Created {bin_name}.i64 is too small ({size} bytes)\n'
                f'Database creation may have failed.'
            )

        print(f'[SUCCESS] Created {bin_name}.i64 ({size / 1024:.1f} KB)')
        return i64_path

    except Exception as e:
        if os.path.exists(i64_path):
            try:
                os.remove(i64_path)
            except Exception:
                pass

        pytest.fail(
            f'FATAL: Failed to create {bin_name}.i64\n'
            f'Error: {e}\n'
            f'Source: {src_path}\n'
            f'Target: {i64_path}'
        )


@pytest.fixture(scope='session', autouse=True)
def setup_test_databases():
    """
    Session-scoped fixture to pre-create all .i64 databases.

    This runs once at the start of the test session to create all databases
    in batch, which is much faster than creating them on-demand.

    Note: Individual fixtures use _ensure_database_exists() as a fallback
    in case this session fixture doesn't run for some reason.
    """
    print('\n' + '=' * 70)
    print('PRE-CREATING TEST DATABASES')
    print('=' * 70)
    print(f'IDA Version: {ida_domain.__ida_version__}')
    print(f'Work directory: {WORK_DIR}')

    os.makedirs(WORK_DIR, exist_ok=True)
    os.environ['IDA_NO_HISTORY'] = '1'

    created = 0
    skipped = 0
    failed = []

    for bin_name in TEST_BINARIES:
        src_path = os.path.join(RESOURCES_DIR, bin_name)
        work_bin_path = os.path.join(WORK_DIR, bin_name)
        i64_path = work_bin_path + '.i64'

        # Skip if source doesn't exist
        if not os.path.exists(src_path):
            print(f'  SKIP: {bin_name} (no source)')
            skipped += 1
            continue

        # Skip if valid database already exists
        if os.path.exists(i64_path) and os.path.getsize(i64_path) > 1024:
            size_kb = os.path.getsize(i64_path) / 1024
            print(f'  EXISTING: {bin_name}.i64 ({size_kb:.1f} KB)')
            created += 1
            continue

        # Create database
        print(f'  CREATING: {bin_name}.i64 ... ', end='', flush=True)

        try:
            # Copy binary
            if not os.path.exists(work_bin_path):
                shutil.copy2(src_path, work_bin_path)

            # Remove stale database
            if os.path.exists(i64_path):
                os.remove(i64_path)

            # Create
            ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
            db = ida_domain.Database.open(work_bin_path, args=ida_options, save_on_close=True)
            db.close(save=True)

            # Verify
            if os.path.exists(i64_path) and os.path.getsize(i64_path) > 1024:
                size_kb = os.path.getsize(i64_path) / 1024
                print(f'OK ({size_kb:.1f} KB)')
                created += 1
            else:
                print('FAILED (file not created or too small)')
                failed.append(bin_name)
                if os.path.exists(i64_path):
                    os.remove(i64_path)

        except Exception as e:
            print(f'FAILED ({e})')
            failed.append(bin_name)
            if os.path.exists(i64_path):
                try:
                    os.remove(i64_path)
                except Exception:
                    pass

    print('=' * 70)
    print(f'Result: {created} ready, {skipped} skipped, {len(failed)} failed')
    if failed:
        print(f'Failed: {", ".join(failed)}')
        print('Note: Tests will attempt on-demand creation for failed databases')
    print('=' * 70 + '\n')

    yield


@pytest.fixture(scope='module')
def imports_test_setup(setup_test_databases):
    """Setup for imports tests - provides path to test_imports.bin.i64."""
    return _ensure_database_exists('test_imports.bin')


@pytest.fixture(scope='module')
def switches_test_setup(setup_test_databases):
    """Setup for switches tests - provides path to test_switches.bin.i64."""
    return _ensure_database_exists('test_switches.bin')


@pytest.fixture(scope='module')
def try_blocks_test_setup(setup_test_databases):
    """Setup for try blocks tests - provides path to test_try_blocks.bin.i64."""
    return _ensure_database_exists('test_try_blocks.bin')


@pytest.fixture(scope='module')
def stack_frames_test_setup(setup_test_databases):
    """Setup for stack frames tests - provides path to test_stack_frames.bin.i64."""
    return _ensure_database_exists('test_stack_frames.bin')


@pytest.fixture(scope='module')
def types_test_setup(setup_test_databases):
    """Setup for types tests - provides path to test_types.bin.i64."""
    return _ensure_database_exists('test_types.bin')


@pytest.fixture(scope='module')
def tiny_c_setup(setup_test_databases):
    """Setup for tests using tiny_c.bin - provides path to tiny_c.bin.i64."""
    return _ensure_database_exists('tiny_c.bin')


@pytest.fixture(scope='module')
def tiny_asm_setup(setup_test_databases):
    """Setup for tests using tiny_asm.bin - provides path to tiny_asm.bin.i64."""
    return _ensure_database_exists('tiny_asm.bin')
