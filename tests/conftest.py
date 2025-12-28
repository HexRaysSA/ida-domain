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


def _create_idb(bin_path: str, i64_path: str) -> bool:
    """
    Open a binary in IDA, run auto-analysis, and save as .i64.

    Args:
        bin_path: Path to the source binary file
        i64_path: Path where the .i64 database should be saved

    Returns:
        True if successful, False otherwise
    """
    print(f'  Creating: {os.path.basename(i64_path)}')

    # Remove existing .i64 if present
    if os.path.exists(i64_path):
        os.remove(i64_path)

    try:
        # Open with new database and auto-analysis
        ida_options = IdaCommandOptions(
            new_database=True,
            auto_analysis=True,
        )

        db = ida_domain.Database.open(
            path=bin_path,
            args=ida_options,
            save_on_close=True,
        )

        # Close and save
        db.close(save=True)

        # Verify the file was created
        if os.path.exists(i64_path):
            size = os.path.getsize(i64_path)
            print(f'    Size: {size / 1024:.1f} KB')
            return True
        else:
            print(f'    ERROR: Output file not created!')
            return False

    except Exception as e:
        print(f'    ERROR: {e}')
        return False


@pytest.fixture(scope='session', autouse=True)
def setup_test_databases():
    """
    Session-scoped fixture to create all .i64 databases once at test startup.

    This fixture runs automatically before any tests and creates IDA databases
    from the test binaries. This ensures the databases are compatible with
    the current IDA version being used for testing.
    """
    print('\n' + '=' * 60)
    print('Setting up test databases for ida-domain tests')
    print('=' * 60)
    print(f'IDA Version: {ida_domain.__ida_version__}')
    print(f'API Version: {ida_domain.__version__}')

    # Create work directory
    os.makedirs(WORK_DIR, exist_ok=True)

    # Disable IDA history
    os.environ['IDA_NO_HISTORY'] = '1'

    success_count = 0
    fail_count = 0
    skip_count = 0

    for bin_name in TEST_BINARIES:
        bin_path = os.path.join(RESOURCES_DIR, bin_name)
        i64_path = os.path.join(WORK_DIR, bin_name + '.i64')

        if not os.path.exists(bin_path):
            print(f'  SKIP: {bin_name} (source binary not found)')
            skip_count += 1
            continue

        if _create_idb(bin_path, i64_path):
            success_count += 1
        else:
            fail_count += 1

    print('=' * 60)
    print(f'Database setup: {success_count} created, {skip_count} skipped, {fail_count} failed')
    print('=' * 60 + '\n')

    if fail_count > 0:
        pytest.fail(f'Failed to create {fail_count} test database(s)')

    yield

    # Cleanup work directory after all tests complete
    # Note: We don't delete here to allow inspection of test artifacts if needed
    # The temp directory will be cleaned up by the OS eventually


@pytest.fixture(scope='module')
def imports_test_setup(setup_test_databases):
    """
    Setup for imports tests - provides path to test_imports.bin.i64.

    RATIONALE: The test_imports.bin binary is specifically designed for testing
    the Imports entity - it's a dynamically linked x86_64 Linux ELF that imports
    many libc functions including: printf, fprintf, malloc, free, calloc, realloc,
    memset, memcpy, memcmp, strlen, strcpy, strcat, strcmp, strncmp, strstr,
    strchr, open, read, close, stat, getenv, getpid, getuid, atoi, puts, snprintf.
    """
    idb_path = os.path.join(WORK_DIR, 'test_imports.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('test_imports.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def switches_test_setup(setup_test_databases):
    """
    Setup for switches tests - provides path to test_switches.bin.i64.

    RATIONALE: The test_switches.bin binary contains 9 different switch statement
    patterns: dense_switch (cases 0-7), dense_switch_offset (cases 10-15),
    sparse_switch (non-consecutive cases), fallthrough_switch, no_default_switch,
    nested_switch, char_switch, negative_switch (-3 to 2), and large_switch (20 cases).
    """
    idb_path = os.path.join(WORK_DIR, 'test_switches.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('test_switches.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def try_blocks_test_setup(setup_test_databases):
    """
    Setup for try blocks tests - provides path to test_try_blocks.bin.i64.

    RATIONALE: The test_try_blocks.bin is a C++ binary with various exception
    handling patterns: simple_try_catch, multiple_catch, catch_all, nested_try,
    rethrow_example, exception_with_cleanup, custom_exception_hierarchy,
    catch_from_callee, and call_noexcept.
    """
    idb_path = os.path.join(WORK_DIR, 'test_try_blocks.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('test_try_blocks.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def stack_frames_test_setup(setup_test_databases):
    """
    Setup for stack frames tests - provides path to test_stack_frames.bin.i64.

    RATIONALE: The test_stack_frames.bin contains functions with various stack
    frame layouts: simple_locals, many_arguments (8 args), large_array (256 ints),
    mixed_types, struct_local, nested_struct_local, pointer_args, array_of_structs,
    factorial (recursive), deep_nesting, leaf_function, and many_registers.
    """
    idb_path = os.path.join(WORK_DIR, 'test_stack_frames.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('test_stack_frames.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def types_test_setup(setup_test_databases):
    """
    Setup for types tests - provides path to test_types.bin.i64.

    RATIONALE: The test_types.bin has rich type information including:
    - Enums: ColorChannel, ProcessState, ErrorCode, ValueType
    - Structs: Point2D, Record, PaddedStruct, PackedStruct, PhysicsBody, Node, etc.
    - Unions: FloatBits, DoubleBits, TaggedValue
    - Bitfields: BitfieldStruct, BitfieldStruct64
    - Function pointers: VoidFunc, IntFunc, BinaryFunc, AllocFunc, Allocator
    """
    idb_path = os.path.join(WORK_DIR, 'test_types.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('test_types.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def tiny_c_setup(setup_test_databases):
    """
    Setup for tests using tiny_c.bin - provides path to tiny_c.bin.i64.

    RATIONALE: tiny_c.bin is a minimal C binary used for basic functionality tests.
    """
    idb_path = os.path.join(WORK_DIR, 'tiny_c.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('tiny_c.bin.i64 not available')
    return idb_path


@pytest.fixture(scope='module')
def tiny_asm_setup(setup_test_databases):
    """
    Setup for tests using tiny_asm.bin - provides path to tiny_asm.bin.i64.

    RATIONALE: tiny_asm.bin is a minimal assembly binary used for low-level tests.
    """
    idb_path = os.path.join(WORK_DIR, 'tiny_asm.bin.i64')
    if not os.path.exists(idb_path):
        pytest.skip('tiny_asm.bin.i64 not available')
    return idb_path
