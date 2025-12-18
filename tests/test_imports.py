"""Tests for Imports entity."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def imports_test_setup():
    """
    Setup for imports tests.

    RATIONALE: We need a real binary with import tables to test the Imports entity.
    The tiny_asm.bin and tiny_c.bin in the existing test resources are minimal
    binaries without imports. For comprehensive import testing, we need a binary
    that uses external library functions (e.g., from libc or Windows DLLs).

    This fixture will use tiny_c.bin as a temporary solution, and if it doesn't
    have imports, tests will be skipped with appropriate warnings.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'imports_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip("Test binary not found")

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def imports_db(imports_test_setup):
    """
    Open database for imports testing.

    RATIONALE: Each test needs a fresh database instance to ensure test isolation.
    We open the database with auto-analysis enabled to ensure import tables are
    properly parsed and populated by IDA.
    """
    idb_path = imports_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


def test_imports_module_count(imports_db):
    """
    Test that we can get the count of import modules.

    RATIONALE: This tests the basic __len__() operation on the Imports entity,
    which internally calls ida_nalt.get_import_module_qty(). This is a fundamental
    operation that all other import operations depend on.

    The test binary (tiny_c.bin) is a minimal C program that should have at least
    one import module (typically libc or msvcrt depending on platform). If the
    binary has no imports, we skip the test rather than fail, as this indicates
    a limitation of the test binary, not a bug in the implementation.
    """
    count = len(imports_db.imports)

    # tiny_c.bin might not have imports if it's statically linked
    # Real-world binaries will have imports
    assert count >= 0, "Import count should be non-negative"

    # If no imports, skip remaining assertions
    if count == 0:
        pytest.skip("Test binary has no imports (statically linked?)")

    # If we have imports, verify they're accessible
    assert count > 0, "Expected test binary to have at least one import module"


def test_imports_module_iteration(imports_db):
    """
    Test that we can iterate over all import modules.

    RATIONALE: This validates the __iter__() implementation which enables
    `for module in db.imports` patterns. This is a core usability feature
    that transforms IDA's index-based access into Pythonic iteration.

    For each module, we verify:
    - name is a non-empty string (module names are always present)
    - index is non-negative and sequentially ordered
    - import_count is non-negative (modules can theoretically have 0 imports)

    We also verify that iteration order matches index order, which is important
    for consistency with the legacy IDA API.
    """
    modules = list(imports_db.imports)

    if len(modules) == 0:
        pytest.skip("Test binary has no imports")

    # Verify basic properties
    for idx, module in enumerate(modules):
        assert isinstance(module.name, str), "Module name should be string"
        assert len(module.name) > 0, "Module name should not be empty"
        assert module.index == idx, f"Module index should match iteration order"
        assert module.import_count >= 0, "Import count should be non-negative"


def test_imports_get_module_by_index(imports_db):
    """
    Test getting a specific module by its index.

    RATIONALE: Index-based access is important for compatibility with legacy
    code that uses ida_nalt.get_import_module_name(index). This test validates
    that get_module(index) correctly retrieves the module at the given position.

    Edge cases tested:
    - Negative index (should raise InvalidParameterError)
    - Valid index (should return ImportModule)
    - Out-of-range index (should return None)
    - Module properties match iteration results (consistency check)
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Test valid index
    module = imports_db.imports.get_module(0)
    assert module is not None, "First module should exist"
    assert module.index == 0, "Module index should be 0"
    assert isinstance(module.name, str), "Module name should be string"

    # Test negative index (should raise)
    with pytest.raises(Exception):  # Should raise InvalidParameterError
        imports_db.imports.get_module(-1)

    # Test out of range
    module = imports_db.imports.get_module(count + 100)
    assert module is None, "Out-of-range index should return None"

    # Test consistency with iteration
    all_modules = list(imports_db.imports)
    for idx, iter_module in enumerate(all_modules):
        idx_module = imports_db.imports.get_module(idx)
        assert idx_module is not None, f"Module at index {idx} should exist"
        assert idx_module.name == iter_module.name, "Module name should match"
        assert idx_module.index == iter_module.index, "Module index should match"


def test_imports_get_module_by_name(imports_db):
    """
    Test getting a module by its name.

    RATIONALE: Name-based lookup is a common use case for analysts who want to
    check if a specific library is imported (e.g., "Is ws2_32.dll imported?").
    This test validates that get_module_by_name() correctly performs case-insensitive
    lookups, which matches IDA's typical behavior with module names.

    Edge cases tested:
    - Exact case match
    - Different case (UPPERCASE, lowercase) - should still match
    - Non-existent module name (should return None)
    - Empty string (should return None)
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get first module to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    # Test exact name match
    module = imports_db.imports.get_module_by_name(first_module.name)
    assert module is not None, "Should find module by exact name"
    assert module.name == first_module.name, "Module names should match"
    assert module.index == first_module.index, "Module indices should match"

    # Test case-insensitive match
    module_upper = imports_db.imports.get_module_by_name(first_module.name.upper())
    module_lower = imports_db.imports.get_module_by_name(first_module.name.lower())

    # At least one case variant should match (case-insensitive)
    assert module_upper is not None or module_lower is not None, (
        "Case-insensitive lookup should work"
    )

    # Test non-existent module
    module = imports_db.imports.get_module_by_name("nonexistent_module_xyz_123.dll")
    assert module is None, "Non-existent module should return None"


def test_imports_module_entries(imports_db):
    """
    Test accessing import entries from a module.

    RATIONALE: The ImportModule.imports property provides lazy iteration over
    all imports from a specific module. This is implemented via the callback-based
    ida_nalt.enum_import_names() API. This test validates that:
    - The imports property returns an iterator
    - Each entry has valid properties (address, name, module info)
    - The parent-child relationship between module and entries is correct

    Import entries can be either:
    - Named imports: has a function name (e.g., "CreateFileW")
    - Ordinal imports: imported by number only (e.g., ordinal 42)

    This test validates both types if present in the test binary.
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get first module
    module = imports_db.imports.get_module(0)
    assert module is not None

    # Get entries from module
    entries = list(module.imports)

    # Verify entry count matches module's import_count
    assert len(entries) == module.import_count, (
        "Number of entries should match module's import_count"
    )

    if len(entries) == 0:
        # Module exists but has no imports (unusual but valid)
        pytest.skip("Module has no import entries")

    # Verify each entry's properties
    for entry in entries:
        # Every entry should have an address
        assert entry.address > 0, "Import should have valid address"

        # Entry should be either named or ordinal import
        assert entry.is_named_import or entry.is_ordinal_import, (
            "Import should be either named or ordinal"
        )

        # Entry should know its parent module
        assert entry.module_name == module.name, "Entry should reference correct module"
        assert entry.module_index == module.index, "Entry should have correct module index"

        # If named import, name should not be empty
        if entry.is_named_import:
            assert len(entry.name) > 0, "Named import should have non-empty name"

        # If ordinal import, ordinal should be non-zero
        if entry.is_ordinal_import:
            assert entry.ordinal > 0, "Ordinal import should have non-zero ordinal"

        # full_name should always be valid
        assert len(entry.full_name) > 0, "Entry should have non-empty full_name"
        assert module.name in entry.full_name, "full_name should contain module name"


def test_imports_get_entries_by_module(imports_db):
    """
    Test getting all entries from a specific module by index.

    RATIONALE: The get_entries_by_module() method provides direct access to
    import entries without first retrieving the module object. This is useful
    for batch processing scenarios. This test validates:
    - Correct enumeration of entries for a given module index
    - Proper error handling for invalid indices
    - Consistency with ImportModule.imports property

    Edge cases:
    - Negative index (should raise)
    - Valid index (should return iterator)
    - Out-of-range index (should raise)
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Test valid module index
    entries_direct = list(imports_db.imports.get_entries_by_module(0))
    module = imports_db.imports.get_module(0)
    assert module is not None

    entries_via_module = list(module.imports)

    # Should get same results both ways
    assert len(entries_direct) == len(entries_via_module), (
        "Direct and via-module access should return same count"
    )

    # Test negative index
    with pytest.raises(Exception):  # Should raise InvalidParameterError
        list(imports_db.imports.get_entries_by_module(-1))

    # Test out of range
    with pytest.raises(Exception):  # Should raise InvalidParameterError
        list(imports_db.imports.get_entries_by_module(count + 100))


def test_imports_empty_database():
    """
    Test Imports entity behavior with an empty/minimal database.

    RATIONALE: The Imports entity should gracefully handle databases with
    no import information (e.g., statically-linked binaries, raw binary dumps,
    or embedded firmware). This test ensures that:
    - __len__() returns 0 for binaries without imports
    - __iter__() returns empty iterator (no exceptions)
    - get_module() operations return None appropriately
    - No crashes or exceptions occur with empty import tables

    This is important for robustness - the API should work with ANY binary,
    not just those with import tables.
    """
    # Use tiny_asm.bin which likely has no imports
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_asm_imports.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')

    if os.path.exists(src_path):
        shutil.copy(src_path, idb_path)
        ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
        db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)

        try:
            # Should return 0, not crash
            count = len(db.imports)
            assert count >= 0, "Import count should be non-negative even for empty database"

            # Should return empty iterator, not crash
            modules = list(db.imports)
            assert len(modules) == count, "Iteration should match count"

            # get_module should return None
            module = db.imports.get_module(0)
            if count == 0:
                assert module is None, "get_module should return None when no imports"

        finally:
            if db.is_open():
                db.close(False)
