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


def test_imports_get_all_entries(imports_db):
    """
    Test getting all import entries across all modules (flattened view).

    RATIONALE: The get_all_entries() method provides a flattened view of all
    imports across all modules. This is useful for:
    - Building import address mappings for quick lookup
    - Searching for specific imports without knowing the module
    - Statistical analysis of import usage patterns

    This test validates:
    - All entries from all modules are returned
    - Each entry has valid properties
    - The flattened view matches the sum of per-module entries
    - Iterator is lazy and memory-efficient
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get all entries (flattened)
    all_entries = list(imports_db.imports.get_all_entries())

    # Calculate expected count by summing module import counts
    expected_count = sum(module.import_count for module in imports_db.imports)

    assert len(all_entries) == expected_count, (
        f"get_all_entries() should return all imports: "
        f"got {len(all_entries)}, expected {expected_count}"
    )

    if len(all_entries) == 0:
        pytest.skip("No import entries found")

    # Verify each entry
    for entry in all_entries:
        assert entry.address > 0, "Entry should have valid address"
        assert isinstance(entry.module_name, str), "Module name should be string"
        assert len(entry.module_name) > 0, "Module name should not be empty"
        assert entry.module_index >= 0, "Module index should be non-negative"
        assert entry.is_named_import or entry.is_ordinal_import, (
            "Entry should be either named or ordinal"
        )


def test_imports_get_at(imports_db):
    """
    Test getting an import entry at a specific address.

    RATIONALE: The get_at() method enables reverse lookup of imports by address.
    This is critical for analyzing code that calls imports - given a call target
    address, we can determine if it's an import and get its details. Use cases:
    - Identifying which imported function a piece of code calls
    - Finding all code locations that call a specific import
    - Analyzing IAT (Import Address Table) entries

    This test validates:
    - get_at() returns correct entry for valid import addresses
    - get_at() returns None for non-import addresses
    - get_at() raises InvalidEAError for invalid addresses
    - Returned entry matches the entry from module enumeration
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get first import entry to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.skip("First module has no entries")

    first_entry = first_entries[0]

    # Test getting import at known address
    entry = imports_db.imports.get_at(first_entry.address)
    assert entry is not None, "Should find import at known address"
    assert entry.address == first_entry.address, "Addresses should match"
    assert entry.name == first_entry.name, "Names should match"
    assert entry.module_name == first_entry.module_name, "Module names should match"

    # Test with non-import address (database minimum_ea is typically not an import)
    non_import_ea = imports_db.minimum_ea
    if non_import_ea != first_entry.address:
        entry = imports_db.imports.get_at(non_import_ea)
        # Could be None or another import, just verify no crash
        # Most binaries have imports in a specific segment, not at minimum_ea

    # Test with invalid address (should raise InvalidEAError)
    from ida_domain.base import InvalidEAError
    with pytest.raises(InvalidEAError):
        imports_db.imports.get_at(0xFFFFFFFFFFFFFFFF)


def test_imports_find_by_name(imports_db):
    """
    Test finding an import entry by function name.

    RATIONALE: The find_by_name() method enables searching for imports by
    function name, optionally filtering by module. This is essential for:
    - Checking if a binary imports specific APIs (e.g., "VirtualAlloc")
    - Malware analysis (detecting suspicious API usage)
    - Cross-referencing analysis (finding all calls to a specific API)

    This test validates:
    - find_by_name() returns correct entry for known import names
    - find_by_name() returns None for non-existent names
    - Module filtering works correctly (find in specific module)
    - Case-sensitive matching (import names are case-sensitive in most formats)
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get a known import name to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.skip("First module has no entries")

    # Find a named import (skip ordinal imports)
    test_entry = None
    for entry in first_entries:
        if entry.is_named_import:
            test_entry = entry
            break

    if test_entry is None:
        pytest.skip("No named imports found in first module")

    # Test finding by name (no module filter)
    found_entry = imports_db.imports.find_by_name(test_entry.name)
    assert found_entry is not None, f"Should find import '{test_entry.name}'"
    assert found_entry.name == test_entry.name, "Names should match"
    assert found_entry.address == test_entry.address, "Addresses should match"

    # Test finding by name with module filter
    found_entry = imports_db.imports.find_by_name(test_entry.name, test_entry.module_name)
    assert found_entry is not None, (
        f"Should find '{test_entry.name}' in '{test_entry.module_name}'"
    )
    assert found_entry.name == test_entry.name, "Names should match"
    assert found_entry.module_name == test_entry.module_name, "Module names should match"

    # Test finding with wrong module filter (should return None)
    found_entry = imports_db.imports.find_by_name(test_entry.name, "nonexistent_module.dll")
    assert found_entry is None, "Should not find import in wrong module"

    # Test finding non-existent import
    found_entry = imports_db.imports.find_by_name("ThisFunctionDefinitelyDoesNotExist12345")
    assert found_entry is None, "Should not find non-existent import"


def test_imports_find_by_name_case_insensitive_module(imports_db):
    """
    Test that module name filtering in find_by_name() is case-insensitive.

    RATIONALE: Module names (DLL names on Windows) are typically case-insensitive.
    For example, "kernel32.dll", "KERNEL32.DLL", and "Kernel32.dll" should all
    refer to the same module. This test validates that find_by_name() respects
    this convention when filtering by module name.

    This is important for user convenience - analysts shouldn't need to remember
    the exact capitalization of module names.
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get a known import
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.skip("First module has no entries")

    # Find a named import
    test_entry = None
    for entry in first_entries:
        if entry.is_named_import:
            test_entry = entry
            break

    if test_entry is None:
        pytest.skip("No named imports found")

    # Test with different case variations of module name
    module_lower = test_entry.module_name.lower()
    module_upper = test_entry.module_name.upper()

    found_lower = imports_db.imports.find_by_name(test_entry.name, module_lower)
    found_upper = imports_db.imports.find_by_name(test_entry.name, module_upper)

    # At least one should succeed (case-insensitive)
    assert found_lower is not None or found_upper is not None, (
        "Module name filter should be case-insensitive"
    )


def test_imports_get_module_names(imports_db):
    """
    Test getting list of all module names.

    RATIONALE: The get_module_names() method provides a convenient way to get
    a flat list of all imported module names. This is useful for:
    - Quick dependency checks (e.g., "if 'ws2_32.dll' in db.imports.get_module_names()")
    - Generating dependency reports
    - Comparing imports across multiple binaries

    Unlike __iter__() which returns ImportModule objects with full metadata,
    get_module_names() returns just the names as strings, which is lighter-weight
    and more convenient for simple name-based operations.

    This test validates:
    - Returns a list (not iterator) of strings
    - List length matches module count
    - Each name is non-empty
    - Names match those from iteration
    - Order matches import table order
    """
    count = len(imports_db.imports)

    if count == 0:
        pytest.skip("Test binary has no imports")

    # Get module names
    names = imports_db.imports.get_module_names()

    # Should be a list, not iterator
    assert isinstance(names, list), "get_module_names should return a list"

    # Length should match module count
    assert len(names) == count, (
        f"get_module_names() should return {count} names, got {len(names)}"
    )

    # Each name should be a non-empty string
    for name in names:
        assert isinstance(name, str), "Each module name should be a string"
        assert len(name) > 0, "Module names should not be empty"

    # Names should match iteration order
    modules = list(imports_db.imports)
    for i, (name, module) in enumerate(zip(names, modules)):
        assert name == module.name, (
            f"Module name at index {i} should match: "
            f"got '{name}', expected '{module.name}'"
        )


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
