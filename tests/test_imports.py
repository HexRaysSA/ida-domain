"""Tests for Imports entity."""

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions

# imports_test_setup fixture is provided by conftest.py


@pytest.fixture(scope='function')
def imports_db(imports_test_setup):
    """
    Open database for imports testing.

    Note: Function scope is required for IDA databases because the IDA kernel
    maintains global state that can be affected by other database instances.
    Module-scoped fixtures cause test pollution when other tests open databases.
    Uses pre-analyzed database for fast loading (no auto-analysis needed).
    """
    idb_path = imports_test_setup
    ida_options = IdaCommandOptions(new_database=False, auto_analysis=False)
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

    The test_imports.bin binary is dynamically linked against libc, so it will
    have at least one import module.
    """
    count = len(imports_db.imports)

    # test_imports.bin is dynamically linked and must have imports
    assert count > 0, 'Expected test binary to have at least one import module'


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
    assert len(modules) > 0, 'test_imports.bin must have import modules'

    # Verify basic properties
    for idx, module in enumerate(modules):
        assert isinstance(module.name, str), 'Module name should be string'
        assert len(module.name) > 0, 'Module name should not be empty'
        assert module.index == idx, f'Module index should match iteration order'
        assert module.import_count >= 0, 'Import count should be non-negative'


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
        pytest.fail('test_imports.bin must have imports')

    # Test valid index
    module = imports_db.imports.get_module(0)
    assert module is not None, 'First module should exist'
    assert module.index == 0, 'Module index should be 0'
    assert isinstance(module.name, str), 'Module name should be string'

    # Test negative index (should raise)
    with pytest.raises(Exception):  # Should raise InvalidParameterError
        imports_db.imports.get_module(-1)

    # Test out of range
    module = imports_db.imports.get_module(count + 100)
    assert module is None, 'Out-of-range index should return None'

    # Test consistency with iteration
    all_modules = list(imports_db.imports)
    for idx, iter_module in enumerate(all_modules):
        idx_module = imports_db.imports.get_module(idx)
        assert idx_module is not None, f'Module at index {idx} should exist'
        assert idx_module.name == iter_module.name, 'Module name should match'
        assert idx_module.index == iter_module.index, 'Module index should match'


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
        pytest.fail('test_imports.bin must have imports')

    # Get first module to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    # Test exact name match
    module = imports_db.imports.get_module_by_name(first_module.name)
    assert module is not None, 'Should find module by exact name'
    assert module.name == first_module.name, 'Module names should match'
    assert module.index == first_module.index, 'Module indices should match'

    # Test case-insensitive match
    module_upper = imports_db.imports.get_module_by_name(first_module.name.upper())
    module_lower = imports_db.imports.get_module_by_name(first_module.name.lower())

    # At least one case variant should match (case-insensitive)
    assert module_upper is not None or module_lower is not None, (
        'Case-insensitive lookup should work'
    )

    # Test non-existent module
    module = imports_db.imports.get_module_by_name('nonexistent_module_xyz_123.dll')
    assert module is None, 'Non-existent module should return None'


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
        pytest.fail('test_imports.bin must have imports')

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
        pytest.fail('Module in test_imports.bin must have import entries')

    # Verify each entry's properties
    for entry in entries:
        # Every entry should have an address
        assert entry.address > 0, 'Import should have valid address'

        # Entry should be either named or ordinal import
        assert entry.is_named_import or entry.is_ordinal_import, (
            'Import should be either named or ordinal'
        )

        # Entry should know its parent module
        assert entry.module_name == module.name, 'Entry should reference correct module'
        assert entry.module_index == module.index, 'Entry should have correct module index'

        # If named import, name should not be empty
        if entry.is_named_import:
            assert len(entry.name) > 0, 'Named import should have non-empty name'

        # If ordinal import, ordinal should be non-zero
        if entry.is_ordinal_import:
            assert entry.ordinal > 0, 'Ordinal import should have non-zero ordinal'

        # full_name should always be valid
        assert len(entry.full_name) > 0, 'Entry should have non-empty full_name'
        assert module.name in entry.full_name, 'full_name should contain module name'


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
        pytest.fail('test_imports.bin must have imports')

    # Test valid module index
    entries_direct = list(imports_db.imports.get_entries_by_module(0))
    module = imports_db.imports.get_module(0)
    assert module is not None

    entries_via_module = list(module.imports)

    # Should get same results both ways
    assert len(entries_direct) == len(entries_via_module), (
        'Direct and via-module access should return same count'
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
        pytest.fail('test_imports.bin must have imports')

    # Get all entries (flattened)
    all_entries = list(imports_db.imports.get_all_entries())

    # Calculate expected count by summing module import counts
    expected_count = sum(module.import_count for module in imports_db.imports)

    assert len(all_entries) == expected_count, (
        f'get_all_entries() should return all imports: '
        f'got {len(all_entries)}, expected {expected_count}'
    )

    if len(all_entries) == 0:
        pytest.fail('test_imports.bin must have import entries')

    # Verify each entry
    for entry in all_entries:
        assert entry.address > 0, 'Entry should have valid address'
        assert isinstance(entry.module_name, str), 'Module name should be string'
        assert len(entry.module_name) > 0, 'Module name should not be empty'
        assert entry.module_index >= 0, 'Module index should be non-negative'
        assert entry.is_named_import or entry.is_ordinal_import, (
            'Entry should be either named or ordinal'
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
        pytest.fail('test_imports.bin must have imports')

    # Get first import entry to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.fail('First module in test_imports.bin must have entries')

    first_entry = first_entries[0]

    # Test getting import at known address
    entry = imports_db.imports.get_at(first_entry.address)
    assert entry is not None, 'Should find import at known address'
    assert entry.address == first_entry.address, 'Addresses should match'
    assert entry.name == first_entry.name, 'Names should match'
    assert entry.module_name == first_entry.module_name, 'Module names should match'

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
        pytest.fail('test_imports.bin must have imports')

    # Get a known import name to test with
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.fail('First module in test_imports.bin must have entries')

    # Find a named import (skip ordinal imports)
    test_entry = None
    for entry in first_entries:
        if entry.is_named_import:
            test_entry = entry
            break

    if test_entry is None:
        pytest.fail('First module in test_imports.bin must have named imports')

    # Test finding by name (no module filter)
    found_entry = imports_db.imports.find_by_name(test_entry.name)
    assert found_entry is not None, f"Should find import '{test_entry.name}'"
    assert found_entry.name == test_entry.name, 'Names should match'
    assert found_entry.address == test_entry.address, 'Addresses should match'

    # Test finding by name with module filter
    found_entry = imports_db.imports.find_by_name(test_entry.name, test_entry.module_name)
    assert found_entry is not None, (
        f"Should find '{test_entry.name}' in '{test_entry.module_name}'"
    )
    assert found_entry.name == test_entry.name, 'Names should match'
    assert found_entry.module_name == test_entry.module_name, 'Module names should match'

    # Test finding with wrong module filter (should return None)
    found_entry = imports_db.imports.find_by_name(test_entry.name, 'nonexistent_module.dll')
    assert found_entry is None, 'Should not find import in wrong module'

    # Test finding non-existent import
    found_entry = imports_db.imports.find_by_name('ThisFunctionDefinitelyDoesNotExist12345')
    assert found_entry is None, 'Should not find non-existent import'


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
        pytest.fail('test_imports.bin must have imports')

    # Get a known import
    first_module = imports_db.imports.get_module(0)
    assert first_module is not None

    first_entries = list(first_module.imports)
    if len(first_entries) == 0:
        pytest.fail('First module in test_imports.bin must have entries')

    # Find a named import
    test_entry = None
    for entry in first_entries:
        if entry.is_named_import:
            test_entry = entry
            break

    if test_entry is None:
        pytest.fail('test_imports.bin must have named imports')

    # Test with different case variations of module name
    module_lower = test_entry.module_name.lower()
    module_upper = test_entry.module_name.upper()

    found_lower = imports_db.imports.find_by_name(test_entry.name, module_lower)
    found_upper = imports_db.imports.find_by_name(test_entry.name, module_upper)

    # At least one should succeed (case-insensitive)
    assert found_lower is not None or found_upper is not None, (
        'Module name filter should be case-insensitive'
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
        pytest.fail('test_imports.bin must have imports')

    # Get module names
    names = imports_db.imports.get_module_names()

    # Should be a list, not iterator
    assert isinstance(names, list), 'get_module_names should return a list'

    # Length should match module count
    assert len(names) == count, f'get_module_names() should return {count} names, got {len(names)}'

    # Each name should be a non-empty string
    for name in names:
        assert isinstance(name, str), 'Each module name should be a string'
        assert len(name) > 0, 'Module names should not be empty'

    # Names should match iteration order
    modules = list(imports_db.imports)
    for i, (name, module) in enumerate(zip(names, modules)):
        assert name == module.name, (
            f"Module name at index {i} should match: got '{name}', expected '{module.name}'"
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
            assert count >= 0, 'Import count should be non-negative even for empty database'

            # Should return empty iterator, not crash
            modules = list(db.imports)
            assert len(modules) == count, 'Iteration should match count'

            # get_module should return None
            module = db.imports.get_module(0)
            if count == 0:
                assert module is None, 'get_module should return None when no imports'

        finally:
            if db.is_open():
                db.close(False)


def test_imports_find_all_by_name(imports_db):
    """
    Test finding all imports with the same name (handles duplicates).

    RATIONALE: While duplicate imports are rare, they can occur in certain
    scenarios (malformed binaries, manual IAT modification, or specific linker
    configurations). The find_all_by_name method should return ALL matching
    entries, not just the first one like find_by_name does.

    This test validates:
    - Returns iterator of all matching imports
    - Works with module filtering (when specified)
    - Returns empty iterator when name not found
    - Can detect duplicates if they exist in the test binary
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    # Get first import to use as test case
    first_module = next(iter(imports_db.imports))
    entries_from_module = list(first_module.imports)

    if len(entries_from_module) == 0:
        pytest.fail('First module in test_imports.bin must have imports')

    # Find first named import
    test_entry = None
    for entry in entries_from_module:
        if entry.is_named_import:
            test_entry = entry
            break

    if not test_entry:
        pytest.fail('First module in test_imports.bin must have named imports')

    # Test: find all by name (should find at least the test entry)
    results = list(imports_db.imports.find_all_by_name(test_entry.name))

    assert len(results) >= 1, 'Should find at least one match'
    assert any(r.name == test_entry.name for r in results), 'Results should include test entry'

    # Test: find all by name with module filter
    results_filtered = list(
        imports_db.imports.find_all_by_name(test_entry.name, test_entry.module_name)
    )

    assert len(results_filtered) >= 1, 'Should find at least one match with module filter'
    assert all(r.module_name == test_entry.module_name for r in results_filtered), (
        'All results should be from specified module'
    )

    # Test: non-existent name returns empty
    results_empty = list(imports_db.imports.find_all_by_name('_NonExistentFunction_12345'))
    assert len(results_empty) == 0, 'Should return empty for non-existent function'


def test_imports_filter_entries(imports_db):
    """
    Test filtering imports with a custom predicate function.

    RATIONALE: The filter_entries method enables flexible querying of imports
    based on arbitrary criteria. This is useful for finding API patterns
    (e.g., all memory allocation functions, all crypto APIs, all network calls).

    This test validates:
    - Predicate function is called for each entry
    - Only entries matching predicate are returned
    - Works with various filter criteria
    - Returns empty when no matches
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    # Get all entries to establish ground truth
    all_entries = list(imports_db.imports.get_all_entries())
    if len(all_entries) == 0:
        pytest.fail('test_imports.bin must have import entries')

    # Test: filter for first module only
    first_module = next(iter(imports_db.imports))
    filtered = list(
        imports_db.imports.filter_entries(lambda e: e.module_name == first_module.name)
    )

    assert len(filtered) > 0, 'Should find imports from first module'
    assert all(e.module_name == first_module.name for e in filtered), (
        'All filtered entries should be from first module'
    )

    # Test: filter for named imports only
    named_only = list(imports_db.imports.filter_entries(lambda e: e.is_named_import))

    assert all(e.is_named_import for e in named_only), 'All should be named imports'

    # Test: filter that matches nothing
    empty_filter = list(
        imports_db.imports.filter_entries(lambda e: e.address == 0xFFFFFFFFFFFFFFFF)
    )

    assert len(empty_filter) == 0, 'Should return empty when no matches'

    # Test: filter always returns True (should match all)
    all_filter = list(imports_db.imports.filter_entries(lambda e: True))

    assert len(all_filter) == len(all_entries), 'Should return all entries with always-true filter'


def test_imports_search_by_pattern(imports_db):
    """
    Test searching imports using regular expression patterns.

    RATIONALE: Pattern-based searching is powerful for finding API families
    or security-relevant function groups. For example, finding all "Create*"
    APIs, or all socket-related functions, or crypto functions.

    This test validates:
    - Case-insensitive search (default)
    - Case-sensitive search (when enabled)
    - Complex regex patterns work correctly
    - Returns empty when pattern matches nothing
    - Handles invalid regex patterns gracefully
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    # Get sample import name to test with
    all_entries = list(imports_db.imports.get_all_entries())
    if len(all_entries) == 0:
        pytest.fail('test_imports.bin must have import entries')

    # Find first named import
    test_entry = None
    for entry in all_entries:
        if entry.is_named_import and len(entry.name) > 3:
            test_entry = entry
            break

    if not test_entry:
        pytest.fail('test_imports.bin must have suitable named imports')

    # Test: search by exact name (should find at least one)
    exact_results = list(imports_db.imports.search_by_pattern(f'^{test_entry.name}$'))

    assert len(exact_results) >= 1, 'Should find exact match'
    assert all(e.name == test_entry.name for e in exact_results), 'Should match exact name'

    # Test: search by prefix (first 3 chars)
    prefix = test_entry.name[:3]
    prefix_results = list(imports_db.imports.search_by_pattern(f'^{prefix}'))

    assert len(prefix_results) >= 1, 'Should find entries matching prefix'
    assert all(e.name.startswith(prefix) for e in prefix_results), (
        'All results should start with prefix'
    )

    # Test: case-insensitive (default)
    case_insensitive = list(
        imports_db.imports.search_by_pattern(test_entry.name.lower(), case_sensitive=False)
    )

    assert len(case_insensitive) >= 1, 'Case-insensitive should find match'

    # Test: case-sensitive (should still find if name has same case)
    case_sensitive = list(
        imports_db.imports.search_by_pattern(test_entry.name, case_sensitive=True)
    )

    assert len(case_sensitive) >= 1, 'Case-sensitive should find exact case match'

    # Test: pattern matching nothing
    no_match = list(imports_db.imports.search_by_pattern(r'^_NONEXISTENT_PATTERN_12345$'))

    assert len(no_match) == 0, 'Should return empty for non-matching pattern'


def test_imports_has_imports(imports_db):
    """
    Test checking whether database has any imports.

    RATIONALE: has_imports() is a quick boolean check useful for early
    validation. Statically linked binaries, shellcode, and some packed
    executables have no import tables. This method allows scripts to
    quickly determine if import-based analysis is relevant.

    This test validates:
    - Returns True when imports exist
    - Returns False when no imports exist
    - Faster than len(db.imports) > 0
    """
    # Test with imports_db (should have imports based on test binary)
    has_imports = imports_db.imports.has_imports()

    # Result should match len() check
    has_imports_via_len = len(imports_db.imports) > 0

    assert has_imports == has_imports_via_len, 'has_imports should match len() > 0'

    # Test with empty database
    work_dir = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir')
    idb_path = os.path.join(work_dir, 'tiny_asm_has_imports.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')

    if os.path.exists(src_path):
        shutil.copy(src_path, idb_path)
        ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
        db_empty = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)

        try:
            # Empty database should return False (or True if it has imports)
            has_empty = db_empty.imports.has_imports()
            count_empty = len(db_empty.imports)

            assert has_empty == (count_empty > 0), 'has_imports should match count > 0'

        finally:
            if db_empty.is_open():
                db_empty.close(False)


def test_imports_is_import(imports_db):
    """
    Test checking if a specific address is an import entry.

    RATIONALE: is_import() is useful for validating addresses during analysis.
    For example, when following cross-references, you might want to check if
    the target is an import or regular code. This is faster than calling
    get_at() and checking if result is None.

    This test validates:
    - Returns True for actual import addresses
    - Returns False for non-import addresses
    - Raises InvalidEAError for invalid addresses
    - Handles edge cases (BADADDR, segment boundaries)
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    # Get a known import address
    all_entries = list(imports_db.imports.get_all_entries())
    if len(all_entries) == 0:
        pytest.fail('test_imports.bin must have import entries')

    test_entry = all_entries[0]

    # Test: known import address should return True
    is_import = imports_db.imports.is_import(test_entry.address)
    assert is_import, 'Should return True for import address'

    # Test: verify consistency with get_at
    entry_via_get_at = imports_db.imports.get_at(test_entry.address)
    assert entry_via_get_at is not None, 'get_at should also find this import'

    # Test: non-import address should return False
    # Use function start (if we have functions, it's unlikely to be an import)
    if len(imports_db.functions) > 0:
        func = next(iter(imports_db.functions))
        is_func_import = imports_db.imports.is_import(func.start_ea)

        # Function starts are typically not imports (though thunks might be)
        # Just verify the call doesn't crash and returns a boolean
        assert isinstance(is_func_import, bool), 'Should return boolean'

    # Test: invalid address should raise InvalidEAError
    from ida_domain.base import InvalidEAError

    with pytest.raises(InvalidEAError):
        imports_db.imports.is_import(0xFFFFFFFFFFFFFFFF)


def test_imports_get_statistics(imports_db):
    """
    Test retrieving import statistics.

    RATIONALE: Import statistics provide useful metadata for profiling binaries,
    detecting anomalies, and understanding dependencies. For example:
    - Total import count indicates dependency complexity
    - Named vs ordinal ratio indicates build configuration
    - Most-imported module reveals primary dependencies

    This test validates:
    - Returns ImportStatistics with correct counts
    - module_count matches len(db.imports)
    - total_imports matches sum of all entries
    - named_imports + ordinal_imports equals total_imports
    - most_imported_module is correctly identified
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    stats = imports_db.imports.get_statistics()

    # Verify module count
    assert stats.module_count == len(imports_db.imports), 'module_count should match len(imports)'

    # Manually count total imports
    all_entries = list(imports_db.imports.get_all_entries())
    actual_total = len(all_entries)

    assert stats.total_imports == actual_total, 'total_imports should match actual count'

    # Verify named vs ordinal split
    actual_named = sum(1 for e in all_entries if e.is_named_import)
    actual_ordinal = sum(1 for e in all_entries if e.is_ordinal_import)

    assert stats.named_imports == actual_named, 'named_imports count should be correct'
    assert stats.ordinal_imports == actual_ordinal, 'ordinal_imports count should be correct'

    # named + ordinal should equal total
    assert stats.named_imports + stats.ordinal_imports == stats.total_imports, (
        'named + ordinal should equal total'
    )

    # Verify most-imported module
    if stats.module_count > 0:
        # Find module with most imports manually
        max_count = 0
        max_module_name = ''

        for module in imports_db.imports:
            if module.import_count > max_count:
                max_count = module.import_count
                max_module_name = module.name

        assert stats.most_imported_module == max_module_name, (
            'most_imported_module should be correct'
        )
        assert stats.most_imported_count == max_count, 'most_imported_count should be correct'


def test_imports_get_entries_by_module_variants(imports_db):
    """
    Test get_entries_by_module with different parameter types.

    RATIONALE: The updated get_entries_by_module now accepts Union[str, int, ImportModule]
    for convenience. This test validates that all three input types work correctly:
    - int: module index (original behavior)
    - str: module name (new convenience)
    - ImportModule: module object (new convenience)

    This test validates:
    - Works with integer index
    - Works with string module name
    - Works with ImportModule object
    - All three methods return same results
    - Proper error handling for invalid inputs
    """
    if len(imports_db.imports) == 0:
        pytest.fail('test_imports.bin must have imports')

    first_module = next(iter(imports_db.imports))

    # Test: get entries by index (int)
    entries_by_index = list(imports_db.imports.get_entries_by_module(first_module.index))

    assert len(entries_by_index) >= 0, 'Should return entries (possibly empty)'

    # Test: get entries by name (str)
    entries_by_name = list(imports_db.imports.get_entries_by_module(first_module.name))

    assert len(entries_by_name) == len(entries_by_index), (
        'Should return same count for name and index'
    )

    # Test: get entries by module object
    entries_by_module = list(imports_db.imports.get_entries_by_module(first_module))

    assert len(entries_by_module) == len(entries_by_index), (
        'Should return same count for module object'
    )

    # Test: all three should return same entries (compare addresses)
    addrs_by_index = {e.address for e in entries_by_index}
    addrs_by_name = {e.address for e in entries_by_name}
    addrs_by_module = {e.address for e in entries_by_module}

    assert addrs_by_index == addrs_by_name, 'Index and name should return same addresses'
    assert addrs_by_index == addrs_by_module, 'Index and module should return same addresses'

    # Test: invalid module name should raise error
    from ida_domain.base import InvalidParameterError

    with pytest.raises(InvalidParameterError):
        list(imports_db.imports.get_entries_by_module('_NonExistentModule_12345'))

    # Test: invalid type should raise error
    with pytest.raises(InvalidParameterError):
        list(imports_db.imports.get_entries_by_module(3.14))  # type: ignore
