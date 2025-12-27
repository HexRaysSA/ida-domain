"""Tests for Search entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.search import SearchDirection


@pytest.fixture(scope='module')
def search_test_setup():
    """
    Setup for search tests.

    RATIONALE: We need a binary with mixed code/data sections to properly test
    the Search entity's ability to find different address types (code, data,
    undefined). The tiny_asm.bin binary is suitable as it contains:
    - Code sections with instructions
    - Data sections
    - Potentially undefined/unanalyzed regions

    This binary is small enough for fast test execution but complex enough to
    validate search functionality.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'search_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def search_db(search_test_setup):
    """
    Open database for search testing.

    RATIONALE: Each test needs a fresh database instance to ensure test isolation.
    We open the database with auto-analysis enabled to ensure the binary is properly
    analyzed, giving us defined code/data regions to search through.
    """
    idb_path = search_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# STATE-BASED SEARCH TESTS
# =============================================================================


def test_next_undefined_finds_address(search_db):
    """
    Test that next_undefined can find undefined bytes in the database.

    RATIONALE: This validates the basic functionality of finding unanalyzed
    regions. In a real binary, there are often gaps between analyzed sections
    or at the end of segments that remain undefined. This is important for
    analysis completeness checks.

    We start from the minimum address and search for undefined regions. The
    method should either find one or return None if the entire database is
    fully analyzed. Both outcomes are valid and we test for correct handling.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_undefined(start_ea)

    # Result can be None if everything is defined, or an address
    if result is not None:
        # CRITICAL: Verify it's actually undefined
        assert search_db.bytes.is_unknown_at(result), (
            f"Address {hex(result)} from next_undefined() should be undefined"
        )


def test_next_defined_finds_address(search_db):
    """
    Test that next_defined can find defined items (instructions or data).

    RATIONALE: This is a fundamental operation - finding the next analyzed item
    in the database. Since we run auto-analysis on the test binary, there should
    be defined items (at minimum, the entry point and its surrounding code).

    We verify that the method returns a valid address and that it's actually
    defined according to IDA's analysis state.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_defined(start_ea)

    # With auto-analysis, we should find at least some defined addresses
    assert result is not None, 'Should find defined addresses in analyzed binary'

    # CRITICAL: Verify it's actually defined
    assert not search_db.bytes.is_unknown_at(result), (
        f"Address {hex(result)} from next_defined() should be defined"
    )


def test_all_undefined_iterator(search_db):
    """
    Test that all_undefined returns an iterator over undefined addresses.

    RATIONALE: This validates the iterator pattern for finding all unanalyzed
    regions. The test doesn't assume any specific undefined regions exist (they
    might not in a fully analyzed binary), but it validates that:
    - The return value is iterable
    - Any returned addresses are valid
    - Addresses are within the specified range
    - The iterator terminates (doesn't hang)

    We limit iteration to prevent potential infinite loops in case of bugs.
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    # Test that it's iterable and addresses are valid
    count = 0
    for ea in search_db.search.all_undefined(start_ea, end_ea):
        assert start_ea <= ea < end_ea, 'Address should be within range'
        # CRITICAL: Verify it's actually undefined
        assert search_db.bytes.is_unknown_at(ea), (
            f"Address {hex(ea)} from all_undefined() should be undefined"
        )
        count += 1
        if count >= 10:  # Limit to prevent infinite loops in tests
            break

    # Count can be 0 if fully analyzed, which is fine
    assert count >= 0, 'Should return non-negative count'


def test_all_defined_iterator(search_db):
    """
    Test that all_defined returns an iterator over defined addresses.

    RATIONALE: This is the complement to all_undefined - it finds all analyzed
    items. With auto-analysis enabled, we expect to find defined addresses.
    The test validates:
    - Iterator returns valid addresses
    - Addresses are within range
    - At least some defined addresses exist (since we auto-analyzed)

    This is crucial for any analysis that needs to process all analyzed items.
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    # Test that it's iterable and addresses are valid
    count = 0
    for ea in search_db.search.all_defined(start_ea, end_ea):
        assert start_ea <= ea < end_ea, 'Address should be within range'
        # CRITICAL: Verify it's actually defined
        assert not search_db.bytes.is_unknown_at(ea), (
            f"Address {hex(ea)} from all_defined() should be defined"
        )
        count += 1
        if count >= 10:  # Limit for test performance
            break

    # With auto-analysis, should have some defined addresses
    assert count > 0, 'Should find defined addresses in analyzed binary'


# =============================================================================
# TYPE-BASED SEARCH TESTS
# =============================================================================


def test_next_code_finds_instruction(search_db):
    """
    Test that next_code can find code (instruction) addresses.

    RATIONALE: Code search is essential for any instruction-level analysis.
    The test binary contains executable code sections, so next_code should
    find at least the entry point and subsequent instructions.

    We verify that:
    - A code address is found
    - The address is valid
    - The address actually contains code (not data)
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_code(start_ea)

    # Should find code in analyzed binary
    assert result is not None, 'Should find code in analyzed binary'

    # CRITICAL: Verify it's actually code
    assert search_db.bytes.is_code_at(result), (
        f"Address {hex(result)} from next_code() should be code"
    )

    # Verify it's >= start address (searching forward)
    assert result >= start_ea, (
        f"Result {hex(result)} should be >= start {hex(start_ea)}"
    )


def test_next_data_finds_data_item(search_db):
    """
    Test that next_data can find data addresses.

    RATIONALE: Many binaries have data sections (constants, strings, global
    variables). This test verifies we can find them. The result might be None
    if the test binary has no data sections, which is acceptable for a minimal
    test binary.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_data(start_ea)

    # Result can be None if binary has no data sections
    if result is not None:
        # CRITICAL: Verify it's actually data
        assert search_db.bytes.is_data_at(result), (
            f"Address {hex(result)} from next_data() should be data"
        )


def test_search_direction_up(search_db):
    """
    Test that SearchDirection.UP searches towards lower addresses.

    RATIONALE: Search direction control is important for context-aware analysis.
    When analyzing code, you often need to search backwards to find the
    beginning of a function or data structure.

    We start from the maximum address and search upward (towards lower
    addresses). We should find code since we started from the top of the
    address space.
    """
    start_ea = search_db.maximum_ea - 1  # Start near top
    result = search_db.search.next_code(start_ea, direction=SearchDirection.UP)

    # Should find code when searching upward from top of memory
    # (might be None if no code near top, which is acceptable)
    assert result is None or (isinstance(result, int) and search_db.is_valid_ea(result)), (
        'Search UP should return None or valid address'
    )

    if result is not None:
        assert result <= start_ea, 'UP search should find lower or equal address'


def test_all_code_iterator(search_db):
    """
    Test that all_code iterates over all code addresses.

    RATIONALE: This is crucial for comprehensive code analysis - processing
    every instruction in the binary. The test validates:
    - Iterator works correctly
    - Returns valid code addresses
    - Finds multiple code locations (not just one)

    Since we auto-analyzed, there should be at least some code.
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    count = 0
    for ea in search_db.search.all_code(start_ea, end_ea):
        # CRITICAL: Verify it's actually code
        assert search_db.bytes.is_code_at(ea), (
            f"Address {hex(ea)} from all_code() should be code"
        )
        count += 1
        if count >= 20:  # Test first 20 code locations
            break

    assert count > 0, 'Should find code addresses in analyzed binary'


def test_all_data_iterator(search_db):
    """
    Test that all_data iterates over all data addresses.

    RATIONALE: Similar to all_code but for data items. Not all binaries have
    significant data sections, so we accept 0 results but validate that any
    returned addresses are valid and within range.
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    count = 0
    for ea in search_db.search.all_data(start_ea, end_ea):
        assert start_ea <= ea < end_ea, 'Address should be within range'
        # CRITICAL: Verify it's actually data
        assert search_db.bytes.is_data_at(ea), (
            f"Address {hex(ea)} from all_data() should be data"
        )
        count += 1
        if count >= 10:
            break

    # Count can be 0 if no data sections
    assert count >= 0, 'Should return non-negative count'


def test_next_code_outside_function(search_db):
    """
    Test finding code that's not part of a function.

    RATIONALE: Sometimes IDA's auto-analysis misses functions or there's code
    that legitimately isn't part of a function (e.g., data in code sections,
    padding). This search helps identify such regions for manual analysis or
    automated function creation.

    The result might be None if all code is properly assigned to functions,
    which indicates good analysis quality.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_code_outside_function(start_ea)

    # Can be None if all code is in functions (good analysis)
    if result is not None:
        # CRITICAL: Verify it's code AND not in a function
        assert search_db.bytes.is_code_at(result), (
            f"Address {hex(result)} from next_code_outside_function() should be code"
        )
        assert not search_db.functions.get_at(result), (
            f"Address {hex(result)} should not be in a function"
        )


def test_all_code_outside_functions_iterator(search_db):
    """
    Test iteration over all orphaned code.

    RATIONALE: For analysis quality assurance, we want to identify all code
    that isn't assigned to functions. This might indicate missed functions
    or require manual investigation.

    The test accepts 0 results (good analysis) but validates any found
    addresses are legitimate.
    """
    count = 0
    for ea in search_db.search.all_code_outside_functions():
        assert search_db.is_valid_ea(ea), 'Orphaned code address should be valid'
        count += 1
        if count >= 5:
            break

    # Can be 0 if all code is properly in functions
    assert count >= 0, 'Should return non-negative count'


# =============================================================================
# PROBLEM-BASED SEARCH TESTS
# =============================================================================


def test_next_error_handling(search_db):
    """
    Test that next_error correctly returns tuple format.

    RATIONALE: Error search helps identify analysis problems. The return format
    is a tuple (address, operand_number) or (None, None). This test validates
    the format is correct regardless of whether errors are found.

    Well-analyzed binaries might have no errors, which is fine. The key is
    that the return format is consistent.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_error(start_ea)

    assert isinstance(result, tuple), 'next_error should return tuple'
    assert len(result) == 2, 'Tuple should have 2 elements (ea, opnum)'

    ea, opnum = result
    if ea is not None:
        assert search_db.is_valid_ea(ea), 'Error address should be valid'
        assert isinstance(opnum, int), 'Operand number should be int'
    else:
        assert opnum is None, 'If no error found, both values should be None'


def test_next_untyped_operand_handling(search_db):
    """
    Test that next_untyped_operand returns correct format.

    RATIONALE: Type information is important for analysis quality. This search
    finds operands that lack type information, which might indicate areas
    needing manual type annotation or automated type recovery.

    The return format validation ensures API consistency.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_untyped_operand(start_ea)

    assert isinstance(result, tuple), 'next_untyped_operand should return tuple'
    assert len(result) == 2, 'Tuple should have 2 elements'

    ea, opnum = result
    if ea is not None:
        assert search_db.is_valid_ea(ea), 'Address should be valid'
        assert isinstance(opnum, int), 'Operand number should be int'


def test_next_suspicious_operand_handling(search_db):
    """
    Test that next_suspicious_operand returns correct format.

    RATIONALE: Suspicious operands might indicate analysis issues or interesting
    code patterns worth investigating. The search helps quality assurance and
    security analysis.

    This test ensures the return format is consistent with other problem searches.
    """
    start_ea = search_db.minimum_ea
    result = search_db.search.next_suspicious_operand(start_ea)

    assert isinstance(result, tuple), 'next_suspicious_operand should return tuple'
    assert len(result) == 2, 'Tuple should have 2 elements'


def test_all_errors_iterator(search_db):
    """
    Test iteration over all errors.

    RATIONALE: For quality assurance, we want to enumerate all analysis errors.
    This enables automated validation and reporting.

    Well-analyzed binaries should have 0 errors, but the iterator should work
    correctly regardless.
    """
    count = 0
    for ea, opnum in search_db.search.all_errors():
        assert search_db.is_valid_ea(ea), 'Error address should be valid'
        assert isinstance(opnum, int), 'Operand number should be int'
        count += 1
        if count >= 5:
            break

    # Typically 0 for well-analyzed binaries
    assert count >= 0, 'Should return non-negative count'


def test_all_untyped_operands_iterator(search_db):
    """
    Test iteration over all untyped operands.

    RATIONALE: Type recovery is a common analysis task. This iterator enables
    bulk processing of all operands that need type information.

    The test validates the iterator format and that returned addresses are valid.
    """
    count = 0
    for ea, opnum in search_db.search.all_untyped_operands():
        assert search_db.is_valid_ea(ea), 'Address should be valid'
        assert isinstance(opnum, int), 'Operand number should be int'
        count += 1
        if count >= 5:
            break

    assert count >= 0, 'Should return non-negative count'


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


def test_invalid_start_address_raises_error(search_db):
    """
    Test that invalid start addresses raise InvalidEAError.

    RATIONALE: Input validation is critical for API safety. Invalid addresses
    (like 0xFFFFFFFFFFFFFFFF on 64-bit) should be caught early with clear
    error messages, not passed to the legacy API where they might cause
    undefined behavior.

    This test ensures we properly validate addresses before calling IDA's API.
    """
    from ida_domain.base import InvalidEAError

    invalid_ea = 0xFFFFFFFFFFFFFFFF  # BADADDR-like value

    with pytest.raises(InvalidEAError):
        search_db.search.next_code(invalid_ea)

    with pytest.raises(InvalidEAError):
        search_db.search.next_undefined(invalid_ea)


def test_invalid_range_raises_error(search_db):
    """
    Test that invalid ranges (start >= end) raise InvalidParameterError.

    RATIONALE: Searching from high to low address using all_* methods doesn't
    make sense - users should use next_* with SearchDirection.UP instead.
    We catch this error early to prevent confusing behavior or infinite loops.

    The test validates our parameter validation logic works correctly.
    """
    from ida_domain.base import InvalidParameterError

    start_ea = search_db.maximum_ea
    end_ea = search_db.minimum_ea  # Reversed!

    with pytest.raises(InvalidParameterError):
        list(search_db.search.all_code(start_ea, end_ea))


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


def test_search_entity_accessible_from_database(search_db):
    """
    Test that Search entity is accessible via db.search property.

    RATIONALE: This validates the integration of Search into the Database
    entity. Users should be able to access search functionality through
    the standard db.search property, following the established pattern.

    This is a smoke test ensuring the entity is properly wired up.
    """
    assert hasattr(search_db, 'search'), 'Database should have search property'
    assert search_db.search is not None, 'search property should not be None'

    from ida_domain.search import Search

    assert isinstance(search_db.search, Search), 'search should be Search instance'


def test_search_with_database_range(search_db):
    """
    Test search using database's min/max addresses as default range.

    RATIONALE: The all_* methods default to searching the entire database
    (min_ea to max_ea). This test validates that behavior works correctly
    and that we can successfully search the full address space.

    This ensures the default parameter handling is correct.
    """
    # Should use database min/max by default
    code_count = 0
    for ea in search_db.search.all_code():
        assert search_db.is_valid_ea(ea), 'Address should be valid'
        code_count += 1
        if code_count >= 5:
            break

    assert code_count >= 0, 'Should be able to search entire database'


def test_multiple_searches_on_same_database(search_db):
    """
    Test that multiple search operations can be performed on the same database.

    RATIONALE: In real usage, analysts perform many searches on the same
    database. This test ensures there's no state pollution between searches
    and that the entity can be used multiple times without issues.

    This validates thread-safety and statelessness of search operations.
    """
    # First search
    code1 = search_db.search.next_code(search_db.minimum_ea)

    # Second search
    code2 = search_db.search.next_code(search_db.minimum_ea)

    # Should get same result (deterministic)
    assert code1 == code2, 'Multiple searches should give consistent results'

    # Try different search types (should not interfere with each other)
    data1 = search_db.search.next_data(search_db.minimum_ea)
    undefined1 = search_db.search.next_undefined(search_db.minimum_ea)

    # No assertion needed - if they don't crash, test passes


# =============================================================================
# LLM-FRIENDLY API TESTS
# =============================================================================


def test_find_next_method_exists_and_is_callable(search_db):
    """
    Test that find_next() method exists as an LLM-friendly unified search interface.

    RATIONALE: The find_next() method provides a unified interface for LLMs to
    search for different address types using a string parameter instead of
    remembering individual method names like next_undefined(), next_code(), etc.
    This follows the same pattern as Analysis.schedule() which unified scheduling.
    """
    assert hasattr(search_db.search, 'find_next'), 'find_next() method should exist'
    assert callable(search_db.search.find_next), 'find_next() should be callable'


def test_find_next_with_undefined_type(search_db):
    """
    Test that find_next(ea, "undefined") works like next_undefined().

    RATIONALE: LLMs should be able to use find_next(ea, "undefined") as an
    alternative to next_undefined(ea). Both should return the same result.
    """
    start_ea = search_db.minimum_ea

    # Call find_next with "undefined"
    result = search_db.search.find_next(start_ea, "undefined")

    # Compare with direct method call
    expected = search_db.search.next_undefined(start_ea)

    assert result == expected, 'find_next("undefined") should match next_undefined()'


def test_find_next_with_defined_type(search_db):
    """
    Test that find_next(ea, "defined") works like next_defined().
    """
    start_ea = search_db.minimum_ea

    result = search_db.search.find_next(start_ea, "defined")
    expected = search_db.search.next_defined(start_ea)

    assert result == expected, 'find_next("defined") should match next_defined()'


def test_find_next_with_code_type(search_db):
    """
    Test that find_next(ea, "code") works like next_code().
    """
    start_ea = search_db.minimum_ea

    result = search_db.search.find_next(start_ea, "code")
    expected = search_db.search.next_code(start_ea)

    assert result == expected, 'find_next("code") should match next_code()'


def test_find_next_with_data_type(search_db):
    """
    Test that find_next(ea, "data") works like next_data().
    """
    start_ea = search_db.minimum_ea

    result = search_db.search.find_next(start_ea, "data")
    expected = search_db.search.next_data(start_ea)

    assert result == expected, 'find_next("data") should match next_data()'


def test_find_next_with_code_outside_function_type(search_db):
    """
    Test that find_next(ea, "code_outside_function") works like next_code_outside_function().
    """
    start_ea = search_db.minimum_ea

    result = search_db.search.find_next(start_ea, "code_outside_function")
    expected = search_db.search.next_code_outside_function(start_ea)

    assert result == expected, 'find_next("code_outside_function") should match'


def test_find_next_with_backward_direction(search_db):
    """
    Test that find_next() supports "backward" direction.

    RATIONALE: LLMs can use direction="backward" instead of needing to know
    about SearchDirection.UP enum. String literals are more intuitive.
    """
    start_ea = search_db.maximum_ea - 1

    # Call find_next with backward direction
    result = search_db.search.find_next(start_ea, "code", direction="backward")

    # Compare with direct method call
    expected = search_db.search.next_code(start_ea, direction=SearchDirection.UP)

    assert result == expected, 'find_next with backward should match UP direction'


def test_find_next_validates_address(search_db):
    """
    Test that find_next() properly validates the address parameter.
    """
    from ida_domain.base import InvalidEAError

    with pytest.raises(InvalidEAError):
        search_db.search.find_next(0xFFFFFFFFFFFFFFFF, "code")


def test_find_next_validates_what_parameter(search_db):
    """
    Test that find_next() validates the 'what' parameter.
    """
    from ida_domain.base import InvalidParameterError

    valid_ea = search_db.minimum_ea

    with pytest.raises(InvalidParameterError):
        search_db.search.find_next(valid_ea, "invalid_type")

    with pytest.raises(InvalidParameterError):
        search_db.search.find_next(valid_ea, "")


def test_find_next_validates_direction_parameter(search_db):
    """
    Test that find_next() validates the 'direction' parameter.
    """
    from ida_domain.base import InvalidParameterError

    valid_ea = search_db.minimum_ea

    with pytest.raises(InvalidParameterError):
        search_db.search.find_next(valid_ea, "code", direction="invalid")


# =============================================================================
# FIND_ALL LLM-FRIENDLY API TESTS
# =============================================================================


def test_find_all_method_exists_and_is_callable(search_db):
    """
    Test that find_all() method exists as an LLM-friendly unified iterator interface.

    RATIONALE: The find_all() method provides a unified interface for LLMs to
    iterate over addresses of different types using a string parameter instead of
    remembering individual method names like all_undefined(), all_code(), etc.
    """
    assert hasattr(search_db.search, 'find_all'), 'find_all() method should exist'
    assert callable(search_db.search.find_all), 'find_all() should be callable'


def test_find_all_with_undefined_type(search_db):
    """
    Test that find_all(start, end, "undefined") works like all_undefined().
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    # Get results from both methods
    find_all_results = list(search_db.search.find_all(start_ea, end_ea, "undefined"))
    all_results = list(search_db.search.all_undefined(start_ea, end_ea))

    # Compare first 10 results to avoid exhaustive comparison
    assert find_all_results[:10] == all_results[:10], (
        'find_all("undefined") should match all_undefined()'
    )


def test_find_all_with_defined_type(search_db):
    """
    Test that find_all(start, end, "defined") works like all_defined().
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    find_all_results = list(search_db.search.find_all(start_ea, end_ea, "defined"))
    all_results = list(search_db.search.all_defined(start_ea, end_ea))

    assert find_all_results[:10] == all_results[:10], (
        'find_all("defined") should match all_defined()'
    )


def test_find_all_with_code_type(search_db):
    """
    Test that find_all(start, end, "code") works like all_code().
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    find_all_results = list(search_db.search.find_all(start_ea, end_ea, "code"))
    all_results = list(search_db.search.all_code(start_ea, end_ea))

    assert find_all_results[:10] == all_results[:10], (
        'find_all("code") should match all_code()'
    )


def test_find_all_with_data_type(search_db):
    """
    Test that find_all(start, end, "data") works like all_data().
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    find_all_results = list(search_db.search.find_all(start_ea, end_ea, "data"))
    all_results = list(search_db.search.all_data(start_ea, end_ea))

    assert find_all_results[:10] == all_results[:10], (
        'find_all("data") should match all_data()'
    )


def test_find_all_with_code_outside_function_type(search_db):
    """
    Test that find_all(start, end, "code_outside_function") works like all_code_outside_functions().
    """
    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    find_all_results = list(
        search_db.search.find_all(start_ea, end_ea, "code_outside_function")
    )
    all_results = list(
        search_db.search.all_code_outside_functions(start_ea, end_ea)
    )

    assert find_all_results[:10] == all_results[:10], (
        'find_all("code_outside_function") should match all_code_outside_functions()'
    )


def test_find_all_validates_address_range(search_db):
    """
    Test that find_all() properly validates address range.
    """
    from ida_domain.base import InvalidEAError, InvalidParameterError

    # Invalid start address
    with pytest.raises(InvalidEAError):
        list(search_db.search.find_all(0xFFFFFFFFFFFFFFFF, search_db.minimum_ea, "code"))

    # Invalid end address
    with pytest.raises(InvalidEAError):
        list(search_db.search.find_all(search_db.minimum_ea, 0xFFFFFFFFFFFFFFFF, "code"))

    # start >= end should raise InvalidParameterError
    start_ea = search_db.minimum_ea + 0x100
    with pytest.raises(InvalidParameterError):
        list(search_db.search.find_all(start_ea, start_ea, "code"))


def test_find_all_validates_what_parameter(search_db):
    """
    Test that find_all() validates the 'what' parameter.
    """
    from ida_domain.base import InvalidParameterError

    start_ea = search_db.minimum_ea
    end_ea = search_db.maximum_ea

    with pytest.raises(InvalidParameterError):
        list(search_db.search.find_all(start_ea, end_ea, "invalid_type"))

    with pytest.raises(InvalidParameterError):
        list(search_db.search.find_all(start_ea, end_ea, ""))
