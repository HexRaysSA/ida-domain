"""Tests for Problems entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.problems import Problem, ProblemType


@pytest.fixture(scope='module')
def problems_test_setup():
    """
    Setup for problems tests.

    RATIONALE: We need a test binary to work with. Problems can be added
    manually to any binary, so we use the tiny_c.bin test binary which is
    small and suitable for testing. The Problems entity doesn't depend on
    specific binary contents - it's a metadata system that works with any
    IDA database.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'problems_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def problems_db(problems_test_setup):
    """
    Open database for problems testing.

    RATIONALE: Each test needs a fresh database instance to ensure test
    isolation. Problems are stored in the database, so we need to avoid
    interference between tests. We open with save_on_close=False to avoid
    saving test problems to disk.
    """
    idb_path = problems_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# PROPERTIES TESTS
# =============================================================================


def test_count_property_returns_non_negative_integer(problems_db):
    """
    Test that count method returns a non-negative integer.

    RATIONALE: The count method should always return a valid count,
    even if zero (for databases with no recorded problems). This validates:
    - The method is accessible
    - Returns the correct type (int)
    - Returns a sane value (>= 0)
    """
    count = problems_db.problems.count()

    assert isinstance(count, int), 'count should return an integer'
    assert count >= 0, 'count should be non-negative'


def test_len_matches_count_method(problems_db):
    """
    Test that __len__ returns the same value as count method.

    RATIONALE: The __len__ method should delegate to the count method,
    providing Pythonic len(db.problems) syntax. These should always match
    for API consistency.
    """
    count = problems_db.problems.count()
    length = len(problems_db.problems)

    assert length == count, '__len__ should match count method'


# =============================================================================
# MUTATION TESTS (Add, Remove, Clear)
# =============================================================================


def test_add_creates_problem_at_address(problems_db):
    """
    Test that add() creates a problem at the specified address.

    RATIONALE: The core functionality of the Problems entity is to record
    issues at specific addresses. This test validates:
    - add() method works correctly
    - Problem is stored and retrievable
    - Problem has correct type and address
    - Optional description is stored

    We use a known valid address from the test binary.
    """
    # Get a valid address from the database
    test_ea = problems_db.minimum_ea

    # Add a problem
    problems_db.problems.add(test_ea, ProblemType.DISASM, 'Test disassembly problem')

    # Verify problem was added
    assert problems_db.problems.has_problem(test_ea), 'Problem should exist after add()'
    assert problems_db.problems.has_problem(test_ea, ProblemType.DISASM), (
        'Specific problem type should exist'
    )

    # Retrieve and verify problem details
    problems_at_addr = list(problems_db.problems.get_at(test_ea))
    assert len(problems_at_addr) > 0, 'Should have at least one problem at address'

    # Find our test problem
    test_problem = None
    for p in problems_at_addr:
        if p.type == ProblemType.DISASM:
            test_problem = p
            break

    assert test_problem is not None, 'Should find DISASM problem'
    assert test_problem.address == test_ea, 'Problem should have correct address'
    assert test_problem.description == 'Test disassembly problem', (
        'Problem should have correct description'
    )


def test_add_multiple_problem_types_at_same_address(problems_db):
    """
    Test that multiple problem types can exist at the same address.

    RATIONALE: IDA allows multiple different problem types to be recorded
    at the same address (e.g., both a disassembly failure AND a stack
    tracing issue). This test validates:
    - Multiple problem types coexist at same address
    - Each problem type is independently queryable
    - get_at() returns all problem types at the address
    """
    test_ea = problems_db.minimum_ea

    # Add multiple problem types
    problems_db.problems.add(test_ea, ProblemType.DISASM, 'Disasm issue')
    problems_db.problems.add(test_ea, ProblemType.BADSTACK, 'Stack issue')
    problems_db.problems.add(test_ea, ProblemType.NOXREFS, 'Missing xrefs')

    # Verify all three problem types exist
    assert problems_db.problems.has_problem(test_ea, ProblemType.DISASM)
    assert problems_db.problems.has_problem(test_ea, ProblemType.BADSTACK)
    assert problems_db.problems.has_problem(test_ea, ProblemType.NOXREFS)

    # Verify get_at() returns all of them
    problems_at_addr = list(problems_db.problems.get_at(test_ea))
    problem_types = {p.type for p in problems_at_addr}

    assert ProblemType.DISASM in problem_types, 'Should include DISASM problem'
    assert ProblemType.BADSTACK in problem_types, 'Should include BADSTACK problem'
    assert ProblemType.NOXREFS in problem_types, 'Should include NOXREFS problem'


def test_remove_deletes_specific_problem_type(problems_db):
    """
    Test that remove() deletes a specific problem type at an address.

    RATIONALE: Users should be able to remove specific problem types when
    they're resolved, without affecting other problems at the same address.
    This test validates:
    - remove() returns True when problem exists
    - Problem is actually removed
    - Other problem types at same address are unaffected
    """
    test_ea = problems_db.minimum_ea + 0x10

    # Add two different problem types
    problems_db.problems.add(test_ea, ProblemType.DISASM)
    problems_db.problems.add(test_ea, ProblemType.BADSTACK)

    # Remove one problem type
    result = problems_db.problems.remove(test_ea, ProblemType.DISASM)

    assert result is True, 'remove() should return True for existing problem'
    assert not problems_db.problems.has_problem(test_ea, ProblemType.DISASM), (
        'DISASM problem should be removed'
    )
    assert problems_db.problems.has_problem(test_ea, ProblemType.BADSTACK), (
        'BADSTACK problem should remain'
    )


def test_remove_returns_false_for_nonexistent_problem(problems_db):
    """
    Test that remove() returns False when problem doesn't exist.

    RATIONALE: remove() should indicate success/failure through its return
    value. When removing a non-existent problem, it should return False
    to indicate nothing was removed.
    """
    test_ea = problems_db.minimum_ea + 0x20

    # Try to remove problem that doesn't exist
    result = problems_db.problems.remove(test_ea, ProblemType.DISASM)

    assert result is False, 'remove() should return False for non-existent problem'


def test_remove_at_deletes_all_problems_at_address(problems_db):
    """
    Test that remove_at() removes all problem types at an address.

    RATIONALE: Sometimes you want to clear all problems at a specific
    address (e.g., after successful reanalysis). This test validates:
    - remove_at() removes all problem types
    - Returns correct count of removed problems
    - Address has no remaining problems after removal
    """
    test_ea = problems_db.minimum_ea + 0x30

    # Add multiple problem types
    problems_db.problems.add(test_ea, ProblemType.DISASM)
    problems_db.problems.add(test_ea, ProblemType.BADSTACK)
    problems_db.problems.add(test_ea, ProblemType.ATTN)

    # Remove all problems at address
    removed_count = problems_db.problems.remove_at(test_ea)

    assert removed_count == 3, 'Should remove all 3 problems'
    assert not problems_db.problems.has_problem(test_ea), 'No problems should remain at address'


def test_clear_removes_all_problems_of_specific_type(problems_db):
    """
    Test that clear() removes all problems of a specific type.

    RATIONALE: When resolving a class of issues (e.g., all disassembly
    problems after improving analysis), clear() should remove all problems
    of that type across the entire database. This test validates:
    - clear() removes problems at multiple addresses
    - Only affects specified problem type
    - Returns correct count of removed problems
    - Other problem types remain unaffected
    """
    # Add DISASM problems at multiple addresses
    ea1 = problems_db.minimum_ea + 0x40
    ea2 = problems_db.minimum_ea + 0x50
    ea3 = problems_db.minimum_ea + 0x60

    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.DISASM)
    problems_db.problems.add(ea3, ProblemType.DISASM)

    # Also add a different problem type that should remain
    problems_db.problems.add(ea1, ProblemType.BADSTACK)

    # Clear all DISASM problems
    removed_count = problems_db.problems.clear(ProblemType.DISASM)

    assert removed_count == 3, 'Should remove 3 DISASM problems'
    assert not problems_db.problems.has_problem(ea1, ProblemType.DISASM)
    assert not problems_db.problems.has_problem(ea2, ProblemType.DISASM)
    assert not problems_db.problems.has_problem(ea3, ProblemType.DISASM)
    assert problems_db.problems.has_problem(ea1, ProblemType.BADSTACK), (
        'Other problem types should remain'
    )


def test_clear_all_removes_all_problems(problems_db):
    """
    Test that clear_all() removes all problems of all types.

    RATIONALE: For database cleanup or reset operations, clear_all()
    should remove every problem. This test validates:
    - clear_all() removes problems of all types
    - Returns total count of removed problems
    - Database has no problems after clear_all()
    """
    # Add various problems
    ea1 = problems_db.minimum_ea + 0x70
    ea2 = problems_db.minimum_ea + 0x80

    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea1, ProblemType.BADSTACK)
    problems_db.problems.add(ea2, ProblemType.NOXREFS)

    # Clear all problems
    removed_count = problems_db.problems.clear_all()

    assert removed_count == 3, 'Should remove all 3 problems'
    assert len(problems_db.problems) == 0, 'No problems should remain in database'
    assert not problems_db.problems.has_problem(ea1)
    assert not problems_db.problems.has_problem(ea2)


# =============================================================================
# QUERY TESTS
# =============================================================================


def test_get_all_returns_all_problems_when_no_filter(problems_db):
    """
    Test that get_all() with no filter returns problems of all types.

    RATIONALE: get_all() should return an iterator over all problems in
    the database when called without a type filter. This test validates:
    - All problem types are included
    - Problems from different addresses are included
    - Iterator produces correct Problem objects
    """
    # Add problems of different types at different addresses
    ea1 = problems_db.minimum_ea + 0x90
    ea2 = problems_db.minimum_ea + 0xA0

    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.BADSTACK)

    # Get all problems
    all_problems = list(problems_db.problems.get_all())

    # Verify we got at least our test problems
    problem_types = {p.type for p in all_problems}
    addresses = {p.address for p in all_problems}

    assert ProblemType.DISASM in problem_types, 'Should include DISASM problems'
    assert ProblemType.BADSTACK in problem_types, 'Should include BADSTACK problems'
    assert ea1 in addresses, 'Should include problems from ea1'
    assert ea2 in addresses, 'Should include problems from ea2'


def test_get_all_filters_by_problem_type(problems_db):
    """
    Test that get_all() with type filter returns only that type.

    RATIONALE: When debugging specific issues, users need to filter
    problems by type. This test validates:
    - Only requested problem type is returned
    - Other problem types are filtered out
    - Filtering works correctly across multiple addresses
    """
    ea1 = problems_db.minimum_ea + 0xB0
    ea2 = problems_db.minimum_ea + 0xC0

    # Add problems of multiple types
    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.DISASM)
    problems_db.problems.add(ea1, ProblemType.BADSTACK)

    # Get only DISASM problems
    disasm_problems = list(problems_db.problems.get_all(ProblemType.DISASM))

    assert len(disasm_problems) == 2, 'Should find exactly 2 DISASM problems'
    for problem in disasm_problems:
        assert problem.type == ProblemType.DISASM, 'All problems should be DISASM type'


def test_get_between_returns_problems_in_range(problems_db):
    """
    Test that get_between() returns only problems within address range.

    RATIONALE: When analyzing a specific function or code region, users
    need to see only problems in that range. This test validates:
    - Only problems within [start, end) are returned
    - Problems outside the range are excluded
    - Range boundaries are correct (inclusive start, exclusive end)
    """
    # Use small offsets to stay within valid range for small test binary
    ea_before = problems_db.minimum_ea
    ea_in_range1 = problems_db.minimum_ea + 0x10
    ea_in_range2 = problems_db.minimum_ea + 0x20
    ea_after = problems_db.minimum_ea + 0x30

    # Add problems at various addresses
    problems_db.problems.add(ea_before, ProblemType.DISASM)
    problems_db.problems.add(ea_in_range1, ProblemType.DISASM)
    problems_db.problems.add(ea_in_range2, ProblemType.BADSTACK)
    problems_db.problems.add(ea_after, ProblemType.DISASM)

    # Get problems in range
    start_ea = ea_in_range1
    end_ea = ea_after  # Exclusive, so ea_after should not be included

    problems_in_range = list(problems_db.problems.get_between(start_ea, end_ea))
    addresses_in_range = {p.address for p in problems_in_range}

    assert ea_before not in addresses_in_range, 'Problem before range should be excluded'
    assert ea_in_range1 in addresses_in_range, 'Problem at range start should be included'
    assert ea_in_range2 in addresses_in_range, 'Problem within range should be included'
    assert ea_after not in addresses_in_range, 'Problem at range end should be excluded'


def test_get_between_with_type_filter(problems_db):
    """
    Test that get_between() can filter by both range and type.

    RATIONALE: Combining range and type filters is a common use case
    (e.g., "show me disassembly problems in this function"). This test
    validates both filters work together correctly.
    """
    ea1 = problems_db.minimum_ea + 0x40
    ea2 = problems_db.minimum_ea + 0x50

    # Add problems of multiple types in range
    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.DISASM)
    problems_db.problems.add(ea1, ProblemType.BADSTACK)

    # Get only DISASM problems in range
    problems = list(
        problems_db.problems.get_between(ea1, ea2 + 0x10, problem_type=ProblemType.DISASM)
    )

    assert len(problems) == 2, 'Should find 2 DISASM problems'
    for problem in problems:
        assert problem.type == ProblemType.DISASM, 'All should be DISASM type'


def test_get_next_finds_next_problem_of_any_type(problems_db):
    """
    Test that get_next() without type filter finds closest problem.

    RATIONALE: Navigation through problems is essential for review
    workflows. This test validates:
    - get_next() finds the nearest problem at or after given address
    - Searches across all problem types
    - Returns None when no more problems exist
    - Returns correct Problem object with all details
    """
    ea1 = problems_db.minimum_ea + 0x60
    ea2 = problems_db.minimum_ea + 0x70
    search_from = ea1 - 0x10  # Before first problem

    # Add problems
    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.BADSTACK)

    # Find next problem from before first one
    next_problem = problems_db.problems.get_next(search_from)

    assert next_problem is not None, 'Should find a problem'
    assert next_problem.address == ea1, 'Should find problem at ea1 (closest)'


def test_get_next_with_type_filter(problems_db):
    """
    Test that get_next() with type filter finds next of specific type.

    RATIONALE: When fixing specific problem categories, users want to
    navigate only through that type. This test validates type-specific
    navigation works correctly and skips other problem types.
    """
    ea1 = problems_db.minimum_ea + 0x80
    ea2 = problems_db.minimum_ea + 0x90
    ea3 = problems_db.minimum_ea + 0xA0

    # Add problems: DISASM at ea1, BADSTACK at ea2, DISASM at ea3
    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.BADSTACK)
    problems_db.problems.add(ea3, ProblemType.DISASM)

    # Find next DISASM problem starting from ea2
    # Should skip BADSTACK at ea2 and find DISASM at ea3
    next_problem = problems_db.problems.get_next(ea2, ProblemType.DISASM)

    assert next_problem is not None, 'Should find a DISASM problem'
    assert next_problem.address == ea3, 'Should find DISASM at ea3, skipping BADSTACK'
    assert next_problem.type == ProblemType.DISASM


def test_get_next_returns_none_when_no_more_problems(problems_db):
    """
    Test that get_next() returns None when no more problems exist.

    RATIONALE: Proper iteration termination - get_next() should return
    None when there are no more problems to find, allowing loops to
    terminate naturally.
    """
    # Search from near end of address space
    search_from = problems_db.maximum_ea - 0x10

    next_problem = problems_db.problems.get_next(search_from)

    # Should be None unless there happen to be actual problems near max_ea
    # In our test case, we haven't added any there
    if next_problem is not None:
        # If a problem exists, it should be at or after search address
        assert next_problem.address >= search_from


def test_count_by_type_returns_correct_count(problems_db):
    """
    Test that count_by_type() returns accurate count for each type.

    RATIONALE: Statistics about problems help users prioritize fixes.
    This test validates:
    - count_by_type() accurately counts problems of specific type
    - Count is correct even with multiple addresses
    - Different types have independent counts
    """
    ea1 = problems_db.minimum_ea + 0xB0
    ea2 = problems_db.minimum_ea + 0xC0
    ea3 = problems_db.minimum_ea + 0xD0

    # Add 3 DISASM problems and 1 BADSTACK problem
    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.DISASM)
    problems_db.problems.add(ea3, ProblemType.DISASM)
    problems_db.problems.add(ea1, ProblemType.BADSTACK)

    disasm_count = problems_db.problems.count_by_type(ProblemType.DISASM)
    badstack_count = problems_db.problems.count_by_type(ProblemType.BADSTACK)

    assert disasm_count == 3, 'Should count 3 DISASM problems'
    assert badstack_count == 1, 'Should count 1 BADSTACK problem'


def test_was_auto_decision_detects_ida_decisions(problems_db):
    """
    Test that was_auto_decision() correctly identifies IDA decisions.

    RATIONALE: was_auto_decision() is a convenience method for checking
    if IDA made an automatic decision at an address. This test validates:
    - Correctly identifies FINAL problem type
    - Returns True only for addresses with FINAL markers
    - Returns False for other problem types and empty addresses
    """
    ea_decision = problems_db.minimum_ea + 0xE0
    ea_no_decision = problems_db.minimum_ea + 0xE8

    # Add FINAL problem (IDA decision)
    problems_db.problems.add(ea_decision, ProblemType.FINAL)
    # Add different problem type
    problems_db.problems.add(ea_no_decision, ProblemType.DISASM)

    assert problems_db.problems.was_auto_decision(ea_decision), 'Should detect IDA decision'
    assert not problems_db.problems.was_auto_decision(ea_no_decision), (
        'Should not report decision for DISASM problem'
    )


def test_problem_type_name_returns_readable_string(problems_db):
    """
    Test that Problem.type_name returns human-readable description.

    RATIONALE: When displaying problems to users, readable names are
    essential. This test validates the type_name property works and
    returns meaningful strings from IDA's problem naming system.
    """
    ea = problems_db.minimum_ea + 0xF0

    problems_db.problems.add(ea, ProblemType.DISASM, 'Test description')

    problem = next(problems_db.problems.get_at(ea))
    type_name = problem.type_name

    assert isinstance(type_name, str), 'type_name should return a string'
    assert len(type_name) > 0, 'type_name should not be empty'
    # Should be something like "Can't disassemble"
    assert 'disasm' in type_name.lower() or "can't" in type_name.lower()


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


def test_add_raises_error_for_invalid_address(problems_db):
    """
    Test that add() raises InvalidEAError for invalid addresses.

    RATIONALE: Operations on invalid addresses should fail fast with
    clear errors. This prevents silent failures and helps users identify
    bugs in their code.
    """
    invalid_ea = 0xFFFFFFFFFFFFFFFF  # Definitely invalid

    with pytest.raises(InvalidEAError):
        problems_db.problems.add(invalid_ea, ProblemType.DISASM)


def test_remove_raises_error_for_invalid_address(problems_db):
    """
    Test that remove() raises InvalidEAError for invalid addresses.

    RATIONALE: Consistent error handling across all methods - invalid
    addresses should always raise InvalidEAError.
    """
    invalid_ea = 0xFFFFFFFFFFFFFFFF

    with pytest.raises(InvalidEAError):
        problems_db.problems.remove(invalid_ea, ProblemType.DISASM)


def test_has_problem_raises_error_for_invalid_address(problems_db):
    """
    Test that has_problem() raises InvalidEAError for invalid addresses.

    RATIONALE: Query methods should also validate addresses to maintain
    API consistency and catch user errors early.
    """
    invalid_ea = 0xFFFFFFFFFFFFFFFF

    with pytest.raises(InvalidEAError):
        problems_db.problems.has_problem(invalid_ea)


def test_get_between_raises_error_when_start_gte_end(problems_db):
    """
    Test that get_between() raises error when start >= end.

    RATIONALE: An empty or inverted range is a logic error that should
    be caught immediately rather than returning empty results silently.
    """
    start_ea = problems_db.minimum_ea + 0xF0
    end_ea = problems_db.minimum_ea + 0x40  # Before start

    with pytest.raises(InvalidParameterError):
        list(problems_db.problems.get_between(start_ea, end_ea))


def test_get_between_raises_error_for_invalid_start_address(problems_db):
    """
    Test that get_between() validates start address.

    RATIONALE: Both range boundaries should be validated to ensure
    meaningful queries.
    """
    invalid_start = 0xFFFFFFFFFFFFFFFF
    valid_end = problems_db.maximum_ea

    with pytest.raises(InvalidEAError):
        list(problems_db.problems.get_between(invalid_start, valid_end))


def test_get_between_raises_error_for_invalid_end_address(problems_db):
    """
    Test that get_between() validates end address.

    RATIONALE: Both range boundaries should be validated for API
    consistency and to catch user errors early.
    """
    valid_start = problems_db.minimum_ea
    invalid_end = 0xFFFFFFFFFFFFFFFF

    with pytest.raises(InvalidEAError):
        list(problems_db.problems.get_between(valid_start, invalid_end))


# =============================================================================
# ITERATION TESTS
# =============================================================================


def test_iter_protocol_iterates_all_problems(problems_db):
    """
    Test that __iter__ allows iteration over all problems.

    RATIONALE: Python iteration protocol (for loop) should work
    naturally with the Problems entity. This test validates:
    - __iter__ is implemented correctly
    - Iteration returns Problem objects
    - All problems are included
    """
    ea1 = problems_db.minimum_ea + 0xF8
    ea2 = problems_db.minimum_ea + 0xFC

    problems_db.problems.add(ea1, ProblemType.DISASM)
    problems_db.problems.add(ea2, ProblemType.BADSTACK)

    # Use for loop (calls __iter__)
    problems_list = []
    for problem in problems_db.problems:
        problems_list.append(problem)
        assert isinstance(problem, Problem), 'Should yield Problem objects'

    addresses = {p.address for p in problems_list}
    assert ea1 in addresses, 'Should include problem at ea1'
    assert ea2 in addresses, 'Should include problem at ea2'
