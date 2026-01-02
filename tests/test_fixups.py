"""Tests for Fixups entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.fixups import FixupInfo, FixupType


@pytest.fixture(scope='module')
def fixups_test_setup():
    """
    Setup for fixups tests.

    RATIONALE: We need a binary containing fixups (relocations) to properly test
    the Fixups entity. The tiny_c.bin binary is compiled code which should contain
    fixups for any external references or position-independent code. Most compiled
    binaries have at least some fixups, especially PE/ELF formats with imports.

    Fixups are created by loaders when parsing binary relocation tables, so they
    are present in virtually all dynamically linked binaries.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'fixups_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def fixups_db(fixups_test_setup):
    """
    Open database for fixups testing.

    RATIONALE: Each test needs a fresh database instance to ensure test
    isolation. We open the database with auto-analysis enabled to ensure
    proper fixup detection and processing by IDA's loader.
    """
    idb_path = fixups_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# PROPERTIES TESTS
# =============================================================================


def test_count_returns_non_negative_integer(fixups_db):
    """
    Test that count property returns a non-negative integer.

    RATIONALE: The count property should always return a valid count,
    even if zero (for statically linked binaries). This validates that:
    - The property is accessible
    - Returns the correct type (int)
    - Returns a sane value (>= 0)

    We don't assert a specific count since it depends on the binary,
    but we validate the returned value is a reasonable integer.
    """
    count = fixups_db.fixups.count

    assert isinstance(count, int), 'count should return an integer'
    assert count >= 0, 'count should be non-negative'


def test_len_matches_count(fixups_db):
    """
    Test that __len__ returns the same value as count property.

    RATIONALE: The __len__ method should delegate to the count property,
    providing Pythonic len(db.fixups) syntax. These should always match.
    """
    count = fixups_db.fixups.count
    length = len(fixups_db.fixups)

    assert length == count, '__len__ should match count property'


# =============================================================================
# QUERY METHOD TESTS
# =============================================================================


def test_get_at_returns_none_for_address_without_fixup(fixups_db):
    """
    Test that get_at returns None when no fixup exists at the address.

    RATIONALE: This validates the basic query operation for the common case
    where no fixup is present. Most addresses in a binary don't have fixups,
    so returning None is the expected behavior. This tests the "not found" path.

    We use minimum_ea which is typically a valid address but unlikely to have
    a fixup (usually points to header or code section start).
    """
    ea = fixups_db.minimum_ea
    result = fixups_db.fixups.get_at(ea)

    # Entry point typically doesn't have a fixup
    assert result is None, f'get_at at entry point 0x{ea:x} should return None'


def test_get_at_raises_on_invalid_address(fixups_db):
    """
    Test that get_at raises InvalidEAError for invalid addresses.

    RATIONALE: This validates input validation and error handling. Invalid
    addresses should be caught early with a clear exception rather than
    passing through to IDA's API which might crash or return undefined behavior.

    We test with an address that is definitely outside the valid range.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.get_at(invalid_ea)


def test_has_fixup_returns_boolean(fixups_db):
    """
    Test that has_fixup returns a boolean value.

    RATIONALE: The has_fixup method is a convenience wrapper that should
    return a boolean. This tests that it returns the correct type for any
    valid address, even if the result varies (True/False) based on whether
    a fixup exists.
    """
    ea = fixups_db.minimum_ea
    result = fixups_db.fixups.has_fixup(ea)

    assert isinstance(result, bool), 'has_fixup should return boolean'


def test_has_fixup_raises_on_invalid_address(fixups_db):
    """
    Test that has_fixup raises InvalidEAError for invalid addresses.

    RATIONALE: Consistent error handling across all query methods. Even
    the simple has_fixup check should validate inputs properly.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.has_fixup(invalid_ea)


def test_get_all_returns_iterator(fixups_db):
    """
    Test that get_all returns an iterator of FixupInfo objects.

    RATIONALE: The get_all method should return an iterator (lazy evaluation)
    rather than a list, for memory efficiency. This tests:
    - Return type is iterable
    - Elements (if any) are FixupInfo objects
    - Iterator can be consumed

    We don't assert how many fixups exist since it depends on the binary,
    but we validate the iterator protocol works.
    """
    fixups = fixups_db.fixups.get_all()

    # Check it's iterable
    fixups_list = list(fixups)

    # All elements should be FixupInfo (if any exist)
    for fixup in fixups_list:
        assert isinstance(fixup, FixupInfo), 'get_all should yield FixupInfo objects'


def test_get_between_with_valid_range(fixups_db):
    """
    Test that get_between returns fixups in the specified range.

    RATIONALE: This tests range queries, a common operation for analyzing
    fixups within specific code sections (e.g., a function or segment).

    We use the full database range (min_ea to max_ea) which should return
    the same fixups as get_all. This validates:
    - Range filtering works
    - Boundary conditions are handled correctly
    - Iterator protocol works
    """
    start_ea = fixups_db.minimum_ea
    end_ea = fixups_db.maximum_ea

    fixups = list(fixups_db.fixups.get_between(start_ea, end_ea))

    # All returned fixups should be FixupInfo
    for fixup in fixups:
        assert isinstance(fixup, FixupInfo)
        # Fixup should be within range (inclusive start, exclusive end)
        assert start_ea <= fixup.address < end_ea


def test_get_between_raises_on_invalid_start_address(fixups_db):
    """
    Test that get_between raises InvalidEAError for invalid start address.

    RATIONALE: Input validation for range queries. Both start and end
    addresses should be validated.
    """
    invalid_start = fixups_db.maximum_ea + 0x10000
    valid_end = fixups_db.maximum_ea

    with pytest.raises(InvalidEAError):
        list(fixups_db.fixups.get_between(invalid_start, valid_end))


def test_get_between_raises_on_invalid_end_address(fixups_db):
    """
    Test that get_between raises InvalidEAError for invalid end address.

    RATIONALE: Both boundary addresses need validation.
    """
    valid_start = fixups_db.minimum_ea
    invalid_end = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        list(fixups_db.fixups.get_between(valid_start, invalid_end))


def test_get_between_raises_on_inverted_range(fixups_db):
    """
    Test that get_between raises InvalidParameterError when start >= end.

    RATIONALE: Range queries require start < end. Inverted ranges are
    logically invalid and should be caught with a clear error.
    """
    start_ea = fixups_db.maximum_ea
    end_ea = fixups_db.minimum_ea  # Inverted!

    with pytest.raises(InvalidParameterError):
        list(fixups_db.fixups.get_between(start_ea, end_ea))


def test_contains_fixups_returns_boolean(fixups_db):
    """
    Test that contains_fixups returns a boolean.

    RATIONALE: The contains_fixups method checks if any fixups exist in a
    range. It should return a simple boolean rather than a count or list.
    This tests the return type for the full database range.
    """
    start_ea = fixups_db.minimum_ea
    size = fixups_db.maximum_ea - fixups_db.minimum_ea

    result = fixups_db.fixups.contains_fixups(start_ea, size)

    assert isinstance(result, bool), 'contains_fixups should return boolean'


def test_contains_fixups_raises_on_invalid_address(fixups_db):
    """
    Test that contains_fixups raises InvalidEAError for invalid address.

    RATIONALE: Input validation for range existence check.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.contains_fixups(invalid_ea, 100)


def test_contains_fixups_raises_on_invalid_size(fixups_db):
    """
    Test that contains_fixups raises InvalidParameterError for invalid size.

    RATIONALE: The size parameter must be positive. Zero or negative sizes
    are invalid and should be rejected.
    """
    valid_ea = fixups_db.minimum_ea

    with pytest.raises(InvalidParameterError):
        fixups_db.fixups.contains_fixups(valid_ea, 0)

    with pytest.raises(InvalidParameterError):
        fixups_db.fixups.contains_fixups(valid_ea, -10)


def test_get_description_returns_string(fixups_db):
    """
    Test that get_description returns a string.

    RATIONALE: The description method should always return a string, even
    if empty when no fixup exists. This tests the return type and that
    the method doesn't raise exceptions for addresses without fixups.
    """
    ea = fixups_db.minimum_ea
    desc = fixups_db.fixups.get_description(ea)

    assert isinstance(desc, str), 'get_description should return string'
    # Empty string is valid when no fixup exists


def test_get_description_raises_on_invalid_address(fixups_db):
    """
    Test that get_description raises InvalidEAError for invalid address.

    RATIONALE: Consistent input validation across all methods.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.get_description(invalid_ea)


# =============================================================================
# COLLECTION PROTOCOL TESTS
# =============================================================================


def test_iter_returns_all_fixups(fixups_db):
    """
    Test that iterating over db.fixups yields all fixups.

    RATIONALE: The __iter__ method should provide Pythonic iteration syntax
    (for fixup in db.fixups). This should return the same fixups as get_all.
    """
    iter_fixups = list(fixups_db.fixups)
    all_fixups = list(fixups_db.fixups.get_all())

    assert len(iter_fixups) == len(all_fixups), '__iter__ should return same count as get_all'

    # All elements should be FixupInfo
    for fixup in iter_fixups:
        assert isinstance(fixup, FixupInfo)


# =============================================================================
# DATA CLASS TESTS
# =============================================================================


def test_fixup_info_target_property(fixups_db):
    """
    Test that FixupInfo.target property computes correctly.

    RATIONALE: The target property is a computed field that should return
    target_offset + displacement. This tests that the property works and
    returns a valid address.

    If any fixups exist in the database, we test the property. If none exist,
    we create a mock FixupInfo to test the computation.
    """
    # Try to get a real fixup first
    fixups_list = list(fixups_db.fixups.get_all())

    if fixups_list:
        # Test with real fixup
        fixup = fixups_list[0]
        expected = fixup.target_offset + fixup.displacement
        assert fixup.target == expected, 'target property should compute correctly'
    else:
        # Create a mock FixupInfo to test the property
        from ida_idaapi import BADADDR

        mock_fixup = FixupInfo(
            address=0x1000,
            type=FixupType.OFF32,
            target_offset=0x2000,
            displacement=0x100,
            is_relative=False,
            is_extdef=True,
            is_unused=False,
            was_created=False,
        )
        assert mock_fixup.target == 0x2100, 'target property should compute correctly'


def test_fixup_info_is_immutable(fixups_db):
    """
    Test that FixupInfo is immutable (frozen dataclass).

    RATIONALE: FixupInfo should be immutable since fixups represent read-only
    database information. Attempts to modify fields should raise an error.
    """
    from ida_idaapi import BADADDR

    fixup = FixupInfo(
        address=0x1000,
        type=FixupType.OFF32,
        target_offset=0x2000,
        displacement=0,
        is_relative=False,
        is_extdef=True,
        is_unused=False,
        was_created=False,
    )

    # Attempt to modify should raise FrozenInstanceError
    with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
        fixup.address = 0x3000  # type: ignore


# =============================================================================
# MUTATION METHOD TESTS (if database is writable)
# =============================================================================


def test_add_fixup_basic(fixups_db):
    """
    Test adding a fixup with basic parameters.

    RATIONALE: The add method allows manual fixup creation, useful for binary
    patching scenarios. This tests:
    - Basic fixup can be added
    - Method returns boolean success value
    - Added fixup can be retrieved

    We pick an address without an existing fixup to avoid conflicts.
    """
    # Find an address without a fixup
    test_ea = fixups_db.minimum_ea + 0x100

    # Ensure no fixup exists there already
    if fixups_db.fixups.has_fixup(test_ea):
        pytest.skip('Test address already has a fixup')

    # Add a fixup
    target = fixups_db.minimum_ea + 0x200
    success = fixups_db.fixups.add(
        ea=test_ea, fixup_type=FixupType.OFF32, target_offset=target
    )

    assert isinstance(success, bool), 'add should return boolean'

    # If addition succeeded, verify we can retrieve it
    if success:
        fixup = fixups_db.fixups.get_at(test_ea)
        assert fixup is not None, 'Added fixup should be retrievable'
        assert fixup.type == FixupType.OFF32, 'Fixup type should match'


def test_add_fixup_raises_on_invalid_address(fixups_db):
    """
    Test that add raises InvalidEAError for invalid address.

    RATIONALE: Input validation for mutation operations.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.add(
            ea=invalid_ea,
            fixup_type=FixupType.OFF32,
            target_offset=fixups_db.minimum_ea,
        )


def test_remove_returns_false_for_nonexistent_fixup(fixups_db):
    """
    Test that remove returns False when removing non-existent fixup.

    RATIONALE: The remove method should indicate whether a fixup was actually
    removed. Attempting to remove a non-existent fixup should return False
    (not an error).
    """
    # Find an address without a fixup
    test_ea = fixups_db.minimum_ea

    # Ensure no fixup exists
    if fixups_db.fixups.has_fixup(test_ea):
        # Try another address
        test_ea = test_ea + 0x10

    if not fixups_db.fixups.has_fixup(test_ea):
        result = fixups_db.fixups.remove(test_ea)
        assert result is False, 'remove should return False for non-existent fixup'


def test_remove_raises_on_invalid_address(fixups_db):
    """
    Test that remove raises InvalidEAError for invalid address.

    RATIONALE: Input validation for removal operations.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.remove(invalid_ea)


def test_patch_value_raises_on_invalid_address(fixups_db):
    """
    Test that patch_value raises InvalidEAError for invalid address.

    RATIONALE: Input validation for patch operations.
    """
    invalid_ea = fixups_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        fixups_db.fixups.patch_value(invalid_ea)


def test_patch_value_returns_false_for_nonexistent_fixup(fixups_db):
    """
    Test that patch_value returns False when no fixup exists.

    RATIONALE: The patch_value method should indicate whether patching
    succeeded. Attempting to patch where no fixup exists should return False.
    """
    # Find an address without a fixup
    test_ea = fixups_db.minimum_ea

    if not fixups_db.fixups.has_fixup(test_ea):
        result = fixups_db.fixups.patch_value(test_ea)
        assert result is False, 'patch_value should return False for non-existent fixup'
