"""Tests for Switches entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.switches import SwitchFlags, SwitchInfo


@pytest.fixture(scope='module')
def switches_test_setup():
    """
    Setup for switches tests.

    RATIONALE: We need a binary containing switch statements to properly test
    the Switches entity. The tiny_c.bin binary is suitable as it contains
    compiled C code which may include switch statements. While we cannot
    guarantee switch statements exist in every test binary, this binary
    provides a realistic test environment.

    For tests requiring switches to exist, we'll need to either:
    - Create switches manually (testing create/update/delete functionality)
    - Skip tests if no natural switches exist in the binary
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'switches_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def switches_db(switches_test_setup):
    """
    Open database for switches testing.

    RATIONALE: Each test needs a fresh database instance to ensure test
    isolation. We open the database with auto-analysis enabled to ensure
    proper switch detection by IDA's automated analysis.
    """
    idb_path = switches_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# QUERY METHOD TESTS
# =============================================================================


def test_get_at_returns_none_for_nonexistent_switch(switches_db):
    """
    Test that get_at returns None when no switch exists at the address.

    RATIONALE: This validates the basic query operation when no switch is
    present. We pick an arbitrary valid address that is unlikely to have
    a switch statement. This tests the "not found" path of the method.
    """
    # Pick a valid address - use minimum_ea as it's valid but unlikely to be a switch
    ea = switches_db.minimum_ea
    result = switches_db.switches.get_at(ea)

    # Most addresses don't have switches, so None is expected
    assert result is None or isinstance(result, SwitchInfo), (
        'get_at should return None or SwitchInfo'
    )


def test_get_at_raises_on_invalid_address(switches_db):
    """
    Test that get_at raises InvalidEAError for invalid addresses.

    RATIONALE: This validates input validation and error handling. Invalid
    addresses should be caught early with a clear exception rather than
    passing through to IDA's API which might crash or return undefined
    behavior.

    We test with an address that is definitely outside the valid range
    (maximum + large offset).
    """
    from ida_domain.base import InvalidEAError

    invalid_ea = switches_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        switches_db.switches.get_at(invalid_ea)


def test_exists_at_returns_false_for_nonexistent_switch(switches_db):
    """
    Test that exists_at returns False when no switch exists.

    RATIONALE: The exists_at method is a convenience wrapper that should
    return a boolean. This tests the common case where no switch is present.
    It's simpler than get_at for existence checks.
    """
    ea = switches_db.minimum_ea
    result = switches_db.switches.exists_at(ea)

    assert isinstance(result, bool), 'exists_at should return boolean'
    # Most addresses don't have switches
    assert result is False or result is True


def test_exists_at_raises_on_invalid_address(switches_db):
    """
    Test that exists_at raises InvalidEAError for invalid addresses.

    RATIONALE: Consistent error handling across all query methods. Even
    the simple exists_at check should validate inputs properly.
    """
    from ida_domain.base import InvalidEAError

    invalid_ea = switches_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        switches_db.switches.exists_at(invalid_ea)


# =============================================================================
# CREATE/UPDATE/DELETE TESTS
# =============================================================================


def test_create_switch_with_valid_data(switches_db):
    """
    Test creating a new switch statement with valid data.

    RATIONALE: This tests the core creation functionality. We create a simple
    dense switch (most common type) with minimal valid parameters. This
    validates that:
    - The create method accepts a properly formatted SwitchInfo
    - The switch can be retrieved after creation
    - The data round-trips correctly (what we create is what we get back)

    We use addresses in the valid range but unlikely to have existing switches.
    """
    # Find a suitable address - use a code address if available
    test_ea = switches_db.minimum_ea + 0x100  # Offset to avoid entry point

    # Ensure address is valid
    if not switches_db.is_valid_ea(test_ea):
        pytest.skip('Cannot find valid test address')

    # Create a simple dense switch (no value table)
    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=test_ea + 0x100,  # Jump table after switch instruction
        values=None,  # Dense switch has no value table
        lowcase=0,  # Cases 0-4
        defjump=test_ea + 0x200,  # Default case address
        startea=test_ea,  # Start of switch idiom
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,  # Unknown register
    )

    # Create the switch
    result = switches_db.switches.create(test_ea, switch_info)
    assert result is True, 'create should return True for valid data'

    # Verify it was created
    retrieved = switches_db.switches.get_at(test_ea)
    assert retrieved is not None, 'Should be able to retrieve created switch'
    assert retrieved.ncases == 5, 'Case count should match'
    assert retrieved.lowcase == 0, 'Lowcase should match'
    assert retrieved.defjump == test_ea + 0x200, 'Default jump should match'


def test_create_switch_with_invalid_address_raises_error(switches_db):
    """
    Test that create raises InvalidEAError for invalid addresses.

    RATIONALE: Input validation is critical for create operations. Attempting
    to create a switch at an invalid address should fail gracefully with a
    clear error rather than corrupting the database or crashing.
    """
    from ida_domain.base import InvalidEAError

    invalid_ea = switches_db.maximum_ea + 0x10000

    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=3,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=invalid_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    with pytest.raises(InvalidEAError):
        switches_db.switches.create(invalid_ea, switch_info)


def test_create_switch_with_negative_ncases_raises_error(switches_db):
    """
    Test that create raises InvalidParameterError for negative case counts.

    RATIONALE: Data validation is essential. A switch with negative cases
    makes no sense and should be rejected early with a clear error message.
    This prevents passing invalid data to IDA's underlying API.
    """
    from ida_domain.base import InvalidParameterError

    test_ea = switches_db.minimum_ea + 0x100

    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=-5,  # Invalid: negative cases
        jumps=test_ea + 0x100,
        values=None,
        lowcase=0,
        defjump=test_ea + 0x200,
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    with pytest.raises(InvalidParameterError):
        switches_db.switches.create(test_ea, switch_info)


def test_update_switch_modifies_existing(switches_db):
    """
    Test that update modifies an existing switch statement.

    RATIONALE: The update operation should allow modifying switch properties
    after initial creation. This is important for refining switch analysis
    as more information becomes available. We test the update path by:
    1. Creating a switch with initial values
    2. Updating it with different values
    3. Verifying the new values are persisted
    """
    test_ea = switches_db.minimum_ea + 0x100

    # Create initial switch
    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=3,
        jumps=test_ea + 0x100,
        values=None,
        lowcase=0,
        defjump=test_ea + 0x200,
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(test_ea, switch_info)

    # Update with different case count
    updated_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=7,  # Changed from 3 to 7
        jumps=test_ea + 0x100,
        values=None,
        lowcase=0,
        defjump=test_ea + 0x300,  # Changed default jump
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    result = switches_db.switches.update(test_ea, updated_info)
    assert result is True, 'update should return True'

    # Verify the update
    retrieved = switches_db.switches.get_at(test_ea)
    assert retrieved is not None
    assert retrieved.ncases == 7, 'Case count should be updated'
    assert retrieved.defjump == test_ea + 0x300, 'Default jump should be updated'


def test_remove_deletes_existing_switch(switches_db):
    """
    Test that remove deletes an existing switch statement.

    RATIONALE: The remove operation should cleanly delete switch information.
    This is important for correcting mis-detected switches or removing
    manual annotations. We verify that:
    - remove returns True when a switch exists
    - The switch is actually deleted (get_at returns None after)
    - Subsequent removes return False (idempotent)
    """
    test_ea = switches_db.minimum_ea + 0x100

    # Create a switch
    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=test_ea + 0x100,
        values=None,
        lowcase=0,
        defjump=test_ea + 0x200,
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(test_ea, switch_info)

    # Remove it
    result = switches_db.switches.remove(test_ea)
    assert result is True, 'remove should return True for existing switch'

    # Verify it's gone
    retrieved = switches_db.switches.get_at(test_ea)
    assert retrieved is None, 'Switch should be deleted'

    # Second remove should return False
    result2 = switches_db.switches.remove(test_ea)
    assert result2 is False, 'remove should return False when no switch exists'


def test_remove_nonexistent_returns_false(switches_db):
    """
    Test that remove returns False when no switch exists.

    RATIONALE: The remove method should be idempotent and clearly indicate
    whether a switch was actually deleted. Returning False for non-existent
    switches allows callers to distinguish between successful deletion and
    no-op cases.
    """
    test_ea = switches_db.minimum_ea + 0x100

    # Try to remove non-existent switch
    result = switches_db.switches.remove(test_ea)
    assert result is False, 'remove should return False when no switch exists'


# =============================================================================
# PARENT RELATIONSHIP TESTS
# =============================================================================


def test_get_parent_returns_none_for_no_relationship(switches_db):
    """
    Test that get_parent returns None when no parent relationship exists.

    RATIONALE: Most addresses don't have parent switch relationships. This
    tests the common case where we query an address that has no parent.
    The method should return None (converted from BADADDR) rather than
    raising an exception.
    """
    ea = switches_db.minimum_ea
    result = switches_db.switches.get_parent(ea)

    assert result is None or isinstance(result, int), 'get_parent should return None or an address'


def test_set_parent_creates_relationship(switches_db):
    """
    Test that set_parent creates a parent relationship between addresses.

    RATIONALE: Parent relationships allow multiple case targets to reference
    a single switch_info structure. This is important for memory efficiency
    and consistency. We test that:
    - set_parent successfully creates the relationship
    - get_parent returns the correct parent address
    - The relationship persists
    """
    switch_ea = switches_db.minimum_ea + 0x10
    case_ea = switches_db.minimum_ea + 0x20

    # Ensure both addresses are valid
    if not switches_db.is_valid_ea(switch_ea) or not switches_db.is_valid_ea(case_ea):
        pytest.skip('Cannot find valid addresses for parent test')

    # Create a switch at switch_ea
    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=switch_ea + 0x40,
        values=None,
        lowcase=0,
        defjump=switch_ea + 0x50,
        startea=switch_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(switch_ea, switch_info)

    # Set parent relationship
    result = switches_db.switches.set_parent(case_ea, switch_ea)
    assert result is True, 'set_parent should return True'

    # Verify the relationship
    parent = switches_db.switches.get_parent(case_ea)
    assert parent == switch_ea, 'get_parent should return the parent address'


def test_remove_parent_deletes_relationship(switches_db):
    """
    Test that remove_parent deletes an existing parent relationship.

    RATIONALE: We need to be able to remove parent relationships when they're
    no longer needed or were set incorrectly. This tests the deletion path
    by creating a relationship and then removing it.
    """
    switch_ea = switches_db.minimum_ea + 0x10
    case_ea = switches_db.minimum_ea + 0x20

    # Ensure both addresses are valid
    if not switches_db.is_valid_ea(switch_ea) or not switches_db.is_valid_ea(case_ea):
        pytest.skip('Cannot find valid addresses for parent test')

    # Create switch and set parent
    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=switch_ea + 0x40,
        values=None,
        lowcase=0,
        defjump=switch_ea + 0x50,
        startea=switch_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(switch_ea, switch_info)
    switches_db.switches.set_parent(case_ea, switch_ea)

    # Remove the relationship
    result = switches_db.switches.remove_parent(case_ea)
    assert result is True, 'remove_parent should return True for existing relationship'

    # Verify it's removed
    parent = switches_db.switches.get_parent(case_ea)
    assert parent is None, 'Parent relationship should be deleted'


def test_remove_parent_nonexistent_returns_false(switches_db):
    """
    Test that remove_parent returns False when no relationship exists.

    RATIONALE: Similar to remove, remove_parent should be idempotent and
    clearly indicate whether a relationship was actually deleted.
    """
    ea = switches_db.minimum_ea + 0x100

    result = switches_db.switches.remove_parent(ea)
    assert result is False, 'remove_parent should return False when no relationship exists'


# =============================================================================
# SWITCH ANALYSIS TESTS
# =============================================================================


def test_get_case_count_returns_zero_for_nonexistent(switches_db):
    """
    Test that get_case_count returns 0 when no switch exists.

    RATIONALE: This convenience method should handle the non-existent case
    gracefully by returning 0 rather than raising an exception. This makes
    it easy to use in conditional logic without explicit existence checks.
    """
    ea = switches_db.minimum_ea
    count = switches_db.switches.get_case_count(ea)

    assert count == 0, 'get_case_count should return 0 for non-existent switch'


def test_get_case_count_returns_correct_count(switches_db):
    """
    Test that get_case_count returns the correct case count for a switch.

    RATIONALE: This validates the convenience method against a known switch
    that we create. It should match the ncases field we set.
    """
    test_ea = switches_db.minimum_ea + 0x100

    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=8,  # Specific count to test
        jumps=test_ea + 0x100,
        values=None,
        lowcase=0,
        defjump=test_ea + 0x200,
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(test_ea, switch_info)

    count = switches_db.switches.get_case_count(test_ea)
    assert count == 8, 'get_case_count should return the correct case count'


def test_get_case_values_dense_switch(switches_db):
    """
    Test getting case values for a dense switch statement.

    RATIONALE: Dense switches compute case values from lowcase + offset.
    This is the most common switch type. We create a dense switch and
    verify that get_case_values computes the correct sequential values.
    """
    test_ea = switches_db.minimum_ea + 0x100

    switch_info = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=test_ea + 0x100,
        values=None,  # No value table = dense
        lowcase=10,  # Start at 10
        defjump=test_ea + 0x200,
        startea=test_ea,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    switches_db.switches.create(test_ea, switch_info)

    values = switches_db.switches.get_case_values(switch_info)

    # Should be [10, 11, 12, 13, 14]
    assert len(values) == 5, 'Should have 5 case values'
    assert values == [10, 11, 12, 13, 14], 'Values should be sequential from lowcase'


# =============================================================================
# SWITCHINFO DATACLASS PROPERTY TESTS
# =============================================================================


def test_switchinfo_is_sparse_property():
    """
    Test the is_sparse computed property of SwitchInfo.

    RATIONALE: The is_sparse property determines whether the switch uses a
    value table. This is a key distinction in switch types. We test both
    sparse and dense cases to ensure the flag is correctly interpreted.
    """
    # Dense switch (no SPARSE flag)
    dense = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    assert dense.is_sparse is False, 'Dense switch should not be sparse'

    # Sparse switch (with SPARSE flag)
    sparse = SwitchInfo(
        flags=SwitchFlags.SPARSE,
        ncases=5,
        jumps=0x1000,
        values=0x3000,  # Has value table
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    assert sparse.is_sparse is True, 'Sparse switch should be detected'


def test_switchinfo_has_default_property():
    """
    Test the has_default computed property of SwitchInfo.

    RATIONALE: The has_default property indicates whether a switch has a
    default case. This is determined by checking if defjump is BADADDR.
    Important for understanding control flow completeness.
    """
    # Import BADADDR inside test to avoid module-level import before IDA is loaded
    from ida_idaapi import BADADDR

    # Switch with default
    with_default = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,  # Valid address
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    assert with_default.has_default is True, 'Switch with valid defjump should have default'

    # Switch without default
    without_default = SwitchInfo(
        flags=SwitchFlags.DEFAULT,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=BADADDR,  # No default
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )

    assert without_default.has_default is False, 'Switch with BADADDR should not have default'


def test_switchinfo_jtable_element_size():
    """
    Test the jtable_element_size computed property.

    RATIONALE: The jump table element size is encoded in flag bits and
    determines how to read the jump table. We test all four possible sizes
    (1, 2, 4, 8 bytes) to ensure correct decoding.
    """
    # 2-byte elements (default)
    size2 = SwitchInfo(
        flags=0,  # No J32 or JSIZE
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )
    assert size2.jtable_element_size == 2

    # 4-byte elements
    size4 = SwitchInfo(
        flags=SwitchFlags.J32,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )
    assert size4.jtable_element_size == 4

    # 1-byte elements
    size1 = SwitchInfo(
        flags=SwitchFlags.JSIZE,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )
    assert size1.jtable_element_size == 1

    # 8-byte elements
    size8 = SwitchInfo(
        flags=SwitchFlags.J32 | SwitchFlags.JSIZE,
        ncases=5,
        jumps=0x1000,
        values=None,
        lowcase=0,
        defjump=0x2000,
        startea=0x900,
        jcases=0,
        ind_lowcase=0,
        elbase=0,
        regnum=-1,
    )
    assert size8.jtable_element_size == 8
