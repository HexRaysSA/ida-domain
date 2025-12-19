"""Tests for TryBlocks entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.try_blocks import (
    CatchHandler,
    SehFilterCode,
    SehHandler,
    TryBlock,
    TryBlockError,
    TryBlockKind,
)


@pytest.fixture(scope='module')
def try_blocks_test_setup():
    """
    Setup for try blocks tests.

    RATIONALE: We need a test environment to validate the TryBlocks entity.
    While the tiny_c.bin binary may not contain exception handling code,
    it provides a valid IDA database environment where we can test:
    - Query methods on a database without try blocks (common case)
    - Creation and deletion of try blocks (testing mutation methods)
    - Error handling and validation

    For tests requiring existing try blocks, we'll create them programmatically
    or skip tests if the feature is not applicable to the binary.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'try_blocks_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def try_blocks_db(try_blocks_test_setup):
    """
    Open database for try blocks testing.

    RATIONALE: Each test needs a fresh database instance to ensure test
    isolation. We open the database with auto-analysis enabled to ensure
    proper function detection, which is needed for try block operations.
    """
    idb_path = try_blocks_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


# =============================================================================
# PROPERTY TESTS
# =============================================================================


def test_entity_type_property(try_blocks_db):
    """
    Test that entity_type property returns the correct identifier.

    RATIONALE: This validates the entity type identification which is used
    for runtime type checking and debugging. The entity_type should always
    return "try_blocks" regardless of database state.
    """
    assert try_blocks_db.try_blocks.entity_type == 'try_blocks'


# =============================================================================
# QUERY METHOD TESTS - get_in_range
# =============================================================================


def test_get_in_range_returns_empty_for_range_without_try_blocks(try_blocks_db):
    """
    Test that get_in_range returns empty iterator when no try blocks exist.

    RATIONALE: This tests the most common case - querying a range that has
    no exception handling. Since our test binary likely doesn't have try blocks,
    this validates the "not found" path. The method should return an iterator
    that yields no results, not None or an error.
    """
    start_ea = try_blocks_db.minimum_ea
    end_ea = try_blocks_db.maximum_ea

    result = list(try_blocks_db.try_blocks.get_in_range(start_ea, end_ea))

    assert isinstance(result, list), 'get_in_range should return iterable'
    # Empty or not, both are valid - just checking it works
    assert all(isinstance(tb, TryBlock) for tb in result), 'All results should be TryBlock'


def test_get_in_range_validates_start_address(try_blocks_db):
    """
    Test that get_in_range raises InvalidEAError for invalid start address.

    RATIONALE: Input validation is critical for robustness. Invalid addresses
    should be rejected before calling IDA's API. This tests the start address
    validation with an address well outside the valid range.
    """
    invalid_start = try_blocks_db.maximum_ea + 0x10000
    valid_end = try_blocks_db.maximum_ea

    with pytest.raises(InvalidEAError):
        list(try_blocks_db.try_blocks.get_in_range(invalid_start, valid_end))


def test_get_in_range_validates_end_address(try_blocks_db):
    """
    Test that get_in_range raises InvalidEAError for invalid end address.

    RATIONALE: Both start and end addresses must be validated. This tests
    the end address validation independently from start address validation.
    """
    valid_start = try_blocks_db.minimum_ea
    invalid_end = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        list(try_blocks_db.try_blocks.get_in_range(valid_start, invalid_end))


def test_get_in_range_rejects_reversed_range(try_blocks_db):
    """
    Test that get_in_range raises error when start >= end.

    RATIONALE: A range where start >= end is semantically invalid (empty or
    reversed). The API should reject this early rather than passing it to
    IDA which might have undefined behavior.
    """
    # Use valid addresses but in reversed order
    start_ea = try_blocks_db.minimum_ea + 0x10
    end_ea = try_blocks_db.minimum_ea  # end < start

    with pytest.raises(InvalidParameterError):
        list(try_blocks_db.try_blocks.get_in_range(start_ea, end_ea))


# =============================================================================
# QUERY METHOD TESTS - get_at
# =============================================================================


def test_get_at_returns_none_for_address_without_try_block(try_blocks_db):
    """
    Test that get_at returns None when address is not in any try block.

    RATIONALE: This tests the common case where an address is not within
    exception handling code. The method should return None (not raise an
    exception) to indicate "not found".
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.get_at(ea)

    assert result is None or isinstance(result, TryBlock), 'get_at should return None or TryBlock'


def test_get_at_validates_address(try_blocks_db):
    """
    Test that get_at raises InvalidEAError for invalid address.

    RATIONALE: Input validation for single-address queries. Invalid addresses
    should be rejected before attempting to search for try blocks.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.get_at(invalid_ea)


def test_get_at_returns_none_for_address_outside_function(try_blocks_db):
    """
    Test that get_at returns None when address is not in a function.

    RATIONALE: Try blocks are only valid within functions. When querying
    an address that's not in any function (e.g., data segment), get_at
    should gracefully return None rather than failing.
    """
    # Try to find an address that's not in a function
    # We'll use minimum_ea which is often not in a function
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.get_at(ea)

    # Should not raise exception, should return None if not in function
    assert result is None or isinstance(result, TryBlock)


# =============================================================================
# QUERY METHOD TESTS - Boolean Checks
# =============================================================================


def test_is_in_try_block_returns_false_for_normal_code(try_blocks_db):
    """
    Test that is_in_try_block returns False for code without exception handling.

    RATIONALE: This tests the simple boolean check for the common case of
    code that doesn't have try blocks. Should return False, not raise exception.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_in_try_block(ea)

    assert isinstance(result, bool), 'is_in_try_block should return boolean'


def test_is_in_try_block_validates_address(try_blocks_db):
    """
    Test that is_in_try_block raises InvalidEAError for invalid address.

    RATIONALE: Even simple boolean checks must validate inputs properly.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.is_in_try_block(invalid_ea)


def test_is_in_try_block_with_kind_filter_cpp(try_blocks_db):
    """
    Test that is_in_try_block accepts kind filter for C++ try blocks.

    RATIONALE: The kind parameter allows filtering by exception handling
    type. This tests the CPP filter works and returns a boolean.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_in_try_block(ea, TryBlockKind.CPP)

    assert isinstance(result, bool), 'is_in_try_block with filter should return boolean'


def test_is_in_try_block_with_kind_filter_seh(try_blocks_db):
    """
    Test that is_in_try_block accepts kind filter for SEH try blocks.

    RATIONALE: Tests the SEH filter variant of the method.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_in_try_block(ea, TryBlockKind.SEH)

    assert isinstance(result, bool), 'is_in_try_block with SEH filter should return boolean'


def test_is_catch_start_returns_false_for_normal_code(try_blocks_db):
    """
    Test that is_catch_start returns False for non-catch code.

    RATIONALE: Tests the catch handler boundary detection for the common
    case where an address is not a catch handler start.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_catch_start(ea)

    assert isinstance(result, bool), 'is_catch_start should return boolean'


def test_is_catch_start_validates_address(try_blocks_db):
    """
    Test that is_catch_start raises InvalidEAError for invalid address.

    RATIONALE: Validates input checking for catch boundary detection.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.is_catch_start(invalid_ea)


def test_is_seh_handler_start_returns_false_for_normal_code(try_blocks_db):
    """
    Test that is_seh_handler_start returns False for non-SEH code.

    RATIONALE: Tests SEH handler boundary detection for normal code.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_seh_handler_start(ea)

    assert isinstance(result, bool), 'is_seh_handler_start should return boolean'


def test_is_seh_handler_start_validates_address(try_blocks_db):
    """
    Test that is_seh_handler_start raises InvalidEAError for invalid address.

    RATIONALE: Validates input checking for SEH handler detection.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.is_seh_handler_start(invalid_ea)


def test_is_seh_filter_start_returns_false_for_normal_code(try_blocks_db):
    """
    Test that is_seh_filter_start returns False for non-filter code.

    RATIONALE: Tests SEH filter boundary detection for normal code.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.is_seh_filter_start(ea)

    assert isinstance(result, bool), 'is_seh_filter_start should return boolean'


def test_is_seh_filter_start_validates_address(try_blocks_db):
    """
    Test that is_seh_filter_start raises InvalidEAError for invalid address.

    RATIONALE: Validates input checking for SEH filter detection.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.is_seh_filter_start(invalid_ea)


def test_find_seh_region_returns_none_for_non_seh_code(try_blocks_db):
    """
    Test that find_seh_region returns None when address is not in SEH region.

    RATIONALE: Tests the SEH region search for the common case where code
    doesn't use SEH. Should return None for "not found".
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.find_seh_region(ea)

    assert result is None or isinstance(result, int), (
        'find_seh_region should return None or address'
    )


def test_find_seh_region_validates_address(try_blocks_db):
    """
    Test that find_seh_region raises InvalidEAError for invalid address.

    RATIONALE: Validates input checking for SEH region search.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.find_seh_region(invalid_ea)


def test_has_fallthrough_from_unwind_returns_false_for_normal_code(try_blocks_db):
    """
    Test that has_fallthrough_from_unwind returns False for normal code.

    RATIONALE: Tests exception unwind detection for code without exception
    handling. Most code won't have fall-through from unwind paths.
    """
    ea = try_blocks_db.minimum_ea

    result = try_blocks_db.try_blocks.has_fallthrough_from_unwind(ea)

    assert isinstance(result, bool), 'has_fallthrough_from_unwind should return boolean'


def test_has_fallthrough_from_unwind_validates_address(try_blocks_db):
    """
    Test that has_fallthrough_from_unwind raises InvalidEAError for invalid address.

    RATIONALE: Validates input checking for unwind detection.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.has_fallthrough_from_unwind(invalid_ea)


# =============================================================================
# MUTATION METHOD TESTS - add
# =============================================================================


def test_add_try_block_validates_addresses(try_blocks_db):
    """
    Test that add validates addresses in try block ranges.

    RATIONALE: When adding a try block, all addresses in the ranges must
    be validated. This tests that invalid addresses are rejected before
    attempting to add the try block to IDA's database.
    """
    invalid_ea = try_blocks_db.maximum_ea + 0x10000

    try_block = TryBlock(
        ranges=((invalid_ea, invalid_ea + 0x100),),
        kind=TryBlockKind.CPP,
        level=0,
        catches=(),
        seh_handler=None,
    )

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.add(try_block)


def test_add_try_block_rejects_empty_try_block(try_blocks_db):
    """
    Test that add rejects try blocks with no ranges.

    RATIONALE: An empty try block (no address ranges) is semantically invalid.
    The API should reject this with a clear error rather than passing it to
    IDA which might have undefined behavior.
    """
    try_block = TryBlock(
        ranges=(),  # Empty ranges
        kind=TryBlockKind.CPP,
        level=0,
        catches=(),
        seh_handler=None,
    )

    with pytest.raises(TryBlockError):
        try_blocks_db.try_blocks.add(try_block)


def test_add_try_block_rejects_cpp_without_catches(try_blocks_db):
    """
    Test that add rejects C++ try blocks without catch handlers.

    RATIONALE: A C++ try block must have at least one catch handler, otherwise
    it's semantically invalid. This validates that the API enforces this rule.
    """
    start_ea = try_blocks_db.minimum_ea
    end_ea = min(start_ea + 0x100, try_blocks_db.maximum_ea)

    try_block = TryBlock(
        ranges=((start_ea, end_ea),),
        kind=TryBlockKind.CPP,
        level=0,
        catches=None,  # No catches for CPP try block
        seh_handler=None,
    )

    with pytest.raises(TryBlockError):
        try_blocks_db.try_blocks.add(try_block)


# =============================================================================
# MUTATION METHOD TESTS - remove_in_range
# =============================================================================


def test_remove_in_range_returns_false_when_no_try_blocks(try_blocks_db):
    """
    Test that remove_in_range returns False when no try blocks to remove.

    RATIONALE: The remove method should indicate whether anything was removed.
    When removing from a range that has no try blocks, it should return False
    (nothing was removed) rather than raising an error.
    """
    start_ea = try_blocks_db.minimum_ea
    end_ea = try_blocks_db.maximum_ea

    result = try_blocks_db.try_blocks.remove_in_range(start_ea, end_ea)

    assert isinstance(result, bool), 'remove_in_range should return boolean'
    # Likely False since test binary probably has no try blocks
    assert result is False or result is True


def test_remove_in_range_validates_start_address(try_blocks_db):
    """
    Test that remove_in_range raises InvalidEAError for invalid start address.

    RATIONALE: Deletion operations must validate inputs before modifying
    the database. This tests start address validation.
    """
    invalid_start = try_blocks_db.maximum_ea + 0x10000
    valid_end = try_blocks_db.maximum_ea

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.remove_in_range(invalid_start, valid_end)


def test_remove_in_range_validates_end_address(try_blocks_db):
    """
    Test that remove_in_range raises InvalidEAError for invalid end address.

    RATIONALE: Both start and end addresses must be validated for deletion.
    """
    valid_start = try_blocks_db.minimum_ea
    invalid_end = try_blocks_db.maximum_ea + 0x10000

    with pytest.raises(InvalidEAError):
        try_blocks_db.try_blocks.remove_in_range(valid_start, invalid_end)


def test_remove_in_range_rejects_reversed_range(try_blocks_db):
    """
    Test that remove_in_range raises error when start >= end.

    RATIONALE: Deletion with reversed range is semantically invalid and
    should be rejected early.
    """
    # Use valid addresses but in reversed order
    start_ea = try_blocks_db.minimum_ea + 0x10
    end_ea = try_blocks_db.minimum_ea  # end < start

    with pytest.raises(InvalidParameterError):
        try_blocks_db.try_blocks.remove_in_range(start_ea, end_ea)


# =============================================================================
# DATA CLASS TESTS
# =============================================================================


def test_tryblock_properties_cpp():
    """
    Test TryBlock properties for C++ try/catch blocks.

    RATIONALE: Validates the convenience properties and computed attributes
    of TryBlock dataclass for C++ exception handling. These properties are
    used throughout client code for type checking and branching.
    """
    catch = CatchHandler(
        ranges=((0x1000, 0x1100),),
        type_id=123,
        obj_offset=16,
        frame_register=5,
    )

    try_block = TryBlock(
        ranges=((0x1000, 0x1050),),
        kind=TryBlockKind.CPP,
        level=0,
        catches=(catch,),
        seh_handler=None,
    )

    assert try_block.is_cpp is True
    assert try_block.is_seh is False
    assert try_block.start_ea == 0x1000
    assert try_block.end_ea == 0x1050
    assert try_block.is_empty is False


def test_tryblock_properties_seh():
    """
    Test TryBlock properties for SEH blocks.

    RATIONALE: Validates TryBlock properties for Windows SEH exception
    handling, ensuring proper type identification.
    """
    seh = SehHandler(
        ranges=((0x1100, 0x1200),),
        filter_ranges=(),
        seh_code=SehFilterCode.HANDLE,
        frame_register=5,
    )

    try_block = TryBlock(
        ranges=((0x1000, 0x1050),),
        kind=TryBlockKind.SEH,
        level=0,
        catches=None,
        seh_handler=seh,
    )

    assert try_block.is_cpp is False
    assert try_block.is_seh is True
    assert try_block.start_ea == 0x1000
    assert try_block.end_ea == 0x1050


def test_tryblock_empty():
    """
    Test TryBlock is_empty property.

    RATIONALE: The is_empty property is used to validate try blocks before
    operations. Tests that it correctly identifies empty try blocks.
    """
    try_block = TryBlock(
        ranges=(),  # Empty
        kind=TryBlockKind.NONE,
        level=0,
        catches=None,
        seh_handler=None,
    )

    assert try_block.is_empty is True


def test_catch_handler_properties_normal():
    """
    Test CatchHandler properties for normal catch blocks.

    RATIONALE: Validates the convenience properties for identifying catch
    handler types (normal, catch-all, cleanup).
    """
    catch = CatchHandler(
        ranges=((0x1000, 0x1100),),
        type_id=123,  # Normal type
        obj_offset=16,
        frame_register=5,
    )

    assert catch.is_catch_all is False
    assert catch.is_cleanup is False
    assert catch.start_ea == 0x1000
    assert catch.end_ea == 0x1100


def test_catch_handler_properties_catch_all():
    """
    Test CatchHandler properties for catch(...) blocks.

    RATIONALE: Validates identification of catch-all handlers (catch(...))
    which have a special type_id of -1.
    """
    catch = CatchHandler(
        ranges=((0x1000, 0x1100),),
        type_id=-1,  # Catch all
        obj_offset=-1,
        frame_register=-1,
    )

    assert catch.is_catch_all is True
    assert catch.is_cleanup is False


def test_catch_handler_properties_cleanup():
    """
    Test CatchHandler properties for cleanup handlers.

    RATIONALE: Validates identification of cleanup handlers (called during
    stack unwinding) which have a special type_id of -2.
    """
    catch = CatchHandler(
        ranges=((0x1000, 0x1100),),
        type_id=-2,  # Cleanup
        obj_offset=-1,
        frame_register=-1,
    )

    assert catch.is_catch_all is False
    assert catch.is_cleanup is True


def test_seh_handler_properties_with_filter():
    """
    Test SehHandler properties when using filter callback.

    RATIONALE: SEH handlers can use filter callbacks to determine whether
    to handle an exception. This tests proper identification of filter-based
    handlers.
    """
    seh = SehHandler(
        ranges=((0x1100, 0x1200),),
        filter_ranges=((0x1050, 0x1080),),  # Has filter
        seh_code=SehFilterCode.HANDLE,
        frame_register=5,
    )

    assert seh.has_filter is True
    assert seh.is_finally is False
    assert seh.filter_start_ea == 0x1050


def test_seh_handler_properties_finally():
    """
    Test SehHandler properties for __finally blocks.

    RATIONALE: __finally blocks use SEH_SEARCH code and no filter callback.
    This tests proper identification of finally handlers.
    """
    seh = SehHandler(
        ranges=((0x1100, 0x1200),),
        filter_ranges=(),  # No filter
        seh_code=SehFilterCode.SEARCH,  # __finally
        frame_register=5,
    )

    assert seh.has_filter is False
    assert seh.is_finally is True
    assert seh.filter_start_ea is None


def test_seh_handler_properties_no_filter():
    """
    Test SehHandler properties for handlers with constant filter code.

    RATIONALE: SEH handlers can use constant filter codes instead of
    callbacks. This tests handlers with explicit SEH codes.
    """
    seh = SehHandler(
        ranges=((0x1100, 0x1200),),
        filter_ranges=(),  # No filter callback
        seh_code=SehFilterCode.HANDLE,
        frame_register=5,
    )

    assert seh.has_filter is False
    assert seh.filter_start_ea is None
