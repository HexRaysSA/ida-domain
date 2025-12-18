"""Tests for Bytes entity - item navigation methods."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def bytes_test_setup():
    """Setup for Bytes tests - prepares tiny_c.bin database."""
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_c.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy tiny_c.bin from test resources
    import shutil
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')
    shutil.copy2(src_path, idb_path)

    yield idb_path

    # Cleanup is handled by temp directory


@pytest.fixture(scope='function')
def test_env(bytes_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=bytes_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestBytesItemNavigation:
    """Tests for item navigation methods (get_item_head_at, get_item_end_at, get_item_size_at)."""

    def test_get_item_head_at_on_head_returns_same_address(self, test_env):
        """
        Test that get_item_head_at returns the same address when called on a head.

        RATIONALE: When analyzing binary data, items (instructions or data) start at
        "head" addresses. If you query the head of an item that is already at its
        head, you should get the same address back. This is a fundamental property
        of item navigation that ensures idempotent behavior.

        This test validates that calling get_item_head_at on an address that is
        already a head (start of an item) returns that same address without
        searching backwards.
        """
        # Get the first valid head in the database
        first_head = test_env.bytes.get_next_head(test_env.minimum_ea)
        assert first_head is not None, "Should have at least one head in database"

        # Calling get_item_head_at on a head should return the same address
        head = test_env.bytes.get_item_head_at(first_head)
        assert head == first_head, (
            f"get_item_head_at should return same address for a head: "
            f"expected 0x{first_head:x}, got 0x{head:x}"
        )

    def test_get_item_head_at_on_tail_finds_head(self, test_env):
        """
        Test that get_item_head_at correctly finds the head when called on a tail byte.

        RATIONALE: Multi-byte items (like dwords, qwords, or multi-byte instructions)
        have a "head" (first byte) and "tail" bytes (remaining bytes). When reverse
        engineering, you often need to find the start of an item given any address
        within it. This is crucial for operations like disassembly, data formatting,
        and cross-reference analysis.

        This test creates a multi-byte data item (dword = 4 bytes) and verifies that
        calling get_item_head_at on any byte within the item (including tail bytes)
        correctly returns the address of the head.
        """
        # Find a location with enough space to create a dword
        test_addr = test_env.minimum_ea + 0x100

        # Ensure we're at a valid location
        if not test_env.is_valid_ea(test_addr):
            pytest.skip("Test address not mapped in database")

        # Create a dword (4 bytes) at test_addr
        success = test_env.bytes.create_dword_at(test_addr, count=1, force=True)
        if not success:
            pytest.skip("Could not create dword at test address")

        # The head should be at test_addr
        head = test_env.bytes.get_item_head_at(test_addr)
        assert head == test_addr, f"Expected head at 0x{test_addr:x}, got 0x{head:x}"

        # Check tail bytes (bytes 1, 2, 3 of the dword)
        for offset in [1, 2, 3]:
            tail_addr = test_addr + offset
            head_of_tail = test_env.bytes.get_item_head_at(tail_addr)
            assert head_of_tail == test_addr, (
                f"get_item_head_at on tail byte at offset {offset} should return "
                f"head address 0x{test_addr:x}, got 0x{head_of_tail:x}"
            )

    def test_get_item_end_at_returns_exclusive_end(self, test_env):
        """
        Test that get_item_end_at returns the exclusive end address of an item.

        RATIONALE: When processing items in a binary, you need to know where each
        item ends to iterate through them sequentially or to extract data ranges.
        The end address is "exclusive" (points to the first byte AFTER the item),
        which follows Python convention and makes range calculations straightforward.

        This test verifies that get_item_end_at returns the correct exclusive end
        address, and that (end - head) equals the item size.
        """
        # Get the first valid head
        first_head = test_env.bytes.get_next_head(test_env.minimum_ea)
        assert first_head is not None, "Should have at least one head in database"

        # Get the end address
        end = test_env.bytes.get_item_end_at(first_head)

        # End should be greater than head
        assert end > first_head, (
            f"Item end 0x{end:x} should be greater than head 0x{first_head:x}"
        )

        # Get item size and verify consistency
        size = test_env.bytes.get_item_size_at(first_head)
        assert end - first_head == size, (
            f"Item size should equal end - head: "
            f"end=0x{end:x}, head=0x{first_head:x}, "
            f"end-head={end-first_head}, size={size}"
        )

    def test_get_item_size_at_returns_correct_size(self, test_env):
        """
        Test that get_item_size_at returns the correct size for various item types.

        RATIONALE: Different data types have different sizes (byte=1, word=2, dword=4,
        qword=8). Instructions also have varying sizes. Knowing the exact size of an
        item is essential for memory analysis, data extraction, and navigation.

        This test creates items of known sizes and verifies that get_item_size_at
        returns the expected size for each type.
        """
        # Find a suitable test location
        test_base = test_env.minimum_ea + 0x200

        if not test_env.is_valid_ea(test_base):
            pytest.skip("Test address range not mapped in database")

        # Test different data types with known sizes
        test_cases = [
            ('byte', 1, lambda addr: test_env.bytes.create_byte_at(addr, count=1, force=True)),
            ('word', 2, lambda addr: test_env.bytes.create_word_at(addr, count=1, force=True)),
            ('dword', 4, lambda addr: test_env.bytes.create_dword_at(addr, count=1, force=True)),
            ('qword', 8, lambda addr: test_env.bytes.create_qword_at(addr, count=1, force=True)),
        ]

        offset = 0
        for type_name, expected_size, create_func in test_cases:
            test_addr = test_base + offset

            # Create the data item
            success = create_func(test_addr)
            if not success:
                pytest.skip(f"Could not create {type_name} at 0x{test_addr:x}")

            # Verify size
            actual_size = test_env.bytes.get_item_size_at(test_addr)
            assert actual_size == expected_size, (
                f"Size of {type_name} should be {expected_size}, got {actual_size}"
            )

            # Move to next test location (with some padding)
            offset += expected_size + 8

    def test_get_item_head_at_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_item_head_at raises InvalidEAError for invalid addresses.

        RATIONALE: Robust error handling is critical for preventing crashes and
        providing clear feedback when invalid inputs are provided. An address outside
        the valid database range should raise a specific exception rather than
        returning incorrect data or causing undefined behavior.

        This test validates that the API properly validates input addresses and
        raises the appropriate exception for out-of-range addresses.
        """
        invalid_addr = 0xFFFFFFFFFFFFFFFF  # Address outside valid range

        with pytest.raises(InvalidEAError):
            test_env.bytes.get_item_head_at(invalid_addr)

    def test_get_item_end_at_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_item_end_at raises InvalidEAError for invalid addresses.

        RATIONALE: Consistent error handling across all methods ensures predictable
        API behavior. Just like get_item_head_at, get_item_end_at should validate
        its input and raise InvalidEAError for addresses outside the valid range.
        """
        invalid_addr = 0xFFFFFFFFFFFFFFFF  # Address outside valid range

        with pytest.raises(InvalidEAError):
            test_env.bytes.get_item_end_at(invalid_addr)

    def test_get_item_size_at_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_item_size_at raises InvalidEAError for invalid addresses.

        RATIONALE: Consistent error handling ensures that all three item navigation
        methods behave predictably. An invalid address should always raise
        InvalidEAError, making error handling in client code straightforward.
        """
        invalid_addr = 0xFFFFFFFFFFFFFFFF  # Address outside valid range

        with pytest.raises(InvalidEAError):
            test_env.bytes.get_item_size_at(invalid_addr)

    def test_item_navigation_consistency(self, test_env):
        """
        Test that all three item navigation methods are mutually consistent.

        RATIONALE: The three methods (get_item_head_at, get_item_end_at,
        get_item_size_at) should provide consistent information about items.
        Specifically:
        - get_item_size_at(ea) should equal get_item_end_at(ea) - get_item_head_at(ea)
        - All three methods should return the same information whether called on
          the head or on a tail byte of the same item

        This test validates the mathematical relationships between these methods,
        ensuring they form a coherent API for item navigation.
        """
        # Get first head
        first_head = test_env.bytes.get_next_head(test_env.minimum_ea)
        assert first_head is not None, "Should have at least one head in database"

        # Get all three values
        head = test_env.bytes.get_item_head_at(first_head)
        end = test_env.bytes.get_item_end_at(first_head)
        size = test_env.bytes.get_item_size_at(first_head)

        # Verify consistency: size = end - head
        assert size == end - head, (
            f"Item navigation inconsistency: size={size}, but end-head={end-head}"
        )

        # If item has multiple bytes, verify tail byte returns same info
        if size > 1:
            tail_addr = first_head + 1  # First tail byte

            tail_head = test_env.bytes.get_item_head_at(tail_addr)
            tail_end = test_env.bytes.get_item_end_at(tail_addr)
            tail_size = test_env.bytes.get_item_size_at(tail_addr)

            assert tail_head == head, (
                f"get_item_head_at should return same head for tail byte: "
                f"expected 0x{head:x}, got 0x{tail_head:x}"
            )
            assert tail_end == end, (
                f"get_item_end_at should return same end for tail byte: "
                f"expected 0x{end:x}, got 0x{tail_end:x}"
            )
            assert tail_size == size, (
                f"get_item_size_at should return same size for tail byte: "
                f"expected {size}, got {tail_size}"
            )

    def test_iterating_items_with_navigation_methods(self, test_env):
        """
        Test using item navigation methods to iterate through consecutive items.

        RATIONALE: A common reverse engineering pattern is to iterate through all
        items in a range, processing each one. The item navigation methods should
        enable this pattern efficiently. This test validates that you can:
        1. Start at an address
        2. Get the item boundaries (head, end, size)
        3. Move to the next item (end of current = start of search for next)
        4. Repeat until no more items

        This is a realistic use case that exercises all three methods together.
        """
        # Start at minimum address
        current_ea = test_env.minimum_ea
        items_found = 0
        max_items = 10  # Limit iterations to avoid long-running tests

        while items_found < max_items and current_ea < test_env.maximum_ea:
            # Get next head
            head = test_env.bytes.get_next_head(current_ea)
            if head is None:
                break

            # Get item boundaries
            item_head = test_env.bytes.get_item_head_at(head)
            item_end = test_env.bytes.get_item_end_at(head)
            item_size = test_env.bytes.get_item_size_at(head)

            # Verify consistency
            assert item_head == head, "Head should be at returned next_head address"
            assert item_size == item_end - item_head, "Size should equal end - head"
            assert item_size > 0, "Item size must be positive"

            # Move to next item (exclusive end is start of search range)
            current_ea = item_end
            items_found += 1

        # Should have found at least a few items
        assert items_found > 0, "Should have found at least one item in database"
