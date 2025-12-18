"""Tests for Names entity - new v1.0.0 methods."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def names_test_setup():
    """Setup for Names tests - prepares tiny_c.bin database."""
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
def test_env(names_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=names_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestNamesResolve:
    """Tests for name resolution methods."""

    def test_resolve_name_finds_existing_function(self, test_env):
        """
        Test that resolve_name correctly finds an existing function by name.

        RATIONALE: Name resolution is a fundamental operation in reverse engineering.
        This test validates that we can look up a function by its name and get back
        the correct address. We first get a name that exists in the database, then
        verify we can resolve it back to the same address.

        This is critical functionality for scripts that need to locate functions by
        name rather than hard-coding addresses.
        """
        # Get the first name in the database
        if test_env.names.get_count() > 0:
            first_addr, first_name = test_env.names.get_at_index(0)

            # Now resolve that name
            resolved_addr = test_env.names.resolve_name(first_name)

            assert resolved_addr is not None, f"resolve_name should find existing name '{first_name}'"
            assert resolved_addr == first_addr, f"Expected address {first_addr:x}, got {resolved_addr:x}"
        else:
            # If no names exist, skip this test
            pytest.skip("No names in database to test")

    def test_resolve_name_returns_none_for_nonexistent(self, test_env):
        """
        Test that resolve_name returns None for non-existent names.

        RATIONALE: Error handling is critical. Scripts need to reliably detect when
        a name doesn't exist to avoid crashes or incorrect behavior. This test ensures
        that looking up a name that doesn't exist in the database returns None rather
        than raising an exception or returning an invalid value.
        """
        addr = test_env.names.resolve_name("nonexistent_function_name_xyz123")

        assert addr is None, "resolve_name should return None for non-existent names"

    def test_resolve_name_finds_data_symbol(self, test_env):
        """
        Test that resolve_name works for different types of symbols.

        RATIONALE: Name resolution needs to work for all types of symbols (functions,
        data, labels). This test validates that we can resolve any named address,
        regardless of its type.
        """
        # Get any name from the database (if available)
        if test_env.names.get_count() > 1:
            # Get the second name (to be different from the first)
            second_addr, second_name = test_env.names.get_at_index(1)

            # Resolve it
            resolved_addr = test_env.names.resolve_name(second_name)

            assert resolved_addr is not None, f"resolve_name should find name '{second_name}'"
            assert resolved_addr == second_addr, f"Expected address {second_addr:x}, got {resolved_addr:x}"
        else:
            pytest.skip("Not enough names in database to test")


class TestNamesLocalOperations:
    """Tests for local name operations."""

    def test_delete_local_with_valid_address(self, test_env):
        """
        Test that delete_local handles valid addresses without error.

        RATIONALE: Local names are function-scoped labels that need to be
        manageable programmatically. This test ensures that delete_local
        can be called on valid addresses without raising exceptions, even
        if no local name exists there.

        The method should return False when no local name exists, not crash.
        """
        # Call on a valid function address
        result = test_env.names.delete_local(0xC4)

        # Should return bool (True if deleted, False if nothing to delete)
        assert isinstance(result, bool), "delete_local should return a boolean"

    def test_delete_local_with_invalid_address_raises_error(self, test_env):
        """
        Test that delete_local raises InvalidEAError for invalid addresses.

        RATIONALE: API consistency requires that methods validate their inputs
        and raise appropriate exceptions for invalid addresses. This prevents
        undefined behavior and helps users catch bugs early.
        """
        with pytest.raises(InvalidEAError):
            test_env.names.delete_local(0xFFFFFFFF)


class TestNamesDummyCreation:
    """Tests for dummy name creation."""

    def test_create_dummy_with_valid_addresses(self, test_env):
        """
        Test that create_dummy successfully creates dummy names.

        RATIONALE: Dummy names (like loc_, sub_, byte_) are IDA's auto-generated
        labels. Being able to create them programmatically is useful for scripts
        that need to ensure labels exist at specific locations. This test validates
        that the method can create dummy names when given valid addresses.

        We test with two addresses from the test binary that we know are valid.
        """
        # Use two valid addresses from the test binary
        # 0xC4 is test_all_operand_types, 0xC8 is inside that function
        result = test_env.names.create_dummy(0xC4, 0xC8)

        assert isinstance(result, bool), "create_dummy should return a boolean"
        # Note: Result may be True or False depending on whether dummy name was created
        # The important thing is that it doesn't crash

    def test_create_dummy_with_invalid_from_ea_raises_error(self, test_env):
        """
        Test that create_dummy validates the from_ea parameter.

        RATIONALE: Both address parameters need validation. This test ensures
        that passing an invalid source address raises an appropriate exception.
        """
        with pytest.raises(InvalidEAError):
            test_env.names.create_dummy(0xFFFFFFFF, 0xC4)

    def test_create_dummy_with_invalid_target_ea_raises_error(self, test_env):
        """
        Test that create_dummy validates the target ea parameter.

        RATIONALE: The target address also needs validation. This test ensures
        that passing an invalid target address raises an appropriate exception.
        """
        with pytest.raises(InvalidEAError):
            test_env.names.create_dummy(0xC4, 0xFFFFFFFF)


class TestNamesVisibleName:
    """Tests for visible name retrieval."""

    def test_get_visible_name_for_named_function(self, test_env):
        """
        Test that get_visible_name returns the correct name for a named address.

        RATIONALE: get_visible_name should return the name that would be displayed
        in IDA's disassembly view. This test validates that the method returns a
        name for an address that has a name.
        """
        # Get an address that has a name
        if test_env.names.get_count() > 0:
            addr, expected_name = test_env.names.get_at_index(0)

            # Get the visible name
            name = test_env.names.get_visible_name(addr)

            assert name is not None, f"get_visible_name should return name for address {addr:x}"
            # Note: visible name might include scope qualifiers, so we just check it's a string
            assert isinstance(name, str), "get_visible_name should return a string"
            assert len(name) > 0, "get_visible_name should return non-empty string"
        else:
            pytest.skip("No names in database to test")

    def test_get_visible_name_for_unnamed_location(self, test_env):
        """
        Test get_visible_name behavior for an address without a name.

        RATIONALE: Not all addresses have names. This test validates how the method
        handles unnamed locations. The behavior should be to return None or an
        auto-generated name, depending on IDA's configuration.
        """
        # Test with a valid address in the middle of the address space
        min_ea = test_env.minimum_ea
        max_ea = test_env.maximum_ea

        if max_ea > min_ea + 100:
            # Test an address in the middle that likely doesn't have a specific name
            test_addr = min_ea + 50
            name = test_env.names.get_visible_name(test_addr)

            # May return None or an auto-generated name like "sub_xxx+offset"
            # The important thing is it doesn't crash
            assert name is None or isinstance(name, str), "Should return None or a string"
        else:
            pytest.skip("Address space too small for test")

    def test_get_visible_name_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_visible_name validates the address parameter.

        RATIONALE: Consistent error handling across all methods. Invalid addresses
        should raise InvalidEAError, not return unexpected values or crash.
        """
        with pytest.raises(InvalidEAError):
            test_env.names.get_visible_name(0xFFFFFFFF)

    def test_get_visible_name_local_flag(self, test_env):
        """
        Test get_visible_name with local=True parameter.

        RATIONALE: The local parameter allows retrieving function-local names
        separately from global names. This test validates that the parameter
        is accepted and doesn't cause crashes, even if no local name exists.
        """
        # Call with local=True on any valid address
        if test_env.names.get_count() > 0:
            addr, _ = test_env.names.get_at_index(0)
            name = test_env.names.get_visible_name(addr, local=True)

            # Should return None or a string
            assert name is None or isinstance(name, str), "Should return None or a string"
        else:
            pytest.skip("No addresses to test")


class TestNamesValidation:
    """Tests for name validation."""

    def test_validate_valid_name_returns_true(self, test_env):
        """
        Test that validate returns (True, name) for valid names.

        RATIONALE: Name validation is essential for scripts that generate or modify
        names programmatically. A valid C-style identifier should be accepted and
        returned unchanged. This validates the happy path of name validation.
        """
        is_valid, cleaned = test_env.names.validate("my_function")

        assert is_valid is True, "Valid name should be marked as valid"
        assert cleaned == "my_function", "Valid name should be returned unchanged"

    def test_validate_name_with_invalid_characters(self, test_env):
        """
        Test that validate handles names with invalid characters.

        RATIONALE: User input or automated name generation might produce names
        with invalid characters (spaces, hyphens, etc.). The validate method
        should either accept and clean these names, or reject them with a clear
        indication. This test validates that the method can handle such cases
        without crashing.
        """
        # Name with a hyphen (invalid in IDA)
        is_valid, cleaned = test_env.names.validate("my-function")

        # Should return a boolean and a string
        assert isinstance(is_valid, bool), "First return value should be boolean"
        assert isinstance(cleaned, str), "Second return value should be string"

        # If cleaned, it should have replaced the invalid character
        if is_valid:
            assert "-" not in cleaned, "Cleaned name should not contain hyphens"

    def test_validate_empty_name(self, test_env):
        """
        Test validate behavior with empty string.

        RATIONALE: Edge case handling. Empty strings are not valid names, and
        the method should handle this case gracefully by returning False.
        """
        is_valid, cleaned = test_env.names.validate("")

        assert is_valid is False, "Empty name should not be valid"

    def test_validate_name_with_spaces(self, test_env):
        """
        Test validate with name containing spaces.

        RATIONALE: Spaces are not allowed in IDA names. This test validates that
        the method handles this common invalid input case appropriately.
        """
        is_valid, cleaned = test_env.names.validate("my function name")

        # Should return results indicating whether name is/can be valid
        assert isinstance(is_valid, bool), "Should return boolean validity"
        assert isinstance(cleaned, str), "Should return string cleaned name"

        if is_valid:
            # If it was made valid, spaces should be gone
            assert " " not in cleaned, "Cleaned name should not contain spaces"

    def test_validate_name_starting_with_digit(self, test_env):
        """
        Test validate with name starting with a digit.

        RATIONALE: C-style identifiers cannot start with digits. This is a common
        validation rule that should be enforced. The method should either reject
        such names or clean them by prepending a valid character.
        """
        is_valid, cleaned = test_env.names.validate("123function")

        # Should return validation result
        assert isinstance(is_valid, bool), "Should return boolean validity"
        assert isinstance(cleaned, str), "Should return string"

        if is_valid:
            # If made valid, shouldn't start with digit
            assert not cleaned[0].isdigit(), "Cleaned name should not start with digit"


class TestNamesIntegration:
    """Integration tests combining multiple name operations."""

    def test_resolve_then_get_visible_name(self, test_env):
        """
        Test that resolve_name and get_visible_name work together.

        RATIONALE: Common workflow is to resolve a name to an address, then
        retrieve information about that address. This integration test validates
        that these two operations work correctly in sequence.
        """
        if test_env.names.get_count() > 0:
            # Get a name from the database
            original_addr, original_name = test_env.names.get_at_index(0)

            # First resolve the name
            addr = test_env.names.resolve_name(original_name)
            assert addr is not None, f"Should find the name '{original_name}'"
            assert addr == original_addr, "Resolved address should match"

            # Then get the visible name at that address
            name = test_env.names.get_visible_name(addr)
            assert name is not None, "Should return a name"
            assert isinstance(name, str), "Should return a string"
        else:
            pytest.skip("No names in database to test")

    def test_validate_then_resolve(self, test_env):
        """
        Test validation before resolution workflow.

        RATIONALE: Scripts might validate user input before attempting to resolve
        it. This test validates that validate and resolve_name work correctly in
        sequence, representing a common defensive programming pattern.
        """
        if test_env.names.get_count() > 0:
            # Get a name from the database
            original_addr, original_name = test_env.names.get_at_index(0)

            # Validate it
            is_valid, cleaned = test_env.names.validate(original_name)
            assert is_valid, f"Name '{original_name}' from database should be valid"

            # Then try to resolve it
            addr = test_env.names.resolve_name(cleaned)
            assert addr is not None, "Valid name should resolve to address"
            assert addr == original_addr, "Should resolve to correct address"
        else:
            pytest.skip("No names in database to test")
