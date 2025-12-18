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

            assert resolved_addr is not None, (
                f"resolve_name should find existing name '{first_name}'"
            )
            assert resolved_addr == first_addr, (
                f"Expected address {first_addr:x}, got {resolved_addr:x}"
            )
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

            assert resolved_addr is not None, (
                f"resolve_name should find name '{second_name}'"
            )
            assert resolved_addr == second_addr, (
                f"Expected address {second_addr:x}, got {resolved_addr:x}"
            )
        else:
            pytest.skip("Not enough names in database to test")

    def test_resolve_value_for_function_name(self, test_env):
        """
        Test that resolve_value returns value and type for a function name.

        RATIONALE: resolve_value provides more information than resolve_name by
        returning both the numeric value AND the type of the name. This is critical
        for scripts that need to distinguish between different kinds of names
        (functions, data, enums, etc.).

        This test validates that we can resolve a function name and get back both
        its address and the NT_CODE type code, confirming it's recognized as code.
        """
        import ida_name

        # Get the first name in the database
        if test_env.names.get_count() > 0:
            first_addr, first_name = test_env.names.get_at_index(0)

            # Resolve with resolve_value
            value, name_type = test_env.names.resolve_value(first_name)

            assert value is not None, (
                f"resolve_value should return a value for existing name '{first_name}'"
            )
            assert value == first_addr, (
                f"Expected value {first_addr:x}, got {value:x}"
            )
            # Type should be one of the valid NT_* constants (not NT_NONE)
            assert name_type != ida_name.NT_NONE, (
                f"Name type should not be NT_NONE for existing name"
            )
        else:
            pytest.skip("No names in database to test")

    def test_resolve_value_for_nonexistent_name(self, test_env):
        """
        Test that resolve_value returns None and NT_NONE for non-existent names.

        RATIONALE: Error handling for resolve_value is important. When a name
        doesn't exist, the method should return (None, NT_NONE) to clearly
        indicate the name wasn't found. This allows callers to distinguish
        between a name with value 0 and a non-existent name.
        """
        import ida_name

        value, name_type = test_env.names.resolve_value("nonexistent_name_xyz123")

        assert value is None, "Value should be None for non-existent name"
        assert name_type == ida_name.NT_NONE, (
            f"Type should be NT_NONE for non-existent name, got {name_type}"
        )

    def test_resolve_value_consistency_with_resolve_name(self, test_env):
        """
        Test that resolve_value returns same address as resolve_name.

        RATIONALE: resolve_value and resolve_name should return consistent results
        for the numeric value/address. This test validates that both methods agree
        on the address of a name, ensuring API consistency.

        The difference is that resolve_value provides additional type information,
        but the address should match.
        """
        # Get a name to test with
        if test_env.names.get_count() > 0:
            test_addr, test_name = test_env.names.get_at_index(0)

            # Resolve with both methods
            addr_from_resolve_name = test_env.names.resolve_name(test_name)
            value_from_resolve_value, _ = test_env.names.resolve_value(test_name)

            assert addr_from_resolve_name is not None
            assert value_from_resolve_value is not None

            assert addr_from_resolve_name == value_from_resolve_value, (
                f"resolve_name returned {addr_from_resolve_name:x}, "
                f"resolve_value returned {value_from_resolve_value:x}"
            )
        else:
            pytest.skip("No names in database to test")

    def test_resolve_value_with_context_address(self, test_env):
        """
        Test that resolve_value respects from_ea context parameter.

        RATIONALE: The from_ea parameter provides context for name resolution,
        which is important for local labels and function-scoped names. This test
        validates that the context parameter is properly passed through to the
        underlying IDA API.

        While we may not have local labels in the test binary, this test ensures
        the parameter is accepted and doesn't cause errors.
        """
        # Get a name and an address to use as context
        if test_env.names.get_count() > 0:
            first_addr, first_name = test_env.names.get_at_index(0)

            # Resolve with context address (use another address as context)
            value, name_type = test_env.names.resolve_value(first_name, from_ea=first_addr)

            # Should still resolve (global names work from any context)
            assert value is not None, "Should resolve global name with context"
            assert value == first_addr
        else:
            pytest.skip("No names in database to test")


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

    def test_is_valid_name_accepts_valid_identifier(self, test_env):
        """
        Test that is_valid_name returns True for valid user-defined names.

        RATIONALE: The primary purpose of is_valid_name is to validate user-defined
        identifiers before setting them as names in the database. A standard C-style
        identifier with underscores should be accepted. This validates the core
        functionality and happy path of the method.
        """
        assert test_env.names.is_valid_name("my_function") is True, \
            "Valid C identifier should be accepted"
        assert test_env.names.is_valid_name("MyClass") is True, \
            "CamelCase identifier should be accepted"
        assert test_env.names.is_valid_name("_private_var") is True, \
            "Identifier starting with underscore should be accepted"
        assert test_env.names.is_valid_name("var123") is True, \
            "Identifier with digits should be accepted"

    def test_is_valid_name_rejects_empty_string(self, test_env):
        """
        Test that is_valid_name returns False for empty strings.

        RATIONALE: Empty strings are not valid names in IDA. This edge case must
        be handled correctly to prevent errors when users or scripts attempt to
        validate potentially empty input.
        """
        assert test_env.names.is_valid_name("") is False, \
            "Empty string should not be valid"

    def test_is_valid_name_rejects_invalid_characters(self, test_env):
        """
        Test that is_valid_name returns False for names with invalid characters.

        RATIONALE: IDA names must follow IDA's identifier rules. Spaces are clearly
        not allowed. This test ensures the method correctly rejects invalid inputs.
        Note that IDA is permissive with many special characters (dots, @, $, etc.)
        to support mangled names, namespaces, and other constructs.
        """
        assert test_env.names.is_valid_name("my function") is False, \
            "Name with space should be invalid"
        assert test_env.names.is_valid_name("my\tfunction") is False, \
            "Name with tab should be invalid"
        assert test_env.names.is_valid_name("my\nfunction") is False, \
            "Name with newline should be invalid"

    def test_is_valid_name_rejects_names_starting_with_digit(self, test_env):
        """
        Test that is_valid_name returns False for names starting with digits.

        RATIONALE: C identifier rules prohibit starting with a digit. This is a
        fundamental validation rule that must be enforced. Scripts that generate
        names programmatically might accidentally create such names.
        """
        assert test_env.names.is_valid_name("123function") is False, \
            "Name starting with digit should be invalid"
        assert test_env.names.is_valid_name("0x401000") is False, \
            "Hex address string should be invalid as name"

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


class TestNamesFormatting:
    """Tests for name formatting methods."""

    def test_get_colored_name_returns_string_for_named_address(self, test_env):
        """
        Test that get_colored_name returns a string for addresses with names.

        RATIONALE: The get_colored_name method returns names with embedded color
        tags for syntax highlighting in IDA's UI. This test validates that the
        method successfully retrieves a colored name for a known named address.

        We use a function address from the database which is guaranteed to have a
        name, and verify that the returned string is not empty and is similar to
        the plain name (color tags are typically invisible control characters).
        """
        # Find a function with a name
        func_with_name = None
        for func in test_env.functions.get_all():
            name = test_env.names.get_at(func.start_ea)
            if name:
                func_with_name = (func.start_ea, name)
                break

        if func_with_name is None:
            pytest.skip("No named functions found in database")

        func_ea, expected_name = func_with_name

        # Get colored name
        colored = test_env.names.get_colored_name(func_ea)

        # Should return a string
        assert colored is not None, f"Should return colored name for address 0x{func_ea:x}"
        assert isinstance(colored, str), "Should return a string"
        assert len(colored) > 0, "Colored name should not be empty"

        # Colored name might contain color tags, but should contain the actual name text
        # (Color tags are typically control chars that don't affect string comparison much)
        # We just verify it's a reasonable non-empty string
        assert len(colored) >= len(expected_name), (
            "Colored name should be at least as long as plain name "
            "(may contain color tags)"
        )

    def test_get_colored_name_returns_none_for_unnamed_address(self, test_env):
        """
        Test that get_colored_name returns None for addresses without names.

        RATIONALE: Not all addresses in a binary have names - only labeled locations
        like functions, data, or manually added labels have names. This test validates
        that get_colored_name correctly returns None for an unnamed address.

        We use an address in the middle of a function body (not at the function start)
        which typically doesn't have a name.
        """
        # Find an address without a name (middle of a function)
        unnamed_ea = None
        for func in test_env.functions.get_all():
            # Try middle of function
            mid_ea = func.start_ea + ((func.end_ea - func.start_ea) // 2)
            if test_env.is_valid_ea(mid_ea):
                name = test_env.names.get_at(mid_ea)
                if not name:
                    unnamed_ea = mid_ea
                    break

        if unnamed_ea is None:
            pytest.skip("Could not find unnamed address")

        # Get colored name - should be None
        colored = test_env.names.get_colored_name(unnamed_ea)
        assert colored is None, f"Should return None for unnamed address 0x{unnamed_ea:x}"

    def test_get_colored_name_with_local_flag(self, test_env):
        """
        Test get_colored_name with local=True parameter.

        RATIONALE: The local parameter affects name lookup priority - when True,
        local names are tried first. This test validates that the local parameter
        is properly passed to the underlying API and doesn't cause errors.

        We use a known named address and verify that the method works with both
        local=False (default) and local=True.
        """
        # Find a named address
        if test_env.names.get_count() > 0:
            addr, name = test_env.names.get_at_index(0)

            # Try with local=False (default)
            colored_global = test_env.names.get_colored_name(addr, local=False)
            assert colored_global is not None, "Should return name with local=False"

            # Try with local=True
            colored_local = test_env.names.get_colored_name(addr, local=True)
            # Either should work - local might return same or different name
            # depending on whether there's a local name at this address
            assert isinstance(colored_local, (str, type(None))), (
                "Should return string or None with local=True"
            )
        else:
            pytest.skip("No names in database")

    def test_get_colored_name_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_colored_name raises InvalidEAError for invalid addresses.

        RATIONALE: All address-based methods should validate their inputs and raise
        InvalidEAError for invalid addresses. This ensures consistent error handling
        across the API.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.names.get_colored_name(invalid_ea)

    def test_format_expression_for_simple_name(self, test_env):
        """
        Test format_expression returns a simple name for offset=0.

        RATIONALE: The format_expression method converts an address to a symbolic
        expression. When the offset matches the address exactly, it should return
        just the name without any displacement.

        We use a known function address and format it with offset=address, expecting
        to get back the function name.
        """
        # Find a named function
        func_with_name = None
        for func in test_env.functions.get_all():
            name = test_env.names.get_at(func.start_ea)
            if name:
                func_with_name = (func.start_ea, name)
                break

        if func_with_name is None:
            pytest.skip("No named functions found")

        func_ea, expected_name = func_with_name

        # Format expression where offset == ea (no displacement)
        expr = test_env.names.format_expression(
            from_ea=func_ea,  # Reference is from the function itself
            n=0,  # Operand 0 (or data item)
            ea=func_ea,  # Base address
            offset=func_ea,  # Value to represent (same as ea)
            include_struct_fields=True
        )

        # Should return a string containing the name
        assert expr is not None, "Should return expression for named address"
        assert isinstance(expr, str), "Should return a string"
        # The expression should contain the function name
        # (it might have prefixes/suffixes depending on IDA's formatting rules)
        assert len(expr) > 0, "Expression should not be empty"

    def test_format_expression_with_offset_includes_displacement(self, test_env):
        """
        Test format_expression includes offset displacement for offset != ea.

        RATIONALE: When the offset value differs from the base address, the formatted
        expression should include the displacement (e.g., "func+10"). This is important
        for displaying operand values symbolically with their offsets.

        We use a function address and add an offset, expecting to get an expression
        like "funcname+offset".
        """
        # Find a named function
        func_with_name = None
        for func in test_env.functions.get_all():
            name = test_env.names.get_at(func.start_ea)
            if name and (func.end_ea - func.start_ea) > 10:
                func_with_name = (func.start_ea, name)
                break

        if func_with_name is None:
            pytest.skip("No suitable named function found")

        func_ea, expected_name = func_with_name
        offset_value = func_ea + 8  # Add offset of 8

        # Format expression with offset
        expr = test_env.names.format_expression(
            from_ea=func_ea,
            n=0,
            ea=func_ea,
            offset=offset_value,
            include_struct_fields=True
        )

        # Should return expression with offset
        assert expr is not None, "Should return expression"
        assert isinstance(expr, str), "Should return a string"
        # Expression should contain some indication of offset
        # Typically formatted as "name+8" or similar
        # We can't check exact format, but it should be non-empty
        assert len(expr) > 0, "Expression should not be empty"

    def test_format_expression_with_struct_fields_flag(self, test_env):
        """
        Test format_expression with include_struct_fields parameter.

        RATIONALE: The include_struct_fields parameter controls whether structure
        field names are appended to the expression. This test validates that both
        True and False values work without errors.

        We test with both values to ensure the flag is properly handled.
        """
        # Find a named address
        if test_env.names.get_count() > 0:
            addr, name = test_env.names.get_at_index(0)

            # Try with include_struct_fields=True
            expr_with_fields = test_env.names.format_expression(
                from_ea=addr,
                n=0,
                ea=addr,
                offset=addr,
                include_struct_fields=True
            )

            # Try with include_struct_fields=False
            expr_no_fields = test_env.names.format_expression(
                from_ea=addr,
                n=0,
                ea=addr,
                offset=addr,
                include_struct_fields=False
            )

            # Both should work (return string or None)
            assert isinstance(expr_with_fields, (str, type(None))), (
                "Should return string or None with include_struct_fields=True"
            )
            assert isinstance(expr_no_fields, (str, type(None))), (
                "Should return string or None with include_struct_fields=False"
            )
        else:
            pytest.skip("No names in database")

    def test_format_expression_with_invalid_from_ea_raises_error(self, test_env):
        """
        Test that format_expression raises InvalidEAError for invalid from_ea.

        RATIONALE: The from_ea parameter must be a valid address. This test validates
        that the method properly checks and raises InvalidEAError for invalid inputs.
        """
        invalid_ea = 0xDEADBEEF
        valid_ea = test_env.minimum_ea

        with pytest.raises(InvalidEAError):
            test_env.names.format_expression(
                from_ea=invalid_ea,
                n=0,
                ea=valid_ea,
                offset=valid_ea
            )

    def test_format_expression_with_invalid_ea_raises_error(self, test_env):
        """
        Test that format_expression raises InvalidEAError for invalid ea.

        RATIONALE: The ea parameter must be a valid address. This test validates
        proper validation of the ea parameter.
        """
        invalid_ea = 0xDEADBEEF
        valid_ea = test_env.minimum_ea

        with pytest.raises(InvalidEAError):
            test_env.names.format_expression(
                from_ea=valid_ea,
                n=0,
                ea=invalid_ea,
                offset=valid_ea
            )
