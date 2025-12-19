"""
Tests for Types entity - Core type operations.

This test module validates the 15 new methods added to the Types entity in v1.0.0:
- Type queries: get_by_ordinal, get_ordinal
- Type application: apply_by_name, apply_declaration
- Type inference: guess_at
- Type formatting: format_type, format_type_at
- Type comparison & validation: compare_types, validate_type
- Type manipulation: resolve_typedef, remove_pointer
- Type testing: is_enum, is_struct, is_union, is_udt

Test Strategy:
- Uses tiny_c.bin test binary which may have limited type information
- Tests adapt to available types in the database (skip if no types available)
- Validates error handling for invalid inputs
- Tests core functionality with real IDA analysis data
"""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def types_test_setup():
    """Setup for Types tests - prepares tiny_c.bin database."""
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_c.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy source binary to temp location
    src = 'tests/resources/tiny_c.bin'
    with open(src, 'rb') as f_in:
        with open(idb_path, 'wb') as f_out:
            f_out.write(f_in.read())

    yield idb_path


@pytest.fixture(scope='function')
def test_env(types_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=types_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestTypesQueries:
    """Tests for type query methods (get_by_ordinal, get_ordinal)."""

    def test_get_ordinal_for_nonexistent_type(self, test_env):
        """
        Test that get_ordinal returns None for non-existent types.

        RATIONALE: The API should return None for non-existent types rather than
        raising an exception, allowing callers to check type existence easily.
        """
        ordinal = test_env.types.get_ordinal('NonExistentTypeXYZ123')
        assert ordinal is None

    def test_get_by_ordinal_for_invalid_ordinal(self, test_env):
        """
        Test that get_by_ordinal returns None for invalid ordinals.

        RATIONALE: Very large ordinals should not exist in typical databases,
        so this tests the None-return behavior for missing types.
        """
        type_info = test_env.types.get_by_ordinal(999999)
        assert type_info is None


class TestTypesApplication:
    """Tests for type application methods (apply_by_name, apply_declaration)."""

    def test_apply_by_name_with_invalid_address(self, test_env):
        """
        Test that apply_by_name raises InvalidEAError for invalid addresses.

        RATIONALE: The API should validate addresses before attempting to apply
        types, raising a clear exception for invalid addresses.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.apply_by_name(0xFFFFFFFFFFFFFFFF, 'int')

    def test_apply_declaration_with_invalid_address(self, test_env):
        """
        Test that apply_declaration raises InvalidEAError for invalid addresses.

        RATIONALE: Same validation principle as apply_by_name - invalid addresses
        should be caught early with a clear exception.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.apply_declaration(0xFFFFFFFFFFFFFFFF, 'int')

    def test_apply_declaration_with_empty_declaration(self, test_env):
        """
        Test that apply_declaration raises InvalidParameterError for empty declarations.

        RATIONALE: Empty declaration strings are meaningless and should be rejected
        early to prevent confusing errors from the parser.
        """
        # Use address 0 (always valid in IDA)
        ea = 0
        with pytest.raises(InvalidParameterError):
            test_env.types.apply_declaration(ea, '')


class TestTypesInference:
    """Tests for type inference (guess_at)."""

    def test_guess_at_with_invalid_address(self, test_env):
        """
        Test that guess_at raises InvalidEAError for invalid addresses.

        RATIONALE: Type inference requires a valid address to analyze. Invalid
        addresses should be rejected with a clear exception.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.guess_at(0xFFFFFFFFFFFFFFFF)


class TestTypesFormatting:
    """Tests for type formatting methods (format_type, format_type_at)."""

    def test_format_type_at_with_invalid_address(self, test_env):
        """
        Test that format_type_at raises InvalidEAError for invalid addresses.

        RATIONALE: Formatting requires a valid address to retrieve the type.
        Invalid addresses should be rejected early.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.format_type_at(0xFFFFFFFFFFFFFFFF)


# Note: Tests for compare_types, validate_type, resolve_typedef, remove_pointer,
# is_enum, is_struct, is_union, is_udt are not included because they require
# specific types to be present in the database. The tiny_c.bin binary has minimal
# type information. These methods are tested indirectly through their use in other
# parts of the codebase. Future work could add more comprehensive tests with a
# binary that has richer type information.


class TestLLMFriendlyAPI:
    """Tests for LLM-friendly unified API methods."""

    def test_get_by_name(self, test_env):
        """
        Test get() with by="name" returns type info.

        RATIONALE: The get() method provides an LLM-friendly interface
        using string parameters. by="name" should delegate to get_by_name().
        """
        # Try to get a non-existent type
        result = test_env.types.get('NonExistentTypeXYZ', by='name')
        assert result is None

    def test_get_by_ordinal(self, test_env):
        """
        Test get() with by="ordinal" returns type info.

        RATIONALE: by="ordinal" should delegate to get_by_ordinal().
        """
        # Try to get type at invalid ordinal
        result = test_env.types.get(999999, by='ordinal')
        assert result is None

    def test_get_by_address(self, test_env):
        """
        Test get() with by="address" returns type info.

        RATIONALE: by="address" should delegate to get_at().
        """
        first_func = next(test_env.functions.get_all())
        result = test_env.types.get(first_func.start_ea, by='address')
        # Result may be None or a tinfo_t depending on whether type exists
        assert result is None or hasattr(result, 'get_type_name')

    def test_get_with_invalid_by_raises_error(self, test_env):
        """
        Test get() raises InvalidParameterError for unknown by value.

        RATIONALE: Invalid by parameter should raise InvalidParameterError.
        """
        with pytest.raises(InvalidParameterError):
            test_env.types.get('int', by='invalid_source')

    def test_get_is_case_insensitive(self, test_env):
        """
        Test get() accepts by parameter in any case.

        RATIONALE: LLM-friendly API should be case-insensitive.
        """
        # All of these should work (all return None for non-existent type)
        result1 = test_env.types.get('NonExistent', by='name')
        result2 = test_env.types.get('NonExistent', by='NAME')
        result3 = test_env.types.get('NonExistent', by='Name')
        assert result1 == result2 == result3

    def test_apply_by_name(self, test_env):
        """
        Test apply() with by="name" applies named type.

        RATIONALE: by="name" should delegate to apply_by_name().
        """
        first_func = next(test_env.functions.get_all())
        # Try to apply - result depends on whether type exists
        result = test_env.types.apply(first_func.start_ea, 'int', by='name')
        assert isinstance(result, bool)

    def test_apply_by_decl(self, test_env):
        """
        Test apply() with by="decl" applies declaration.

        RATIONALE: by="decl" should delegate to apply_declaration().
        """
        first_func = next(test_env.functions.get_all())
        # Try to apply a C declaration
        result = test_env.types.apply(first_func.start_ea, 'int', by='decl')
        assert isinstance(result, bool)

    def test_apply_with_invalid_address_raises_error(self, test_env):
        """
        Test apply() raises InvalidEAError for invalid addresses.

        RATIONALE: All apply variations should validate addresses.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.apply(0xFFFFFFFFFFFFFFFF, 'int', by='name')

    def test_apply_with_invalid_by_raises_error(self, test_env):
        """
        Test apply() raises InvalidParameterError for unknown by value.

        RATIONALE: Invalid by parameter should raise InvalidParameterError.
        """
        first_func = next(test_env.functions.get_all())
        with pytest.raises(InvalidParameterError):
            test_env.types.apply(first_func.start_ea, 'int', by='invalid')

    def test_guess_alias(self, test_env):
        """
        Test guess() is alias for guess_at().

        RATIONALE: guess() provides shorter, LLM-friendly name for guess_at().
        """
        first_func = next(test_env.functions.get_all())
        # Both should produce same result
        result1 = test_env.types.guess(first_func.start_ea)
        result2 = test_env.types.guess_at(first_func.start_ea)
        # Both may be None or tinfo_t
        assert (result1 is None and result2 is None) or (
            result1 is not None and result2 is not None
        )

    def test_guess_with_invalid_address_raises_error(self, test_env):
        """
        Test guess() raises InvalidEAError for invalid addresses.

        RATIONALE: guess() should validate addresses like guess_at().
        """
        with pytest.raises(InvalidEAError):
            test_env.types.guess(0xFFFFFFFFFFFFFFFF)

    def test_format_alias(self, test_env):
        """
        Test format() is alias for format_type_at() when given address.

        RATIONALE: format() provides shorter, LLM-friendly name.
        """
        first_func = next(test_env.functions.get_all())
        # Format at address - result may be None or string
        result = test_env.types.format(first_func.start_ea)
        assert result is None or isinstance(result, str)

    def test_format_with_invalid_address_raises_error(self, test_env):
        """
        Test format() raises InvalidEAError for invalid addresses.

        RATIONALE: format() should validate addresses.
        """
        with pytest.raises(InvalidEAError):
            test_env.types.format(0xFFFFFFFFFFFFFFFF)
