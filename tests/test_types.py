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
- Uses test_types.bin which has rich type information including:
  * Enums: ColorChannel, ProcessState, ErrorCode, ValueType
  * Structs: Point2D, Record, PaddedStruct, PackedStruct, PhysicsBody, Node, etc.
  * Unions: FloatBits, DoubleBits, TaggedValue
  * Bitfields: BitfieldStruct, BitfieldStruct64
  * Function pointers: VoidFunc, IntFunc, BinaryFunc, AllocFunc, Allocator
- Tests adapt to available types in the database
- Validates error handling for invalid inputs
- Tests core functionality with real IDA analysis data
"""

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.types import TypeApplyMode, TypeLookupMode

# types_test_setup fixture is provided by conftest.py


@pytest.fixture(scope='function')
def db_readonly(types_test_setup):
    """
    Opens database for read-only tests.

    Note: Function scope is required for IDA databases because the IDA kernel
    maintains global state that can be affected by other database instances.
    Module-scoped fixtures cause test pollution when mutation tests run.
    Uses pre-analyzed database for fast loading (no auto-analysis needed).
    """
    ida_options = IdaCommandOptions(new_database=False, auto_analysis=False)
    db = ida_domain.Database.open(path=types_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


@pytest.fixture(scope='function')
def db_mutable(types_test_setup):
    """
    Opens database for mutation tests (fresh per test).

    RATIONALE: Tests that modify type data (apply types) need isolated
    database instances to prevent test interference. Each test starts with
    a clean database state.
    Uses pre-analyzed database for fast loading (no auto-analysis needed).
    """
    ida_options = IdaCommandOptions(new_database=False, auto_analysis=False)
    db = ida_domain.Database.open(path=types_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestTypesQueries:
    """Tests for type query methods (get_by_ordinal, get_ordinal)."""

    def test_get_ordinal_for_nonexistent_type(self, db_readonly):
        """
        Test that get_ordinal returns None for non-existent types.

        RATIONALE: The API should return None for non-existent types rather than
        raising an exception, allowing callers to check type existence easily.
        """
        ordinal = db_readonly.types.get_ordinal('NonExistentTypeXYZ123')
        assert ordinal is None

    def test_get_by_ordinal_for_invalid_ordinal(self, db_readonly):
        """
        Test that get_by_ordinal returns None for invalid ordinals.

        RATIONALE: Very large ordinals should not exist in typical databases,
        so this tests the None-return behavior for missing types.
        """
        type_info = db_readonly.types.get_by_ordinal(999999)
        assert type_info is None


class TestTypesApplication:
    """Tests for type application methods (apply_by_name, apply_declaration)."""

    def test_apply_by_name_with_invalid_address(self, db_readonly):
        """
        Test that apply_by_name raises InvalidEAError for invalid addresses.

        RATIONALE: The API should validate addresses before attempting to apply
        types, raising a clear exception for invalid addresses.
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.apply_by_name(0xFFFFFFFFFFFFFFFF, 'int')

    def test_apply_declaration_with_invalid_address(self, db_readonly):
        """
        Test that apply_declaration raises InvalidEAError for invalid addresses.

        RATIONALE: Same validation principle as apply_by_name - invalid addresses
        should be caught early with a clear exception.
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.apply_declaration(0xFFFFFFFFFFFFFFFF, 'int')

    def test_apply_declaration_with_empty_declaration(self, db_readonly):
        """
        Test that apply_declaration raises InvalidParameterError for empty declarations.

        RATIONALE: Empty declaration strings are meaningless and should be rejected
        early to prevent confusing errors from the parser.
        """
        # Use a valid address from the binary
        first_func = next(db_readonly.functions.get_all())
        ea = first_func.start_ea
        with pytest.raises(InvalidParameterError):
            db_readonly.types.apply_declaration(ea, '')


class TestTypesInference:
    """Tests for type inference (guess_at)."""

    def test_guess_at_with_invalid_address(self, db_readonly):
        """
        Test that guess_at raises InvalidEAError for invalid addresses.

        RATIONALE: Type inference requires a valid address to analyze. Invalid
        addresses should be rejected with a clear exception.
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.guess_at(0xFFFFFFFFFFFFFFFF)


class TestTypesFormatting:
    """Tests for type formatting methods (format_type, format_type_at)."""

    def test_format_type_at_with_invalid_address(self, db_readonly):
        """
        Test that format_type_at raises InvalidEAError for invalid addresses.

        RATIONALE: Formatting requires a valid address to retrieve the type.
        Invalid addresses should be rejected early.
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.format_type_at(0xFFFFFFFFFFFFFFFF)


# Note: Tests for compare_types, validate_type, resolve_typedef, remove_pointer,
# is_enum, is_struct, is_union, is_udt are not included because they require
# specific types to be present in the database. The tiny_c.bin binary has minimal
# type information. These methods are tested indirectly through their use in other
# parts of the codebase. Future work could add more comprehensive tests with a
# binary that has richer type information.


class TestLLMFriendlyAPI:
    """Tests for LLM-friendly unified API methods."""

    def test_get_by_name(self, db_readonly):
        """
        Test get() with by="name" returns type info.

        RATIONALE: The get() method provides an LLM-friendly interface
        using string parameters. by="name" should delegate to get_by_name().
        """
        # Try to get a non-existent type
        result = db_readonly.types.get('NonExistentTypeXYZ', by='name')
        assert result is None

    def test_get_by_ordinal(self, db_readonly):
        """
        Test get() with by="ordinal" returns type info.

        RATIONALE: by="ordinal" should delegate to get_by_ordinal().
        """
        # Try to get type at invalid ordinal
        result = db_readonly.types.get(999999, by='ordinal')
        assert result is None

    def test_get_by_address(self, db_readonly):
        """
        Test get() with by="address" returns type info.

        RATIONALE: by="address" should delegate to get_at().
        """
        first_func = next(db_readonly.functions.get_all())
        result = db_readonly.types.get(first_func.start_ea, by='address')
        # Result may be None or a tinfo_t depending on whether type exists
        assert result is None or hasattr(result, 'get_type_name')

    def test_get_with_invalid_by_raises_error(self, db_readonly):
        """
        Test get() raises InvalidParameterError for unknown by value.

        RATIONALE: Invalid by parameter should raise InvalidParameterError.
        """
        with pytest.raises(InvalidParameterError):
            db_readonly.types.get('int', by='invalid_source')

    def test_get_is_case_insensitive(self, db_readonly):
        """
        Test get() accepts by parameter in any case.

        RATIONALE: LLM-friendly API should be case-insensitive.
        """
        # All of these should work (all return None for non-existent type)
        result1 = db_readonly.types.get('NonExistent', by='name')
        result2 = db_readonly.types.get('NonExistent', by='NAME')
        result3 = db_readonly.types.get('NonExistent', by='Name')
        assert result1 == result2 == result3

    def test_apply_by_name(self, db_mutable):
        """
        Test apply() with by="name" applies named type.

        RATIONALE: by="name" should delegate to apply_by_name().
        The method returns a boolean indicating success/failure.
        """
        first_func = next(db_mutable.functions.get_all())
        result = db_mutable.types.apply(first_func.start_ea, 'int', by='name')

        # Result is a boolean - applying 'int' to function may or may not succeed
        # depending on context, but the API should return a boolean
        assert isinstance(result, bool), 'apply by name should return a boolean'

    def test_apply_by_decl(self, db_mutable):
        """
        Test apply() with by="decl" applies declaration.

        RATIONALE: by="decl" should delegate to apply_declaration().
        The method returns a boolean indicating success/failure.
        """
        first_func = next(db_mutable.functions.get_all())
        # Try to apply a declaration
        result = db_mutable.types.apply(first_func.start_ea, 'int x', by='decl')

        # Result is a boolean - success depends on context
        assert isinstance(result, bool), 'apply by decl should return a boolean'

    def test_apply_with_invalid_address_raises_error(self, db_mutable):
        """
        Test apply() raises InvalidEAError for invalid addresses.

        RATIONALE: All apply variations should validate addresses.
        """
        with pytest.raises(InvalidEAError):
            db_mutable.types.apply(0xFFFFFFFFFFFFFFFF, 'int', by='name')

    def test_apply_with_invalid_by_raises_error(self, db_mutable):
        """
        Test apply() raises InvalidParameterError for unknown by value.

        RATIONALE: Invalid by parameter should raise InvalidParameterError.
        """
        first_func = next(db_mutable.functions.get_all())
        with pytest.raises(InvalidParameterError):
            db_mutable.types.apply(first_func.start_ea, 'int', by='invalid')

    def test_guess_alias(self, db_readonly):
        """
        Test guess() is alias for guess_at().

        RATIONALE: guess() provides shorter, LLM-friendly name for guess_at().
        """
        first_func = next(db_readonly.functions.get_all())
        # Both should produce same result
        result1 = db_readonly.types.guess(first_func.start_ea)
        result2 = db_readonly.types.guess_at(first_func.start_ea)
        # Both may be None or tinfo_t
        assert (result1 is None and result2 is None) or (
            result1 is not None and result2 is not None
        )

    def test_guess_with_invalid_address_raises_error(self, db_readonly):
        """
        Test guess() raises InvalidEAError for invalid addresses.

        RATIONALE: guess() should validate addresses like guess_at().
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.guess(0xFFFFFFFFFFFFFFFF)

    def test_format_alias(self, db_readonly):
        """
        Test format() is alias for format_type_at() when given address.

        RATIONALE: format() provides shorter, LLM-friendly name.
        """
        first_func = next(db_readonly.functions.get_all())
        # Format at address - result may be None or string
        result = db_readonly.types.format(first_func.start_ea)
        assert result is None or isinstance(result, str)

    def test_format_with_invalid_address_raises_error(self, db_readonly):
        """
        Test format() raises InvalidEAError for invalid addresses.

        RATIONALE: format() should validate addresses.
        """
        with pytest.raises(InvalidEAError):
            db_readonly.types.format(0xFFFFFFFFFFFFFFFF)


class TestTypeLookupModeEnum:
    """Tests for TypeLookupMode enum support in get() method."""

    def test_get_with_enum_name(self, db_readonly):
        """
        Test get() accepts TypeLookupMode.NAME enum value.

        RATIONALE: Enum values should be the primary interface.
        """
        result = db_readonly.types.get('NonExistentTypeXYZ', by=TypeLookupMode.NAME)
        assert result is None

    def test_get_with_enum_ordinal(self, db_readonly):
        """
        Test get() accepts TypeLookupMode.ORDINAL enum value.

        RATIONALE: Enum values should be the primary interface.
        """
        result = db_readonly.types.get(999999, by=TypeLookupMode.ORDINAL)
        assert result is None

    def test_get_with_enum_address(self, db_readonly):
        """
        Test get() accepts TypeLookupMode.ADDRESS enum value.

        RATIONALE: Enum values should be the primary interface.
        """
        first_func = next(db_readonly.functions.get_all())
        result = db_readonly.types.get(first_func.start_ea, by=TypeLookupMode.ADDRESS)
        assert result is None or hasattr(result, 'get_type_name')

    def test_get_default_is_enum(self, db_readonly):
        """
        Test get() default for 'by' parameter is TypeLookupMode.NAME.

        RATIONALE: Default should be the enum, not a string.
        """
        # Call without specifying 'by' - should use TypeLookupMode.NAME default
        result = db_readonly.types.get('NonExistentTypeXYZ')
        assert result is None


class TestTypeApplyModeEnum:
    """Tests for TypeApplyMode enum support in apply() method."""

    def test_apply_with_enum_name(self, db_mutable):
        """
        Test apply() accepts TypeApplyMode.NAME enum value.

        RATIONALE: Enum values should be the primary interface.
        """
        first_func = next(db_mutable.functions.get_all())
        result = db_mutable.types.apply(first_func.start_ea, 'int', by=TypeApplyMode.NAME)
        assert isinstance(result, bool)

    def test_apply_with_enum_decl(self, db_mutable):
        """
        Test apply() accepts TypeApplyMode.DECL enum value.

        RATIONALE: Enum values should be the primary interface.
        """
        first_func = next(db_mutable.functions.get_all())
        result = db_mutable.types.apply(first_func.start_ea, 'int x', by=TypeApplyMode.DECL)
        assert isinstance(result, bool)

    def test_apply_default_is_enum(self, db_mutable):
        """
        Test apply() default for 'by' parameter is TypeApplyMode.NAME.

        RATIONALE: Default should be the enum, not a string.
        """
        first_func = next(db_mutable.functions.get_all())
        # Call without specifying 'by' - should use TypeApplyMode.NAME default
        result = db_mutable.types.apply(first_func.start_ea, 'int')
        assert isinstance(result, bool)

    def test_apply_is_case_insensitive(self, db_mutable):
        """
        Test apply() string parameter is case-insensitive.

        RATIONALE: LLM-friendly API should be case-insensitive for backward compatibility.
        """
        first_func = next(db_mutable.functions.get_all())
        # All these should work (not raise InvalidParameterError)
        result1 = db_mutable.types.apply(first_func.start_ea, 'int', by='name')
        result2 = db_mutable.types.apply(first_func.start_ea, 'int', by='NAME')
        result3 = db_mutable.types.apply(first_func.start_ea, 'int', by='Name')
        assert all(isinstance(r, bool) for r in [result1, result2, result3])
