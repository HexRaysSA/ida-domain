import logging
from pathlib import Path

import ida_typeinf
import pytest
from ida_idaapi import BADADDR

import ida_domain  # isort: skip
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.types import (
    ObjectIOFlags,
    TypeAttr,
    TypeDetails,
    TypeDetailsVisitor,
    TypeKind,
    UdtAttr,
)

logger = logging.getLogger(__name__)


def test_types(test_env):
    db = test_env
    all_types = db.types
    assert len(list(all_types)) == 0

    til_path = Path(__file__).parent / 'resources' / 'example.til'
    assert til_path.exists()
    til = db.types.load_library(til_path)
    assert til

    types_list = list(db.types.get_all(library=til, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 3

    types_list = list(db.types.get_all(library=til))
    assert len(types_list) == 3

    assert db.types.import_type(til, 'STRUCT_EXAMPLE')
    assert len(list(db.types)) == 2

    tif = db.types.get_by_name('STRUCT_EXAMPLE')
    assert not db.types.apply_at(tif, 0xB3)

    type_info = db.types.get_at(0xB3)
    assert type_info is None

    assert db.types.apply_at(tif, 0x330)
    type_info = db.types.get_at(0x330)
    assert type_info
    assert type_info.get_tid() == tif.get_tid()


    # Print details via visitor
    visitor = TypeDetailsVisitor(db)
    assert db.types.traverse(tif, visitor)
    for item in visitor.output:
        logger.debug(vars(item))
        if item.udt:
            logger.debug(vars(item.udt))

    # Check for missing attr handlers
    for i in TypeAttr:
        assert i in TypeDetails._HANDLERS

    for k, _ in TypeDetails._HANDLERS.items():
        assert k in TypeAttr

    # Check details
    type_details: TypeDetails = db.types.get_details(tif)
    assert type_details
    assert type_details.name == 'STRUCT_EXAMPLE'
    assert type_details.udt
    assert type_details.udt.num_members == 3
    assert not type_details.array
    assert not type_details.ptr
    assert not type_details.enum
    assert not type_details.bitfield
    assert not type_details.func

    # Check attributes
    attrs = type_details.attributes
    assert attrs
    assert TypeAttr.ATTACHED in attrs
    assert TypeAttr.UDT in attrs
    assert TypeAttr.COMPLEX in attrs
    assert TypeAttr.DECL_TYPEDEF in attrs
    assert TypeAttr.STRUCT in attrs
    assert TypeAttr.WELL_DEFINED in attrs
    assert not TypeAttr.ARRAY in attrs
    assert not TypeAttr.PTR in attrs

    # Test type comment methods
    test_comment = 'Test type comment'

    # Test setting comment for the STRUCT_EXAMPLE type
    assert db.types.set_comment(tif, test_comment)
    retrieved_comment = db.types.get_comment(tif)
    assert retrieved_comment == test_comment

    # Test getting non-existent comment returns empty string
    # Create a simple type without comment
    simple_type = ida_typeinf.tinfo_t()
    empty_comment = db.types.get_comment(simple_type)
    assert empty_comment == ''

    db.types.unload_library(til)

    errors = db.types.parse_declarations(None, 'enum eMyType { first, second };', 0)
    assert errors == 0

    tif = db.types.get_by_name('eMyType')
    assert tif is not None

    details = db.types.get_details(tif)
    assert (
        details.attributes
        | TypeAttr.ATTACHED
        | TypeAttr.COMPLEX
        | TypeAttr.CORRECT
        | TypeAttr.DECL_COMPLEX
        | TypeAttr.DECL_TYPEDEF
        | TypeAttr.ENUM
        | TypeAttr.SUE
        | TypeAttr.UDT
        | TypeAttr.WELL_DEFINED
        | TypeAttr.EXT_ARITHMETIC
        | TypeAttr.EXT_INTEGRAL
    )

    assert details.size == 4

    tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', 'Point22')
    assert tif.get_type_name() == 'Point22'
    tif = db.types.get_by_name('Point22')
    assert tif is not None
    assert tif.get_type_name() == 'Point22'

    tif = db.types.parse_one_declaration(
        None,
        'struct Point22 {int x; int y;}; union UserData { int buffer[10]; Point22 point; };',
        'Union1996',
    )
    assert tif is not None
    assert tif.get_type_name() == 'Union1996'

    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', '')
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct {int x; int y;};', None)
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, '', 'Dummy')
    with pytest.raises(InvalidParameterError):
        tif = db.types.parse_one_declaration(None, 'struct', 'Dummy')
    with pytest.raises(InvalidEAError):
        db.types.get_at(0xFFFFFFFF)
    with pytest.raises(InvalidEAError):
        db.types.apply_at(tif, 0xFFFFFFFF)

    types_list = list(db.types.get_all(library=None, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 5

    errors = db.types.parse_declarations(None, 'struct { int first; int second; };', 0)
    assert errors == 0

    types_list = list(db.types.get_all(library=None, type_kind=TypeKind.NUMBERED))
    assert len(types_list) == 6


# =============================================================================
# Object Serialization / Deserialization Tests
# =============================================================================


def test_serialize_structure_to_bytes_and_retrieve(test_env):
    """
    Test storing an object to bytes and retrieving it back.
    This tests the round-trip serialization without database involvement.
    """
    db = test_env

    # Create a simple struct type: struct Point { int x; int y; };
    point_type = (
        db.types.create_struct('TestPoint')
        .add_member('x', db.types.create_primitive(4))
        .add_member('y', db.types.create_primitive(4))
        .build()
    )

    # Create test data
    test_data = {'x': 42, 'y': 100}

    # Serialize to bytes
    packed = db.types.serialize_structure_to_bytes(point_type, test_data)
    assert packed is not None
    assert len(packed) == 8  # Two 4-byte integers

    # Parse from bytes
    retrieved = db.types.parse_structure_from_bytes(point_type, packed)
    assert retrieved is not None
    assert retrieved['x'] == 42
    assert retrieved['y'] == 100


def test_store_structure_at_and_retrieve(test_env):
    """
    Test storing an object to a database address and retrieving it back.
    This tests the full database integration.
    """
    db = test_env

    # Create a simple struct type
    point_type = (
        db.types.create_struct('TestPoint2')
        .add_member('x', db.types.create_primitive(4))
        .add_member('y', db.types.create_primitive(4))
        .build()
    )

    # Find a data address to use for testing
    # Use an address in the data section
    test_ea = 0x100

    # Create test data
    test_data = {'x': 123, 'y': 456}

    # Store to database
    db.types.store_structure_at(test_ea, point_type, test_data)

    # Retrieve from database
    retrieved = db.types.parse_structure_at(test_ea, point_type)
    assert retrieved is not None
    assert retrieved['x'] == 123
    assert retrieved['y'] == 456


def test_retrieve_object_invalid_ea(test_env):
    """Test that parse_structure_at raises InvalidEAError for invalid addresses."""
    db = test_env
    from ida_domain.base import InvalidEAError

    point_type = (
        db.types.create_struct('TestPoint3').add_member('x', db.types.create_primitive(4)).build()
    )

    with pytest.raises(InvalidEAError):
        db.types.parse_structure_at(BADADDR, point_type)


def test_serialize_structure_to_bytes_invalid_parameter(test_env):
    """Test that serialize_structure_to_bytes raises InvalidParameterError for invalid input."""
    db = test_env

    point_type = (
        db.types.create_struct('TestPoint4').add_member('x', db.types.create_primitive(4)).build()
    )

    with pytest.raises(InvalidParameterError):
        db.types.serialize_structure_to_bytes(point_type, 'not a dict')  # type: ignore


def test_parse_structure_from_bytes_invalid_data(test_env):
    """Test that parse_structure_from_bytes raises InvalidParameterError for invalid data."""
    db = test_env

    point_type = (
        db.types.create_struct('TestPoint5').add_member('x', db.types.create_primitive(4)).build()
    )

    with pytest.raises(InvalidParameterError):
        db.types.parse_structure_from_bytes(point_type, b'')  # Empty bytes


def test_apply_declaration_at(test_env):
    """Test applying a C declaration to an address."""
    db = test_env

    # Apply a function type declaration to the entry point
    entry = db.entries[0]
    result = db.types.apply_declaration_at(entry.address, "int sub(int x);")
    assert result is True

    # Verify the type was applied
    applied = db.types.get_at(entry.address)
    assert applied is not None


def test_apply_declaration_at_invalid_ea(test_env):
    """Test that apply_declaration_at raises InvalidEAError for invalid addresses."""
    db = test_env
    from ida_domain.base import InvalidEAError

    with pytest.raises(InvalidEAError):
        db.types.apply_declaration_at(BADADDR, "int foo(void)")


def test_apply_declaration_at_empty_decl(test_env):
    """Test that apply_declaration_at raises InvalidParameterError for empty declaration."""
    db = test_env

    entry = db.entries[0]
    with pytest.raises(InvalidParameterError):
        db.types.apply_declaration_at(entry.address, "")


def test_apply_declaration_at_invalid_decl(test_env):
    """Test that apply_declaration_at raises InvalidParameterError for unparseable declaration."""
    db = test_env

    entry = db.entries[0]
    with pytest.raises(InvalidParameterError):
        db.types.apply_declaration_at(entry.address, "not a valid declaration !!!")


def test_store_structure_at_invalid_ea(test_env):
    """Test that store_structure_at raises InvalidEAError for invalid addresses."""
    db = test_env
    from ida_domain.base import InvalidEAError

    point_type = (
        db.types.create_struct('TestPoint6').add_member('x', db.types.create_primitive(4)).build()
    )

    with pytest.raises(InvalidEAError):
        db.types.store_structure_at(BADADDR, point_type, {'x': 1})


def test_nested_structure_store_and_parse_at(test_env):
    """Test store/parse round-trip with nested structures at a database address."""
    db = test_env
    from ida_idaapi import object_t

    inner_type = (
        db.types.create_struct('InnerNested')
        .add_member('a', db.types.create_primitive(4))
        .add_member('b', db.types.create_primitive(4))
        .build()
    )
    outer_type = (
        db.types.create_struct('OuterNested')
        .add_member('x', db.types.create_primitive(4))
        .add_member('nested', inner_type)
        .add_member('y', db.types.create_primitive(4))
        .build()
    )

    test_ea = 0x100
    test_data = {'x': 1, 'nested': {'a': 2, 'b': 3}, 'y': 4}
    db.types.store_structure_at(test_ea, outer_type, test_data)

    retrieved = db.types.parse_structure_at(test_ea, outer_type)
    assert isinstance(retrieved, object_t)
    assert retrieved['x'] == 1
    assert retrieved['y'] == 4
    # Nested struct is an object_t, accessible by attribute or key
    assert isinstance(retrieved.nested, object_t)
    assert retrieved['nested']['a'] == 2
    assert retrieved.nested.b == 3


def test_nested_structure_serialize_and_parse_bytes(test_env):
    """Test serialize/parse round-trip with nested structures via bytes."""
    db = test_env
    from ida_idaapi import object_t

    inner_type = (
        db.types.create_struct('InnerBytes')
        .add_member('a', db.types.create_primitive(4))
        .add_member('b', db.types.create_primitive(4))
        .build()
    )
    outer_type = (
        db.types.create_struct('OuterBytes')
        .add_member('x', db.types.create_primitive(4))
        .add_member('nested', inner_type)
        .add_member('y', db.types.create_primitive(4))
        .build()
    )

    test_data = {'x': 10, 'nested': {'a': 20, 'b': 30}, 'y': 40}
    packed = db.types.serialize_structure_to_bytes(outer_type, test_data)
    assert len(packed) == 16  # 4 ints * 4 bytes

    retrieved = db.types.parse_structure_from_bytes(outer_type, packed)
    assert isinstance(retrieved, object_t)
    assert retrieved.x == 10
    assert isinstance(retrieved.nested, object_t)
    assert retrieved.nested.a == 20
    assert retrieved.nested.b == 30
    assert retrieved.y == 40


def test_struct_with_array_member_round_trip(test_env):
    """Test serialize/parse round-trip for a struct containing an array member."""
    db = test_env
    from ida_idaapi import object_t

    arr_type = db.types.create_array(db.types.create_primitive(4), 3)
    struct_type = (
        db.types.create_struct('WithArray')
        .add_member('id', db.types.create_primitive(4))
        .add_member('values', arr_type)
        .build()
    )

    test_data = {'id': 99, 'values': [10, 20, 30]}
    packed = db.types.serialize_structure_to_bytes(struct_type, test_data)
    assert len(packed) == 16  # 4 ints * 4 bytes

    retrieved = db.types.parse_structure_from_bytes(struct_type, packed)
    assert isinstance(retrieved, object_t)
    assert retrieved.id == 99
    # Array members are returned as object_t with string-index keys
    assert isinstance(retrieved.values, object_t)
    assert retrieved.values['0'] == 10
    assert retrieved.values['1'] == 20
    assert retrieved.values['2'] == 30


def test_struct_with_array_member_store_and_parse_at(test_env):
    """Test store/parse at address for a struct containing an array member."""
    db = test_env
    from ida_idaapi import object_t

    arr_type = db.types.create_array(db.types.create_primitive(4), 3)
    struct_type = (
        db.types.create_struct('WithArray2')
        .add_member('id', db.types.create_primitive(4))
        .add_member('values', arr_type)
        .build()
    )

    test_ea = 0x100
    test_data = {'id': 42, 'values': [1, 2, 3]}
    db.types.store_structure_at(test_ea, struct_type, test_data)

    retrieved = db.types.parse_structure_at(test_ea, struct_type)
    assert isinstance(retrieved, object_t)
    assert retrieved.id == 42
    assert isinstance(retrieved.values, object_t)
    assert retrieved.values['0'] == 1
    assert retrieved.values['1'] == 2
    assert retrieved.values['2'] == 3


def test_serialize_primitive_type_rejected(test_env):
    """Test that serializing a primitive type (not a struct) raises InvalidParameterError."""
    db = test_env

    dword_type = db.types.create_primitive(4)
    with pytest.raises(InvalidParameterError):
        db.types.serialize_structure_to_bytes(dword_type, 42)


def test_store_primitive_type_rejected(test_env):
    """Test that storing a primitive type (not a struct) raises InvalidParameterError."""
    db = test_env

    dword_type = db.types.create_primitive(4)
    with pytest.raises(InvalidParameterError):
        db.types.store_structure_at(0x100, dword_type, 42)


def test_union_serialize_and_parse_bytes(test_env):
    """Test serialize/parse round-trip for a union — signed vs unsigned reinterpretation."""
    db = test_env
    from ida_idaapi import object_t

    union_type = (
        db.types.create_union('TestUnion')
        .add_member('as_signed', db.types.create_primitive(4, signed=True))
        .add_member('as_unsigned', db.types.create_primitive(4, signed=False))
        .add_member('as_short', db.types.create_primitive(2, signed=True))
        .build()
    )
    assert union_type.is_union()

    packed = db.types.serialize_structure_to_bytes(union_type, {'as_signed': -1})
    retrieved = db.types.parse_structure_from_bytes(union_type, packed)
    assert isinstance(retrieved, object_t)
    assert retrieved.as_signed == -1
    assert retrieved.as_unsigned == 0xFFFFFFFF
    assert retrieved.as_short == -1  # low 2 bytes of 0xFFFFFFFF

    # Store a value where the short member differs from the int members
    packed2 = db.types.serialize_structure_to_bytes(union_type, {'as_unsigned': 0x00010002})
    retrieved2 = db.types.parse_structure_from_bytes(union_type, packed2)
    assert retrieved2.as_signed == 0x00010002
    assert retrieved2.as_unsigned == 0x00010002
    assert retrieved2.as_short == 2  # low 2 bytes only


def test_union_store_and_parse_at(test_env):
    """Test store/parse round-trip for a union at a database address."""
    db = test_env
    from ida_idaapi import object_t

    union_type = (
        db.types.create_union('TestUnion2')
        .add_member('as_signed', db.types.create_primitive(4, signed=True))
        .add_member('as_unsigned', db.types.create_primitive(4, signed=False))
        .add_member('as_short', db.types.create_primitive(2, signed=True))
        .build()
    )

    test_ea = 0x100
    db.types.store_structure_at(test_ea, union_type, {'as_unsigned': 0x00010002})
    retrieved = db.types.parse_structure_at(test_ea, union_type)
    assert isinstance(retrieved, object_t)
    assert retrieved.as_signed == 0x00010002
    assert retrieved.as_unsigned == 0x00010002
    assert retrieved.as_short == 2


def test_struct_with_union_member_round_trip(test_env):
    """Test serialize/parse round-trip for a struct containing a union member."""
    db = test_env
    from ida_idaapi import object_t

    union_type = (
        db.types.create_union('InnerUnion')
        .add_member('as_signed', db.types.create_primitive(4, signed=True))
        .add_member('as_unsigned', db.types.create_primitive(4, signed=False))
        .add_member('as_short', db.types.create_primitive(2, signed=True))
        .build()
    )
    struct_type = (
        db.types.create_struct('HasUnion')
        .add_member('tag', db.types.create_primitive(4))
        .add_member('data', union_type)
        .build()
    )

    test_data = {'tag': 1, 'data': {'as_unsigned': 0x0003FFFF}}
    packed = db.types.serialize_structure_to_bytes(struct_type, test_data)
    retrieved = db.types.parse_structure_from_bytes(struct_type, packed)

    assert isinstance(retrieved, object_t)
    assert retrieved.tag == 1
    assert isinstance(retrieved.data, object_t)
    assert retrieved.data.as_signed == 0x0003FFFF
    assert retrieved.data.as_unsigned == 0x0003FFFF
    assert retrieved.data.as_short == -1  # low 2 bytes = 0xFFFF


def test_create_primitive_signed_and_unsigned(test_env):
    """Test that create_primitive produces correct signed/unsigned types for all sizes."""
    db = test_env

    for size in (1, 2, 4, 8):
        signed_t = db.types.create_primitive(size, signed=True)
        unsigned_t = db.types.create_primitive(size, signed=False)

        assert signed_t.is_signed(), f"size={size} should be signed"
        assert unsigned_t.is_unsigned(), f"size={size} should be unsigned"
        assert signed_t.get_size() == size
        assert unsigned_t.get_size() == size
        assert signed_t != unsigned_t


def test_create_primitive_default_is_signed(test_env):
    """Test that create_primitive defaults to signed."""
    db = test_env

    default_t = db.types.create_primitive(4)
    assert default_t.is_signed()


def test_create_primitive_invalid_size(test_env):
    """Test that create_primitive rejects invalid sizes."""
    db = test_env

    for size in (0, 3, 5, 7, 16):
        with pytest.raises(InvalidParameterError):
            db.types.create_primitive(size)


def test_pointer_followed_at_idb(test_env):
    """Test that pointers are dereferenced when parsing from IDB (default behavior)."""
    db = test_env
    import ida_bytes
    from ida_idaapi import object_t

    int_type = db.types.create_primitive(4)
    ptr_type = db.types.create_pointer(int_type)

    struct_type = (
        db.types.create_struct('PtrFollow')
        .add_member('value', int_type)
        .add_member('ptr', ptr_type)
        .build()
    )

    # Write a known value at the target address
    ida_bytes.put_dword(0x200, 0xDEAD)

    # Store struct with pointer to that address
    db.types.store_structure_at(0x100, struct_type, {'value': 42, 'ptr': 0x200})

    # Default: pointer is dereferenced, returns the value at 0x200
    retrieved = db.types.parse_structure_at(0x100, struct_type)
    assert retrieved.value == 42
    assert retrieved.ptr == 0xDEAD


def test_pointer_ignored_at_idb(test_env):
    """Test that IGNORE_PTRS returns raw pointer addresses from IDB."""
    db = test_env
    import ida_bytes

    int_type = db.types.create_primitive(4)
    ptr_type = db.types.create_pointer(int_type)

    struct_type = (
        db.types.create_struct('PtrIgnore')
        .add_member('value', int_type)
        .add_member('ptr', ptr_type)
        .build()
    )

    ida_bytes.put_dword(0x200, 0xDEAD)
    db.types.store_structure_at(0x100, struct_type, {'value': 42, 'ptr': 0x200})

    # IGNORE_PTRS: pointer is NOT dereferenced, returns the address itself
    retrieved = db.types.parse_structure_at(
        0x100, struct_type, ObjectIOFlags.IGNORE_PTRS
    )
    assert retrieved.value == 42
    assert retrieved.ptr == 0x200


def test_pointer_to_struct_followed_at_idb(test_env):
    """Test that a pointer to a struct is dereferenced into a nested object_t."""
    db = test_env
    import ida_bytes
    from ida_idaapi import object_t

    int_type = db.types.create_primitive(4)
    inner_type = (
        db.types.create_struct('PtrInner')
        .add_member('a', int_type)
        .add_member('b', int_type)
        .build()
    )
    outer_type = (
        db.types.create_struct('PtrOuter')
        .add_member('id', int_type)
        .add_member('data', db.types.create_pointer(inner_type))
        .build()
    )

    # Write inner struct at 0x300
    ida_bytes.put_dword(0x300, 0xAA)
    ida_bytes.put_dword(0x304, 0xBB)

    # Store outer with pointer to inner
    db.types.store_structure_at(0x100, outer_type, {'id': 1, 'data': 0x300})

    # Default: pointer followed, data is a nested object_t
    retrieved = db.types.parse_structure_at(0x100, outer_type)
    assert retrieved.id == 1
    assert isinstance(retrieved.data, object_t)
    assert retrieved.data.a == 0xAA
    assert retrieved.data.b == 0xBB

    # IGNORE_PTRS: data is the raw address
    retrieved2 = db.types.parse_structure_at(
        0x100, outer_type, ObjectIOFlags.IGNORE_PTRS
    )
    assert retrieved2.id == 1
    assert retrieved2.data == 0x300


def test_pointer_lost_in_bytes_without_ignore_ptrs(test_env):
    """Test that pointer values are zeroed when parsing from bytes without IGNORE_PTRS."""
    db = test_env

    int_type = db.types.create_primitive(4)
    ptr_type = db.types.create_pointer(int_type)

    struct_type = (
        db.types.create_struct('PtrBytes')
        .add_member('value', int_type)
        .add_member('ptr', ptr_type)
        .build()
    )

    packed = db.types.serialize_structure_to_bytes(struct_type, {'value': 42, 'ptr': 0x200})

    # Default from bytes: no IDB context, pointer value is lost (zeroed)
    retrieved = db.types.parse_structure_from_bytes(struct_type, packed)
    assert retrieved.value == 42
    assert retrieved.ptr == 0

    # IGNORE_PTRS from bytes: pointer value is preserved
    retrieved2 = db.types.parse_structure_from_bytes(
        struct_type, packed, ObjectIOFlags.IGNORE_PTRS
    )
    assert retrieved2.value == 42
    assert retrieved2.ptr == 0x200


def test_object_io_flags_values():
    """Test that ObjectIOFlags match the underlying IDA SDK constants."""
    from ida_typeinf import PIO_IGNORE_PTRS, PIO_NOATTR_FAIL

    assert ObjectIOFlags.NONE == 0
    assert ObjectIOFlags.NOATTR_FAIL == PIO_NOATTR_FAIL
    assert ObjectIOFlags.IGNORE_PTRS == PIO_IGNORE_PTRS

    # Test flag combination
    combined = ObjectIOFlags.NOATTR_FAIL | ObjectIOFlags.IGNORE_PTRS
    assert combined == PIO_NOATTR_FAIL | PIO_IGNORE_PTRS
