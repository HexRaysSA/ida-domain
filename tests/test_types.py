import logging
from pathlib import Path

import pytest

import ida_typeinf

import ida_domain  # isort: skip
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.types import TypeAttr, TypeDetails, TypeDetailsVisitor, TypeKind, UdtAttr

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

    from ida_domain.types import TypeAttr, TypeDetailsVisitor, UdtAttr

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
