import pytest

from ida_domain.base import InvalidEAError
from ida_domain.xrefs import CallerInfo, XrefType, XrefsFlags


def test_xrefs(test_env):
    db = test_env
    expected_xrefs = [0xC4]
    expected_names = ['ORDINARY_FLOW']
    xrefs_to = db.xrefs.to_ea(0xC6)
    for i, xref in enumerate(xrefs_to):
        assert xref.from_ea == expected_xrefs[i]
        assert xref.type.name == expected_names[i]

    expected_xrefs = [0xD9]
    expected_names = ['ORDINARY_FLOW']
    xrefs_from = db.xrefs.from_ea(0xD6)
    for i, xref in enumerate(xrefs_from):
        assert xref.to_ea == expected_xrefs[i]
        assert xref.type.name == expected_names[i]

    from ida_domain.xrefs import XrefsFlags

    # Test to() with different XrefsFlags options
    all_xrefs = list(db.xrefs.to_ea(0x2A3))
    assert len(all_xrefs) >= 1

    code_xrefs = list(db.xrefs.to_ea(0x2A3, XrefsFlags.CODE))
    assert isinstance(code_xrefs, list)

    code_xrefs_noflow = list(db.xrefs.to_ea(0x2A3, XrefsFlags.CODE_NOFLOW))
    assert isinstance(code_xrefs_noflow, list)

    data_xrefs = list(db.xrefs.to_ea(0x330, XrefsFlags.DATA))
    assert isinstance(data_xrefs, list)

    # Test from_() with different options
    from_xrefs = list(db.xrefs.from_ea(0x27))
    assert len(from_xrefs) >= 1

    from_code = list(db.xrefs.from_ea(0x27, XrefsFlags.CODE))
    assert isinstance(from_code, list)

    from_data = list(db.xrefs.from_ea(0xFF, XrefsFlags.DATA))
    assert isinstance(from_data, list)

    from ida_domain.xrefs import CallerInfo

    # Test call references
    calls_to = list(db.xrefs.calls_to_ea(0x2A3))  # add_numbers
    assert len(calls_to) == 1
    assert calls_to[0] == 0x27

    # Test callers with detailed info
    callers = list(db.xrefs.get_callers(0x2A3))
    assert isinstance(callers, list)
    assert len(callers) == 1
    assert isinstance(callers[0], CallerInfo)
    assert callers[0].ea == 0x27

    calls_from = list(db.xrefs.calls_from_ea(0x27))
    assert len(calls_from) >= 1

    # Test jump references
    jumps_to = list(db.xrefs.jumps_to_ea(0x272))  # skip_jumps
    assert isinstance(jumps_to, list)

    jumps_from = list(db.xrefs.jumps_from_ea(0x270))
    assert isinstance(jumps_from, list)

    # Test data reads and writes
    reads = list(db.xrefs.reads_of_ea(0x330))  # test_data
    assert isinstance(reads, list)

    writes = list(db.xrefs.writes_to_ea(0x330))
    assert isinstance(writes, list)

    # Test code refs to/from (now returns iterators)
    code_refs_to = list(db.xrefs.code_refs_to_ea(0x2A3))
    assert isinstance(code_refs_to, list)
    assert len(code_refs_to) >= 1
    assert all(isinstance(ea, int) for ea in code_refs_to)

    code_refs_from = list(db.xrefs.code_refs_from_ea(0x27))
    assert isinstance(code_refs_from, list)

    # Test data refs to/from (now returns iterators)
    data_refs_to = list(db.xrefs.data_refs_to_ea(0x330))
    assert isinstance(data_refs_to, list)

    data_refs_from = list(db.xrefs.data_refs_from_ea(0xFF))
    assert isinstance(data_refs_from, list)

    from ida_domain.xrefs import XrefType

    # Test enhanced xref info
    xrefs_info = list(db.xrefs.to_ea(0x2A3))
    assert len(xrefs_info) == 1
    assert xrefs_info[0].from_ea == 39
    assert xrefs_info[0].is_code == True
    assert xrefs_info[0].type == XrefType.CALL_NEAR
    assert xrefs_info[0].user == False
    assert xrefs_info[0].to_ea == 0x2A3
    assert xrefs_info[0].is_call == True

    # Test with custom flags
    xrefs_custom = list(db.xrefs.to_ea(0x2A3, flags=XrefsFlags.CODE))
    assert isinstance(xrefs_custom, list)

    xrefs_from = list(db.xrefs.from_ea(0x27))
    assert isinstance(xrefs_from, list)

    # Test function callers
    callers = list(db.xrefs.get_callers(0x2A3))
    assert isinstance(callers, list)
    assert len(callers) == 1
    assert callers[0].ea == 0x27
    assert callers[0].name == '.text:0000000000000027'
    assert callers[0].xref_type == XrefType.CALL_NEAR
    assert callers[0].function_ea is None

    from ida_domain.base import InvalidEAError

    invalid_ea = 0xFFFFFFFF

    # Test all methods with invalid addresses
    with pytest.raises(InvalidEAError):
        list(db.xrefs.to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.calls_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.calls_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.jumps_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.jumps_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.reads_of_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.writes_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.code_refs_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.code_refs_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.data_refs_to_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.data_refs_from_ea(invalid_ea))

    with pytest.raises(InvalidEAError):
        list(db.xrefs.get_callers(invalid_ea))
