import pytest

from ida_domain.base import InvalidEAError, InvalidParameterError


def test_heads(test_env):
    db = test_env

    count = 0
    heads = db.heads
    for _ in heads:
        count += 1
    assert count == 201

    assert db.heads.get_previous(db.minimum_ea) is None
    assert db.heads.get_next(db.maximum_ea) is None

    expected = [0xC8, 0xC9, 0xCB, 0xCD, 0xCF, 0xD1, 0xD4]
    actual = []
    heads = db.heads.get_between(0xC6, 0xD6)
    for ea in heads:
        actual.append(ea)
    assert actual == expected

    assert db.heads.get_previous(0xCB) == 0xC9
    assert db.heads.get_next(0xC9) == 0xCB

    assert db.heads.is_head(0x67) is True  # Start of an instruction
    assert db.heads.is_head(0x68) is False  # Middle of an instruction
    assert db.heads.is_head(0x330) is True  # Start of data

    assert db.heads.is_tail(0x67) is False  # Start of an instruction
    assert db.heads.is_tail(0x68) is True  # Middle of an instruction
    assert db.heads.is_tail(0x330) is False  # Start of data

    assert db.heads.size(0x67) == 2
    assert db.heads.size(0x330) == 8


    with pytest.raises(InvalidParameterError):
        db.heads.size(0x68)  # Not a head

    start, end = db.heads.bounds(0x67)
    assert start == 0x67 and end == 0x69

    start, end = db.heads.bounds(0x68)  # Middle of instruction
    assert start == 0x67
    assert end == 0x69

    start, end = db.heads.bounds(0x330)
    assert start == 0x330 and end == 0x338

    assert db.heads.is_code(0x67) is True  # Instruction address
    assert db.heads.is_code(0x330) is False  # Data address
    assert db.heads.is_code(0x3D4) is False  # String data

    assert db.heads.is_data(0x67) is False  # Instruction address
    assert db.heads.is_data(0x330) is True  # Data address
    assert db.heads.is_data(0x3D4) is True  # String data

    all_heads_list = list(db.heads.get_all())
    assert len(all_heads_list) == 201  # Same count as iterator

    with pytest.raises(InvalidEAError):
        db.heads.get_next(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.get_previous(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_head(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_tail(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.size(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.bounds(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_code(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        db.heads.is_data(0xFFFFFFFF)

    with pytest.raises(InvalidEAError):
        list(db.heads.get_between(0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        list(db.heads.get_between(0x100, 0x50))  # start > end

    bounds_result = db.heads.bounds(0x400)  # May be in undefined area
    assert isinstance(bounds_result, tuple) and len(bounds_result) == 2
    assert bounds_result[0] <= 0x400 <= bounds_result[1]
