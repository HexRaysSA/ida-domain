import pytest

import ida_domain  # isort: skip


def test_entries(test_env):
    db = test_env

    count = 0
    for _ in db.entries:
        count += 1
    assert count == 1

    assert db.entries.get_count() == 1
    assert len(db.entries) == 1
    assert db.entries[0] == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_at_index(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_by_ordinal(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)
    assert db.entries.get_at(0) == ida_domain.entries.EntryInfo(0, 0, '_start', None)

    assert db.entries.add(address=0xCC, name='test_entry', ordinal=1)
    assert db.entries.get_count() == 2
    assert db.entries.get_at_index(1) == ida_domain.entries.EntryInfo(1, 0xCC, 'test_entry', None)
    assert db.entries.get_by_ordinal(1) == ida_domain.entries.EntryInfo(
        1, 0xCC, 'test_entry', None
    )
    assert db.entries.get_at(0xCC) == ida_domain.entries.EntryInfo(1, 0xCC, 'test_entry', None)

    assert db.entries.rename(0, '_new_start')
    assert db.entries.get_at_index(0) == ida_domain.entries.EntryInfo(0, 0, '_new_start', None)

    assert db.entries.get_by_name('_new_start') == ida_domain.entries.EntryInfo(
        0, 0, '_new_start', None
    )

    assert db.entries.exists(0) is True
    assert db.entries.exists(1) is True
    assert db.entries.exists(999) is False

    ordinals = list(db.entries.get_ordinals())
    assert ordinals == [0, 1]

    addresses = list(db.entries.get_addresses())
    assert addresses == [0, 0xCC]

    names = list(db.entries.get_names())
    assert '_new_start' in names
    assert 'test_entry' in names
    assert len(names) == 2

    assert db.entries.set_forwarder(1, 'kernel32.CreateFile')
    entry_with_forwarder = db.entries.get_by_ordinal(1)
    assert entry_with_forwarder.forwarder_name == 'kernel32.CreateFile'
    assert entry_with_forwarder.has_forwarder() is True

    forwarders = list(db.entries.get_forwarders())
    assert len(forwarders) == 1
    assert forwarders[0].ordinal == 1
    assert forwarders[0].name == 'kernel32.CreateFile'

    entry_no_forwarder = db.entries.get_by_ordinal(0)
    assert entry_no_forwarder.has_forwarder() is False

    with pytest.raises(IndexError):
        db.entries.get_at_index(-1)

    with pytest.raises(IndexError):
        db.entries.get_at_index(999)

    with pytest.raises(IndexError):
        _ = db.entries[999]

    assert db.entries.get_by_ordinal(999) is None
    assert db.entries.get_at(0xFFFF) is None
    assert db.entries.get_by_name('non_existent_entry') is None

    assert db.entries.add(address=0xDD, name='auto_ordinal')
    auto_entry = db.entries.get_at(0xDD)
    assert auto_entry is not None
    assert auto_entry.address == 0xDD
    assert auto_entry.name == 'auto_ordinal'

    assert db.entries.add(address=0xEE, name='no_code', ordinal=100, make_code=False)
    no_code_entry = db.entries.get_by_ordinal(100)
    assert no_code_entry is not None
    assert no_code_entry.address == 0xEE
    assert no_code_entry.name == 'no_code'
