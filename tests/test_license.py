import re
from datetime import datetime, timezone

import pytest

import ida_domain  # isort: skip
from conftest import max_ida_version, min_ida_version
from packaging.version import Version

from ida_domain.license import License, _to_datetime, _to_version


@min_ida_version('9.5')
def test_license(test_env):
    import ida_license

    db = test_env
    lic = db.license
    now = datetime.now(timezone.utc)

    assert lic.is_valid is True
    assert lic.is_decompiler_available is True

    assert re.fullmatch(r'[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}', lic.id)
    assert lic.id in lic.source_ids
    assert lic.product
    assert lic.edition
    raw_description = ida_license.get_license_description()
    assert lic.description == (raw_description or None)
    assert lic.product_version is None or lic.product_version >= Version('9.0')

    # valid means the activation period is in effect
    assert lic.start_date <= now
    assert lic.end_date is None or lic.end_date > lic.start_date
    assert lic.issued_on <= now

    for name in lic.add_ons:
        assert lic.has_add_on(name) is True

    assert lic.has_add_on('NONEXISTENT_ADD_ON') is False
    assert lic.add_on_end_date('NONEXISTENT_ADD_ON') is None

    for name in lic.features:
        assert lic.has_feature(name) is True
    assert lic.has_feature('NONEXISTENT_FEATURE') is False


def test_license_datetime_conversion():
    assert _to_datetime(0) is None
    value = _to_datetime(86400)
    assert value == datetime(1970, 1, 2, tzinfo=timezone.utc)
    assert value.tzinfo is timezone.utc


def test_license_version_conversion():
    assert _to_version(0) is None
    assert _to_version(904) == Version('9.4')
    assert _to_version(1005) == Version('10.5')


@min_ida_version('9.5')
def test_license_without_database():
    db = ida_domain.Database()
    assert db.is_open() is False
    assert db.license.is_decompiler_available is False


@min_ida_version('9.5')
def test_license_after_database_close(test_env):
    db = test_env
    lic = db.license
    db.close(False)

    assert db.is_open() is False
    assert lic.is_decompiler_available is False
    assert db.license.is_decompiler_available is False


@max_ida_version('9.4')
def test_license_unavailable():
    with pytest.raises(NotImplementedError, match='requires IDA 9.5'):
        ida_domain.Database().license
    with pytest.raises(NotImplementedError, match='requires IDA 9.5'):
        License()
