import warnings

import pytest

from ida_domain.base import deprecated
from ida_domain.bytes import Bytes
from ida_domain.fixups import Fixups
from ida_domain.problems import Problems
from ida_domain.switches import Switches


def test_deprecated_decorator_warns():
    @deprecated("Use new_func instead")
    def old_func():
        return 42

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = old_func()
        assert result == 42
        assert len(w) == 1
        assert "Use new_func instead" in str(w[0].message)
        assert issubclass(w[0].category, DeprecationWarning)


def test_fixups_delete_method_exists():
    """Test that Fixups has a delete() method."""
    assert hasattr(Fixups, 'delete')
    assert callable(getattr(Fixups, 'delete'))


def test_switches_delete_method_exists():
    """Test that Switches has a delete() method."""
    assert hasattr(Switches, 'delete')
    assert callable(getattr(Switches, 'delete'))


def test_problems_delete_method_exists():
    """Test that Problems has a delete() method."""
    assert hasattr(Problems, 'delete')
    assert callable(getattr(Problems, 'delete'))


def test_problems_delete_at_method_exists():
    """Test that Problems has a delete_at() method."""
    assert hasattr(Problems, 'delete_at')
    assert callable(getattr(Problems, 'delete_at'))


def test_bytes_find_bytes_in_range_method_exists():
    """Test that Bytes has a find_bytes_in_range() method."""
    assert hasattr(Bytes, 'find_bytes_in_range')
    assert callable(getattr(Bytes, 'find_bytes_in_range'))
