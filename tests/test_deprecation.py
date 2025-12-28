import warnings

import pytest

from ida_domain.base import deprecated


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
