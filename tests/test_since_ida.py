from enum import Flag, IntEnum
from types import SimpleNamespace

import pytest

import ida_domain  # isort: skip

from conftest import max_ida_version  # noqa: E402

from ida_domain.base import NotSupportedWarning, _CheckAttrSupport, _since_ida  # noqa: E402
from ida_domain.microcode import MicroError  # noqa: E402


def test_missing_member_does_not_alias_real_member():
    class _Codes(IntEnum, metaclass=_CheckAttrSupport):
        FIRST = -1
        MISSING = _since_ida('99.0', SimpleNamespace(), 'MISSING')

    with pytest.warns(NotSupportedWarning):
        assert _Codes.MISSING is not _Codes.FIRST


def test_flag_rejects_placeholder():
    with pytest.raises(TypeError):

        class _Bits(Flag, metaclass=_CheckAttrSupport):
            A = 1
            B = _since_ida('99.0', SimpleNamespace(), 'B')


@max_ida_version('9.4')
def test_micro_error_timeout_is_not_interr():
    with pytest.warns(NotSupportedWarning):
        assert MicroError.TIMEOUT is not MicroError.INTERR
