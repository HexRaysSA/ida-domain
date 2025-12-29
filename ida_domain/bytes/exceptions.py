"""Exceptions for the bytes module."""
from __future__ import annotations

from ida_idaapi import ea_t


class NoValueError(ValueError):
    """Raised when a read operation is attempted on an uninitialized address."""

    def __init__(self, ea: ea_t) -> None:
        super().__init__(f'The effective address: 0x{ea:x} has no value')


class UnsupportedValueError(ValueError):
    """Raised when a read operation is attempted on an unsupported format."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
