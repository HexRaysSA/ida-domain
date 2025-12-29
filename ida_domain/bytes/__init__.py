"""
Bytes module - handles raw data access from the IDA database.

This module is split into submodules for maintainability:
- flags: ByteFlags, SearchFlags enums
- exceptions: NoValueError, UnsupportedValueError

The main Bytes class is in the parent _bytes.py module and re-exported here.

All public symbols are re-exported here for backward compatibility.
"""
from __future__ import annotations

# Import Bytes class from the renamed _bytes module
from .._bytes import Bytes
from .exceptions import NoValueError, UnsupportedValueError
from .flags import ByteFlags, SearchFlags

__all__ = [
    'Bytes',
    'ByteFlags',
    'SearchFlags',
    'NoValueError',
    'UnsupportedValueError',
]
