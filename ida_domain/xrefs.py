from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from enum import Enum, IntEnum, IntFlag

import ida_bytes
import ida_frame
import ida_funcs
import ida_kernwin
import ida_lines
import ida_nalt
import ida_typeinf
import ida_xref
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


@dataclass
class XrefInfo:
    """Enhanced cross-reference information."""

    from_ea: ea_t  # Source address of the xref
    to_ea: ea_t  # Target address of the xref
    is_code: bool  # True if this is a code xref, False for data xref
    type: XrefType  # Xref type enum
    user: bool  # True if this is a user-defined xref

    @property
    def is_call(self) -> bool:
        """Check if this is a call reference."""
        return self.type in (XrefType.CALL_NEAR, XrefType.CALL_FAR)

    @property
    def is_jump(self) -> bool:
        """Check if this is a jump reference."""
        return self.type in (XrefType.JUMP_NEAR, XrefType.JUMP_FAR)

    @property
    def is_read(self) -> bool:
        """Check if this is a data read reference."""
        return self.type == XrefType.READ

    @property
    def is_write(self) -> bool:
        """Check if this is a data write reference."""
        return self.type == XrefType.WRITE

    @property
    def is_flow(self) -> bool:
        """Check if this is ordinary flow reference."""
        return self.type == XrefType.ORDINARY_FLOW


@dataclass
class CallerInfo:
    """Information about a function caller."""

    ea: ea_t  # Address of the calling instruction
    name: str  # Name of the calling function (if available)
    xref_type: XrefType  # Type of the xref (always a call type)
    function_ea: Optional[ea_t] = None  # Start address of calling function (if in a function)


class XrefType(IntEnum):
    """Unified cross-reference types (both code and data)."""

    UNKNOWN = 0
    """Unknown"""

    OFFSET = ida_xref.dr_O
    """Offset reference or OFFSET flag set"""
    WRITE = ida_xref.dr_W
    """Write access"""
    READ = ida_xref.dr_R
    """Read access"""
    TEXT = ida_xref.dr_T
    """Text (for forced operands only)"""
    INFORMATIONAL = ida_xref.dr_I
    """Informational reference"""
    SYMBOLIC = ida_xref.dr_S
    """Reference to enum member (symbolic constant)"""

    CALL_FAR = ida_xref.fl_CF
    """Call Far - creates a function at referenced location"""
    CALL_NEAR = ida_xref.fl_CN
    """Call Near - creates a function at referenced location"""
    JUMP_FAR = ida_xref.fl_JF
    """Jump Far"""
    JUMP_NEAR = ida_xref.fl_JN
    """Jump Near"""
    USER_SPECIFIED = ida_xref.fl_USobsolete
    """User specified (obsolete)"""
    ORDINARY_FLOW = ida_xref.fl_F
    """Ordinary flow to next instruction"""

    @classmethod
    @functools.lru_cache(maxsize=1)
    def _get_code_refs(cls) -> Set['XrefType']:
        """Get set of code reference types (cached)."""
        return {
            cls.CALL_FAR,
            cls.CALL_NEAR,
            cls.JUMP_FAR,
            cls.JUMP_NEAR,
            cls.USER_SPECIFIED,
            cls.ORDINARY_FLOW,
        }

    @classmethod
    @functools.lru_cache(maxsize=1)
    def _get_data_refs(cls) -> Set['XrefType']:
        """Get set of data reference types (cached)."""
        return {cls.OFFSET, cls.WRITE, cls.READ, cls.TEXT, cls.INFORMATIONAL, cls.SYMBOLIC}

    def is_code_ref(self) -> bool:
        """Check if this is a code reference."""
        return self in self._get_code_refs()

    def is_data_ref(self) -> bool:
        """Check if this is a data reference."""
        return self in self._get_data_refs()


class XrefsFlags(IntFlag):
    """Flags for xref iteration control."""

    ALL = 0
    """Default - all xrefs"""
    NOFLOW = ida_xref.XREF_NOFLOW
    """Skip ordinary flow xrefs"""
    DATA = ida_xref.XREF_DATA
    """Return only data references"""
    CODE = ida_xref.XREF_CODE
    """Return only code references"""

    CODE_NOFLOW = CODE | NOFLOW
    """Code xrefs without flow"""

    def to_ida_flags(self) -> int:
        """Convert to IDA's xref flags."""
        if self == XrefsFlags.ALL:
            return ida_xref.XREF_ALL
        ida_flags = 0
        if self & XrefsFlags.NOFLOW:
            ida_flags |= ida_xref.XREF_NOFLOW
        if self & XrefsFlags.DATA:
            ida_flags |= ida_xref.XREF_DATA
        elif self & XrefsFlags.CODE:
            ida_flags |= ida_xref.XREF_CODE
        else:
            ida_flags = ida_xref.XREF_ALL
        return ida_flags


def _make_xref_info(xb: ida_xref.xrefblk_t) -> XrefInfo:
    try:
        xref_type = XrefType(xb.type)
    except ValueError:
        xref_type = XrefType.UNKNOWN
    return XrefInfo(from_ea=xb.frm, to_ea=xb.to, is_code=xb.iscode, type=xref_type, user=xb.user)


def _iter_xrefs_to(ea: ea_t, flags: XrefsFlags) -> Iterator[XrefInfo]:
    """Iterate xrefs to ``ea`` without address validation.

    ``ea`` may also be a type id (privrange address); public entry points
    are responsible for validating their input.
    """
    xb = ida_xref.xrefblk_t()
    ok = xb.first_to(ea, flags.to_ida_flags())
    while ok:
        yield _make_xref_info(xb)
        ok = xb.next_to()


def _iter_xrefs_from(ea: ea_t, flags: XrefsFlags) -> Iterator[XrefInfo]:
    """Iterate xrefs from ``ea`` without address validation.

    ``ea`` may also be a type id (privrange address); public entry points
    are responsible for validating their input.
    """
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, flags.to_ida_flags())
    while ok:
        yield _make_xref_info(xb)
        ok = xb.next_from()


@decorate_all_methods(check_db_open)
class Xrefs(DatabaseEntity):
    """
    Provides unified access to cross-reference (xref) analysis in the IDA database.

    This class offers a simplified API for working with both code and data cross-references,
    with convenient methods for common use cases.

    Args:
        database: Reference to the active IDA database.

    Example:
        ```python
        # Get all references to an address
        for xref in db.xrefs.to_ea(ea):
            print(f"{xref.from_ea:x} -> {xref.to_ea:x} ({xref.type.name})")

        # Get only code references
        for caller in db.xrefs.code_refs_to_ea(func_ea):
            print(f"Called from: {caller:x}")

        # Get data reads
        for reader in db.xrefs.reads_of_ea(data_ea):
            print(f"Read by: {reader:x}")
        ```
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def to_ea(self, ea: ea_t, flags: XrefsFlags = XrefsFlags.ALL) -> Iterator[XrefInfo]:
        """
        Get all cross-references to an address.

        Args:
            ea: Target effective address
            flags: Filter flags (default: all xrefs)

        Yields:
            XrefInfo objects with detailed xref information

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not (self.database.is_valid_ea(ea) or self.database.is_private_ea(ea)):
            raise InvalidEAError(ea)

        yield from _iter_xrefs_to(ea, flags)

    def from_ea(self, ea: ea_t, flags: XrefsFlags = XrefsFlags.ALL) -> Iterator[XrefInfo]:
        """
        Get all cross-references from an address.

        Args:
            ea: Source effective address
            flags: Filter flags (default: all xrefs)

        Yields:
            XrefInfo objects with detailed xref information

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not (self.database.is_valid_ea(ea) or self.database.is_private_ea(ea)):
            raise InvalidEAError(ea)

        yield from _iter_xrefs_from(ea, flags)

    def code_refs_to_ea(self, ea: ea_t, flow: bool = True) -> Iterator[ea_t]:
        """
        Get code reference addresses to ea.

        Args:
            ea: Target address
            flow: Include ordinary flow references (default: True)

        Yields:
            Source addresses of code references

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        flags = XrefsFlags.CODE if flow else XrefsFlags.CODE_NOFLOW
        for xref in self.to_ea(ea, flags):
            yield xref.from_ea

    def code_refs_from_ea(self, ea: ea_t, flow: bool = True) -> Iterator[ea_t]:
        """
        Get code reference addresses from ea.

        Args:
            ea: Source address
            flow: Include ordinary flow references (default: True)

        Yields:
            Target addresses of code references

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        flags = XrefsFlags.CODE if flow else XrefsFlags.CODE_NOFLOW
        for xref in self.from_ea(ea, flags):
            yield xref.to_ea

    def data_refs_to_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get data reference addresses to ea.

        Args:
            ea: Target address

        Yields:
            Source addresses of data references

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.to_ea(ea, XrefsFlags.DATA):
            yield xref.from_ea

    def data_refs_from_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get data reference addresses from ea.

        Args:
            ea: Source address

        Yields:
            Target addresses of data references

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.from_ea(ea, XrefsFlags.DATA):
            yield xref.to_ea

    def get_callers(self, func_ea: ea_t) -> Iterator[CallerInfo]:
        """
        Get detailed caller information for a function.

        Args:
            func_ea: Function start address

        Yields:
            CallerInfo objects with caller details

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(func_ea):
            raise InvalidEAError(func_ea)

        for xref in self.to_ea(func_ea):
            if xref.is_call:
                caller_func = ida_funcs.get_func(xref.from_ea)
                caller_name: Optional[str] = None
                caller_func_ea = None

                if caller_func:
                    caller_name = self.database.functions.get_name(caller_func)
                    caller_func_ea = caller_func.start_ea
                else:
                    caller_name = self.database.names.get_at(xref.from_ea)
                    if not caller_name:
                        caller_name = ida_kernwin.ea2str(xref.from_ea)

                yield CallerInfo(
                    ea=xref.from_ea,
                    name=caller_name,
                    xref_type=xref.type,
                    function_ea=caller_func_ea,
                )

    def calls_to_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses where calls to this address occur.

        Args:
            ea: Target address

        Yields:
            Addresses containing call instructions

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.to_ea(ea):
            if xref.is_call:
                yield xref.from_ea

    def calls_from_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses called from this address.

        Args:
            ea: Source address

        Yields:
            Called addresses

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.from_ea(ea):
            if xref.is_call:
                yield xref.to_ea

    def jumps_to_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses where jumps to this address occur.

        Args:
            ea: Target address

        Yields:
            Addresses containing jump instructions

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.to_ea(ea):
            if xref.is_jump:
                yield xref.from_ea

    def jumps_from_ea(self, ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses jumped to from this address.

        Args:
            ea: Source address

        Yields:
            Jump target addresses

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.from_ea(ea):
            if xref.is_jump:
                yield xref.to_ea

    def reads_of_ea(self, data_ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses that read from this data location.

        Args:
            data_ea: Data address

        Yields:
            Addresses that read the data

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.to_ea(data_ea, XrefsFlags.DATA):
            if xref.is_read:
                yield xref.from_ea

    def writes_to_ea(self, data_ea: ea_t) -> Iterator[ea_t]:
        """
        Get addresses that write to this data location.

        Args:
            data_ea: Data address

        Yields:
            Addresses that write to the data

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        for xref in self.to_ea(data_ea, XrefsFlags.DATA):
            if xref.is_write:
                yield xref.from_ea

    def add_code_ref(
        self, from_ea: ea_t, to_ea: ea_t, xref_type: XrefType, user: bool = True
    ) -> bool:
        """
        Add a code cross-reference.

        Args:
            from_ea: Source address; must be the head of a defined item
            to_ea: Target address
            xref_type: Code reference type (e.g. XrefType.CALL_NEAR, XrefType.JUMP_NEAR)
            user: Mark the xref as user-specified (default: True). User xrefs survive
                reanalysis; without this mark the kernel deletes the xref the next time
                the source item is reanalyzed. Non-user xrefs also cannot replace an
                existing user-specified xref for the same address pair.

        Returns:
            True if the cross-reference was added

        Raises:
            InvalidEAError: If either effective address is invalid
            InvalidParameterError: If xref_type is not a code reference type
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)
        if not xref_type.is_code_ref():
            raise InvalidParameterError('xref_type', xref_type, 'not a code reference type')

        ida_type = int(xref_type)
        if user:
            ida_type |= ida_xref.XREF_USER
        return ida_xref.add_cref(from_ea, to_ea, ida_type)

    def remove_code_ref(self, from_ea: ea_t, to_ea: ea_t, expand: bool = False) -> bool:
        """
        Remove a code cross-reference.

        Args:
            from_ea: Source address
            to_ea: Target address
            expand: If True, plan to delete the referenced instruction when it no
                longer has any references (default: False)

        Returns:
            True if the referenced instruction was scheduled for deletion
            (only possible when expand is True), False otherwise

        Raises:
            InvalidEAError: If either effective address is invalid
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        return ida_xref.del_cref(from_ea, to_ea, expand)

    def add_data_ref(
        self, from_ea: ea_t, to_ea: ea_t, xref_type: XrefType, user: bool = True
    ) -> bool:
        """
        Add a data cross-reference.

        Args:
            from_ea: Source address; must be the head of a defined item
            to_ea: Target address; addresses in IDA's private range are also
                accepted (e.g. type and member ids)
            xref_type: Data reference type (e.g. XrefType.READ, XrefType.WRITE, XrefType.OFFSET)
            user: Mark the xref as user-specified (default: True). User xrefs survive
                reanalysis; without this mark the kernel deletes the xref the next time
                the source item is reanalyzed. Non-user xrefs also cannot replace an
                existing user-specified xref for the same address pair.

        Returns:
            True if the cross-reference was added

        Raises:
            InvalidEAError: If either effective address is invalid
            InvalidParameterError: If xref_type is not a data reference type
        """
        if not (self.database.is_valid_ea(from_ea) or self.database.is_private_ea(from_ea)):
            raise InvalidEAError(from_ea)
        if not (self.database.is_valid_ea(to_ea) or self.database.is_private_ea(to_ea)):
            raise InvalidEAError(to_ea)
        if not xref_type.is_data_ref():
            raise InvalidParameterError('xref_type', xref_type, 'not a data reference type')

        ida_type = int(xref_type)
        if user:
            ida_type |= ida_xref.XREF_USER
        return ida_xref.add_dref(from_ea, to_ea, ida_type)

    def remove_data_ref(self, from_ea: ea_t, to_ea: ea_t) -> None:
        """
        Remove a data cross-reference.

        Args:
            from_ea: Source address
            to_ea: Target address

        Raises:
            InvalidEAError: If either effective address is invalid
        """
        if not (self.database.is_valid_ea(from_ea) or self.database.is_private_ea(from_ea)):
            raise InvalidEAError(from_ea)
        if not (self.database.is_valid_ea(to_ea) or self.database.is_private_ea(to_ea)):
            raise InvalidEAError(to_ea)

        ida_xref.del_dref(from_ea, to_ea)
