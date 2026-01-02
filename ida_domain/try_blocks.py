"""
Exception handling (try/catch/SEH) entity for IDA Domain API.

Provides comprehensive access to exception handling information within the IDA database,
including C++ try/catch blocks and Windows SEH (Structured Exception Handling).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Iterator, List, Optional, Tuple

import ida_funcs
import ida_tryblks
from ida_idaapi import BADADDR, ea_t

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
    deprecated,
)

if TYPE_CHECKING:
    from .database import Database

__all__ = [
    'TryBlocks',
    'TryBlock',
    'CatchHandler',
    'SehHandler',
    'TryBlockKind',
    'SehFilterCode',
    'TryBlockError',
]


# ============================================================================
# Exceptions
# ============================================================================


class TryBlockError(RuntimeError):
    """
    Raised when try block operations fail due to invalid try block structure.

    Common scenarios:
    - Try block is empty (no ranges)
    - Start address >= end address
    - No catch/except handlers defined
    - Try block would intersect with inner try block
    """

    pass


# ============================================================================
# Enumerations
# ============================================================================


class TryBlockKind(IntEnum):
    """
    Enumeration of try block kinds.

    This maps to IDA's tryblk_t kind values used to distinguish between
    different exception handling mechanisms.
    """

    NONE = 0
    """Empty/invalid try block"""
    SEH = 1
    """Windows SEH __try/__except/__finally"""
    CPP = 2
    """C++ try/catch"""


class SehFilterCode(IntEnum):
    """
    SEH filter result codes.

    These values correspond to the constants used by Windows SEH to
    control exception handler behavior.
    """

    CONTINUE = -1
    """EXCEPTION_CONTINUE_EXECUTION (resume at faulting instruction)"""
    SEARCH = 0
    """EXCEPTION_CONTINUE_SEARCH (continue searching) / __finally"""
    HANDLE = 1
    """EXCEPTION_EXECUTE_HANDLER (execute except block)"""


# ============================================================================
# Data Classes
# ============================================================================


@dataclass(frozen=True)
class CatchHandler:
    """
    Represents a C++ catch block.

    A catch handler defines the address range and exception type for
    a single catch clause in a C++ try/catch statement.
    """

    ranges: Tuple[Tuple[ea_t, ea_t], ...]
    """Address ranges of the catch handler (immutable)"""
    type_id: int
    """Type ID of exception caught (-1 for catch(...), -2 for cleanup)"""
    obj_offset: int
    """Stack offset to exception object (-1 if unknown)"""
    frame_register: int
    """Frame register number (-1 if none)"""

    @property
    def is_catch_all(self) -> bool:
        """True if this is catch(...) handler."""
        return self.type_id == -1

    @property
    def is_cleanup(self) -> bool:
        """True if this is a cleanup handler."""
        return self.type_id == -2

    @property
    def start_ea(self) -> ea_t:
        """Start address of first range."""
        return self.ranges[0][0] if self.ranges else BADADDR

    @property
    def end_ea(self) -> ea_t:
        """End address of last range."""
        return self.ranges[-1][1] if self.ranges else BADADDR


@dataclass(frozen=True)
class SehHandler:
    """
    Represents a Windows SEH exception handler.

    SEH handlers can use either a filter callback (for __except) or
    a constant filter code (for __finally and simple filters).
    """

    ranges: Tuple[Tuple[ea_t, ea_t], ...]
    """Address ranges of the handler (immutable)"""
    filter_ranges: Tuple[Tuple[ea_t, ea_t], ...]
    """Address ranges of filter callback (empty if using seh_code) (immutable)"""
    seh_code: int
    """SEH filter result code (SEH_CONTINUE, SEH_SEARCH, or SEH_HANDLE)"""
    frame_register: int
    """Frame register number (-1 if none)"""

    @property
    def has_filter(self) -> bool:
        """True if handler uses filter callback."""
        return len(self.filter_ranges) > 0

    @property
    def is_finally(self) -> bool:
        """True if this is __finally handler (seh_code == SEH_SEARCH)."""
        return self.seh_code == SehFilterCode.SEARCH

    @property
    def start_ea(self) -> ea_t:
        """Start address of first handler range."""
        return self.ranges[0][0] if self.ranges else BADADDR

    @property
    def end_ea(self) -> ea_t:
        """End address of last handler range."""
        return self.ranges[-1][1] if self.ranges else BADADDR

    @property
    def filter_start_ea(self) -> Optional[ea_t]:
        """Start address of filter (None if no filter)."""
        return self.filter_ranges[0][0] if self.filter_ranges else None


@dataclass(frozen=True)
class TryBlock:
    """
    Represents a try block (C++ or SEH) with its associated handlers.

    Try blocks can span multiple non-contiguous address ranges and can
    be nested within each other. The nesting level is calculated automatically
    by IDA when retrieving try blocks.
    """

    ranges: Tuple[Tuple[ea_t, ea_t], ...]
    """Address ranges covered by this try block (can be fragmented) (immutable)"""
    kind: TryBlockKind
    """Kind of try block (CPP, SEH, or NONE)"""
    level: int
    """Nesting level (0 = outermost, calculated automatically)"""
    catches: Optional[Tuple[CatchHandler, ...]]
    """C++ catch handlers (None for SEH blocks) (immutable)"""
    seh_handler: Optional[SehHandler]
    """SEH handler (None for C++ blocks)"""

    @property
    def is_cpp(self) -> bool:
        """True if this is a C++ try/catch block."""
        return self.kind == TryBlockKind.CPP

    @property
    def is_seh(self) -> bool:
        """True if this is a Windows SEH block."""
        return self.kind == TryBlockKind.SEH

    @property
    def start_ea(self) -> ea_t:
        """Start address of first range."""
        return self.ranges[0][0] if self.ranges else BADADDR

    @property
    def end_ea(self) -> ea_t:
        """End address of last range."""
        return self.ranges[-1][1] if self.ranges else BADADDR

    @property
    def is_empty(self) -> bool:
        """True if try block has no ranges."""
        return len(self.ranges) == 0


# ============================================================================
# Helper Functions
# ============================================================================


def _ranges_from_rangevec(rangevec: ida_tryblks.rangevec_t) -> Tuple[Tuple[ea_t, ea_t], ...]:
    """Convert IDA rangevec_t to immutable tuple of tuples."""
    ranges = []
    for i in range(len(rangevec)):
        range_obj = rangevec[i]
        ranges.append((range_obj.start_ea, range_obj.end_ea))
    return tuple(ranges)


def _catch_from_ida(catch_t_obj: ida_tryblks.catch_t) -> CatchHandler:
    """Convert IDA catch_t to CatchHandler."""
    return CatchHandler(
        ranges=_ranges_from_rangevec(catch_t_obj),
        type_id=catch_t_obj.type_id,
        obj_offset=catch_t_obj.obj,
        frame_register=catch_t_obj.fpreg,
    )


def _seh_from_ida(seh_t_obj: ida_tryblks.seh_t) -> SehHandler:
    """Convert IDA seh_t to SehHandler."""
    return SehHandler(
        ranges=_ranges_from_rangevec(seh_t_obj),
        filter_ranges=_ranges_from_rangevec(seh_t_obj.filter),
        seh_code=seh_t_obj.seh_code,
        frame_register=seh_t_obj.fpreg,
    )


def _tryblock_from_ida(tryblk_t_obj: ida_tryblks.tryblk_t) -> TryBlock:
    """Convert IDA tryblk_t to TryBlock."""
    kind = TryBlockKind(tryblk_t_obj.get_kind())
    ranges = _ranges_from_rangevec(tryblk_t_obj)

    catches = None
    seh_handler = None

    if kind == TryBlockKind.CPP:
        # Convert C++ catches
        cpp_catches = tryblk_t_obj.cpp()
        catches = tuple(_catch_from_ida(cpp_catches[i]) for i in range(len(cpp_catches)))
    elif kind == TryBlockKind.SEH:
        # Convert SEH handler
        seh_handler = _seh_from_ida(tryblk_t_obj.seh())

    return TryBlock(
        ranges=ranges,
        kind=kind,
        level=tryblk_t_obj.level,
        catches=catches,
        seh_handler=seh_handler,
    )


def _tryblock_to_ida(try_block: TryBlock) -> ida_tryblks.tryblk_t:
    """Convert TryBlock to IDA tryblk_t."""
    import ida_range

    tb = ida_tryblks.tryblk_t()

    # Set ranges
    for start, end in try_block.ranges:
        range_obj = ida_range.range_t(start, end)
        tb.push_back(range_obj)

    # Set kind and handlers
    if try_block.kind == TryBlockKind.CPP and try_block.catches:
        cpp_vec = tb.set_cpp()
        for catch in try_block.catches:
            catch_obj = ida_tryblks.catch_t()
            catch_obj.type_id = catch.type_id
            catch_obj.obj = catch.obj_offset
            catch_obj.fpreg = catch.frame_register
            # Set catch ranges
            for start, end in catch.ranges:
                catch_obj.push_back(ida_range.range_t(start, end))
            cpp_vec.push_back(catch_obj)

    elif try_block.kind == TryBlockKind.SEH and try_block.seh_handler:
        seh_obj = tb.set_seh()
        seh = try_block.seh_handler
        seh_obj.seh_code = seh.seh_code
        seh_obj.fpreg = seh.frame_register
        # Set SEH handler ranges
        for start, end in seh.ranges:
            seh_obj.push_back(ida_range.range_t(start, end))
        # Set filter ranges
        for start, end in seh.filter_ranges:
            seh_obj.filter.push_back(ida_range.range_t(start, end))

    tb.level = try_block.level
    return tb


# ============================================================================
# TryBlocks Entity
# ============================================================================


@decorate_all_methods(check_db_open)
class TryBlocks(DatabaseEntity):
    """
    Provides access to exception handling try/catch blocks.

    The TryBlocks entity manages both C++ try/catch blocks and Windows SEH
    (Structured Exception Handling) blocks, which are critical for analyzing
    compiler-generated exception handling code.
    """

    def __init__(self, database: Database) -> None:
        """
        Initialize the TryBlocks entity.

        Args:
            database: The database instance this entity belongs to.
        """
        super().__init__(database)

    @property
    def entity_type(self) -> str:
        """
        Returns 'try_blocks' as the entity type identifier.

        Returns:
            The string "try_blocks".

        Example:
            >>> db = Database.open("binary.i64")
            >>> print(db.try_blocks.entity_type)
            try_blocks
        """
        return 'try_blocks'

    # ========================================================================
    # Query Methods
    # ========================================================================

    def get_in_range(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[TryBlock]:
        """
        Retrieve all try blocks whose ranges intersect with the specified address range.

        Try blocks are returned sorted by starting address with nesting levels
        calculated by IDA.

        Args:
            start_ea: Start of address range to query
            end_ea: End of address range to query (exclusive)

        Returns:
            Iterator of TryBlock objects in the range, sorted by start address

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open("binary.i64")
            >>> func = db.functions.get_at(0x401000)
            >>> for try_block in db.try_blocks.get_in_range(func.start_ea, func.end_ea):
            ...     print(f"Try block at {hex(try_block.start_ea)}, level {try_block.level}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        # end_ea is exclusive, so it can equal maximum_ea
        if end_ea > self.database.maximum_ea or end_ea < self.database.minimum_ea:
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        import ida_range

        range_obj = ida_range.range_t(start_ea, end_ea)
        tryblks = ida_tryblks.tryblks_t()

        count = ida_tryblks.get_tryblks(tryblks, range_obj)

        for i in range(count):
            yield _tryblock_from_ida(tryblks[i])

    def get_at(self, ea: ea_t) -> Optional[TryBlock]:
        """
        Get the innermost try block containing the specified address.

        If the address is contained in multiple nested try blocks, this
        returns the innermost (highest nesting level) block.

        Args:
            ea: Address to query

        Returns:
            TryBlock containing the address, or None if address is not in any try block

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> try_block = db.try_blocks.get_at(0x401050)
            >>> if try_block:
            ...     print(f"Address is in try block at {hex(try_block.start_ea)}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Get function containing this address
        func = ida_funcs.get_func(ea)
        if not func:
            return None

        import ida_range

        range_obj = ida_range.range_t(func.start_ea, func.end_ea)
        tryblks = ida_tryblks.tryblks_t()
        count = ida_tryblks.get_tryblks(tryblks, range_obj)

        # Find innermost try block containing ea
        innermost = None
        max_level = -1

        for i in range(count):
            tb = tryblks[i]
            # Check if ea is in any range of this try block
            for j in range(len(tb)):
                range_obj = tb[j]
                if range_obj.start_ea <= ea < range_obj.end_ea:
                    if tb.level > max_level:
                        max_level = tb.level
                        innermost = _tryblock_from_ida(tb)
                    break

        return innermost

    def is_in_try_block(self, ea: ea_t, kind: Optional[TryBlockKind] = None) -> bool:
        """
        Check if an address is within a try block, optionally filtering by kind.

        Args:
            ea: Address to check
            kind: Optional filter by TryBlockKind (CPP or SEH). If None, checks for any try block.

        Returns:
            True if address is in a try block (of specified kind), False otherwise

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> # Check if address is in any try block
            >>> if db.try_blocks.is_in_try_block(0x401050):
            ...     print("Address is in a try block")
            >>> # Check if address is specifically in C++ try block
            >>> if db.try_blocks.is_in_try_block(0x401050, TryBlockKind.CPP):
            ...     print("Address is in a C++ try block")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if kind == TryBlockKind.CPP:
            flags = ida_tryblks.TBEA_TRY
        elif kind == TryBlockKind.SEH:
            flags = ida_tryblks.TBEA_SEHTRY
        else:
            flags = ida_tryblks.TBEA_TRY | ida_tryblks.TBEA_SEHTRY

        return bool(ida_tryblks.is_ea_tryblks(ea, flags))

    def is_catch_start(self, ea: ea_t) -> bool:
        """
        Check if an address is the start of a C++ catch or cleanup block.

        Args:
            ea: Address to check

        Returns:
            True if address is start of a catch block, False otherwise

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> if db.try_blocks.is_catch_start(0x401080):
            ...     print("Address is the start of a catch handler")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return bool(ida_tryblks.is_ea_tryblks(ea, ida_tryblks.TBEA_CATCH))

    def is_seh_handler_start(self, ea: ea_t) -> bool:
        """
        Check if an address is the start of a SEH finally/except block.

        Args:
            ea: Address to check

        Returns:
            True if address is start of a SEH handler, False otherwise

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> if db.try_blocks.is_seh_handler_start(0x401090):
            ...     print("Address is the start of a SEH handler")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return bool(ida_tryblks.is_ea_tryblks(ea, ida_tryblks.TBEA_SEHLPAD))

    def is_seh_filter_start(self, ea: ea_t) -> bool:
        """
        Check if an address is the start of a SEH filter callback.

        Args:
            ea: Address to check

        Returns:
            True if address is start of a SEH filter, False otherwise

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> if db.try_blocks.is_seh_filter_start(0x401070):
            ...     print("Address is the start of a SEH filter")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return bool(ida_tryblks.is_ea_tryblks(ea, ida_tryblks.TBEA_SEHFILT))

    def find_seh_region(self, ea: ea_t) -> Optional[ea_t]:
        """
        Find the start address of the system exception handling region containing the address.

        Args:
            ea: Search address

        Returns:
            Start address of surrounding SEH try block, or None if not found

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> seh_start = db.try_blocks.find_seh_region(0x401050)
            >>> if seh_start:
            ...     print(f"Address is in SEH region starting at {hex(seh_start)}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        result = ida_tryblks.find_syseh(ea)
        return result if result != BADADDR else None

    def has_fallthrough_from_unwind(self, ea: ea_t) -> bool:
        """
        Check if there is a fall-through path into the address from an exception unwind region.

        Args:
            ea: Address to check

        Returns:
            True if there is fall-through from unwind region, False otherwise

        Raises:
            InvalidEAError: If ea is invalid

        Example:
            >>> db = Database.open("binary.i64")
            >>> if db.try_blocks.has_fallthrough_from_unwind(0x401060):
            ...     print("Address has fall-through from exception unwind")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return bool(ida_tryblks.is_ea_tryblks(ea, ida_tryblks.TBEA_FALLTHRU))

    # ========================================================================
    # Mutation Methods
    # ========================================================================

    def add(self, try_block: TryBlock) -> bool:
        """
        Add a try block to the database.

        Args:
            try_block: TryBlock object to add

        Returns:
            True if successfully added, False otherwise

        Raises:
            InvalidEAError: If any address in try block ranges is invalid
            InvalidParameterError: If try block is invalid (empty, bad order, no handlers, etc.)
            TryBlockError: If try block would intersect with inner try block

        Example:
            >>> db = Database.open("binary.i64")
            >>> try_block = TryBlock(
            ...     ranges=((0x401000, 0x401050),),
            ...     kind=TryBlockKind.CPP,
            ...     level=0,
            ...     catches=(
            ...         CatchHandler(
            ...             ranges=((0x401050, 0x401080),),
            ...             type_id=123,
            ...             obj_offset=16,
            ...             frame_register=5
            ...         ),
            ...     ),
            ...     seh_handler=None
            ... )
            >>> if db.try_blocks.add(try_block):
            ...     print("Try block added successfully")
        """
        # Validate addresses in try block
        for start, end in try_block.ranges:
            if not self.database.is_valid_ea(start):
                raise InvalidEAError(start)
            if not self.database.is_valid_ea(end):
                raise InvalidEAError(end)

        tb = _tryblock_to_ida(try_block)
        error_code = ida_tryblks.add_tryblk(tb)

        if error_code == ida_tryblks.TBERR_OK:
            return True
        else:
            # Map error codes to exceptions
            error_messages = {
                ida_tryblks.TBERR_START: 'Bad start address',
                ida_tryblks.TBERR_END: 'Bad end address',
                ida_tryblks.TBERR_ORDER: 'Bad address order',
                ida_tryblks.TBERR_EMPTY: 'Empty try block',
                ida_tryblks.TBERR_KIND: 'Illegal try block kind',
                ida_tryblks.TBERR_NO_CATCHES: 'No catch blocks',
                ida_tryblks.TBERR_INTERSECT: 'Would intersect inner try block',
            }
            msg = error_messages.get(error_code, f'Unknown error {error_code}')
            raise TryBlockError(msg)

    def delete_in_range(self, start_ea: ea_t, end_ea: ea_t) -> bool:
        """
        Delete all try blocks in the specified address range.

        Args:
            start_ea: Start of address range
            end_ea: End of address range (exclusive)

        Returns:
            True if any try blocks were deleted, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open("binary.i64")
            >>> func = db.functions.get_at(0x401000)
            >>> if db.try_blocks.delete_in_range(func.start_ea, func.end_ea):
            ...     print("Deleted try blocks from function")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        # end_ea is exclusive, so it can equal maximum_ea
        if end_ea > self.database.maximum_ea or end_ea < self.database.minimum_ea:
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        import ida_range

        range_obj = ida_range.range_t(start_ea, end_ea)

        # Check if there are any try blocks before deletion
        tryblks = ida_tryblks.tryblks_t()
        count_before = ida_tryblks.get_tryblks(tryblks, range_obj)

        # Delete try blocks
        ida_tryblks.del_tryblks(range_obj)

        # Return True if any were deleted
        return bool(count_before > 0)

    @deprecated("Use delete_in_range() instead")
    def remove_in_range(self, start_ea: ea_t, end_ea: ea_t) -> bool:
        """
        Remove all try blocks in the specified address range.

        .. deprecated::
            Use :meth:`delete_in_range` instead.

        Args:
            start_ea: Start of address range
            end_ea: End of address range (exclusive)

        Returns:
            True if any try blocks were removed, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea
        """
        return self.delete_in_range(start_ea, end_ea)
