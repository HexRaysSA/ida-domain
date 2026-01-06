from __future__ import annotations

from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Iterator, Optional, Union

import ida_ida
import ida_idaapi
import ida_search
from ida_idaapi import BADADDR, ea_t

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Search', 'SearchDirection', 'SearchTarget']


class SearchDirection(IntEnum):
    """Direction for search operations."""

    UP = 0
    """Search towards lower addresses"""
    DOWN = 1
    """Search towards higher addresses"""


class SearchTarget(str, Enum):
    """Type of address to find in search operations."""

    UNDEFINED = "undefined"
    """Find undefined/unexplored bytes"""

    DEFINED = "defined"
    """Find defined items (instructions or data)"""

    CODE = "code"
    """Find code addresses"""

    DATA = "data"
    """Find data addresses"""

    CODE_OUTSIDE_FUNCTION = "code_outside_function"
    """Find orphaned code (not in functions)"""


def _normalize_direction(direction: Union[SearchDirection, str]) -> SearchDirection:
    """
    Normalize direction parameter to SearchDirection enum.

    Args:
        direction: SearchDirection enum or string ("forward"/"backward")

    Returns:
        SearchDirection enum value

    Raises:
        InvalidParameterError: If direction is not valid
    """
    if isinstance(direction, SearchDirection):
        return direction

    if isinstance(direction, str):
        direction_lower = direction.lower()
        if direction_lower == "forward":
            return SearchDirection.DOWN
        elif direction_lower == "backward":
            return SearchDirection.UP
        elif direction_lower == "down":
            return SearchDirection.DOWN
        elif direction_lower == "up":
            return SearchDirection.UP

    raise InvalidParameterError(
        'direction', direction,
        'must be SearchDirection enum or one of: "forward", "backward", "up", "down"'
    )


def _normalize_target(what: Union[SearchTarget, str]) -> SearchTarget:
    """
    Normalize target parameter to SearchTarget enum.

    Args:
        what: SearchTarget enum or string value

    Returns:
        SearchTarget enum value

    Raises:
        InvalidParameterError: If what is not valid
    """
    if isinstance(what, SearchTarget):
        return what

    if isinstance(what, str):
        try:
            return SearchTarget(what.lower())
        except ValueError:
            pass

    raise InvalidParameterError(
        'what', what,
        f'must be SearchTarget enum or one of: {", ".join(e.value for e in SearchTarget)}'
    )


@decorate_all_methods(check_db_open)
class Search(DatabaseEntity):
    """
    Provides search operations for finding addresses by various criteria.

    This entity wraps the ida_search module functionality, providing methods for
    finding addresses based on analysis state, item type, problems, and register
    accesses. All methods return None for "not found" rather than raising exceptions.
    """

    def __init__(self, database: Database):
        """
        Initialize the Search entity.

        Args:
            database: Reference to the Database instance
        """
        super().__init__(database)

    # ============================================================================
    # LLM-FRIENDLY UNIFIED SEARCH
    # ============================================================================

    def find_next(
        self,
        ea: ea_t,
        what: Union[SearchTarget, str],
        direction: Union[SearchDirection, str] = SearchDirection.DOWN,
    ) -> Optional[ea_t]:
        """
        Find next address of specified type (LLM-friendly unified search).

        This is an LLM-friendly unified interface for finding addresses. Instead
        of remembering multiple method names (next_undefined, next_code, etc.),
        LLMs can use this single method with a string parameter.

        Args:
            ea: Starting address for search
            what: Type of address to find. Use SearchTarget enum:
                - SearchTarget.UNDEFINED: Find undefined/unexplored bytes
                - SearchTarget.DEFINED: Find defined items (instructions or data)
                - SearchTarget.CODE: Find code addresses
                - SearchTarget.DATA: Find data addresses
                - SearchTarget.CODE_OUTSIDE_FUNCTION: Find orphaned code
                String values also accepted for backward compatibility.
            direction: Search direction. Use SearchDirection enum:
                - SearchDirection.DOWN (or "forward"): Search towards higher addresses
                - SearchDirection.UP (or "backward"): Search towards lower addresses

        Returns:
            Address of next match, or None if not found

        Raises:
            InvalidEAError: If address is invalid
            InvalidParameterError: If what or direction is not a valid option

        Example:
            >>> db = Database.open_current()
            >>> # Find next code using enum (preferred)
            >>> ea = db.search.find_next(0x401000, SearchTarget.CODE)
            >>> # Find next code using string (backward compatible)
            >>> ea = db.search.find_next(0x401000, "code")
            >>> # Find previous data
            >>> ea = db.search.find_next(0x401000, SearchTarget.DATA, SearchDirection.UP)
            >>> ea = db.search.find_next(0x401000, "data", direction="backward")

        Note:
            This method provides a simpler API for LLMs that don't need to
            remember the specific method names for each search type.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Normalize parameters to enums
        search_dir = _normalize_direction(direction)
        target = _normalize_target(what)

        # Dispatch to appropriate method based on target
        if target == SearchTarget.UNDEFINED:
            return self.next_undefined(ea, direction=search_dir)
        elif target == SearchTarget.DEFINED:
            return self.next_defined(ea, direction=search_dir)
        elif target == SearchTarget.CODE:
            return self.next_code(ea, direction=search_dir)
        elif target == SearchTarget.DATA:
            return self.next_data(ea, direction=search_dir)
        elif target == SearchTarget.CODE_OUTSIDE_FUNCTION:
            return self.next_code_outside_function(ea, direction=search_dir)

        # Should not reach here due to _normalize_target validation
        raise InvalidParameterError(
            'what', what,
            f'must be SearchTarget enum or one of: {", ".join(e.value for e in SearchTarget)}'
        )

    def find_all(
        self, start_ea: ea_t, end_ea: ea_t, what: Union[SearchTarget, str]
    ) -> Iterator[ea_t]:
        """
        Iterate over all addresses of specified type (LLM-friendly unified iterator).

        This is an LLM-friendly unified interface for iterating over addresses.
        Instead of remembering multiple method names (all_undefined, all_code, etc.),
        LLMs can use this single method with a string parameter.

        Args:
            start_ea: Start of range
            end_ea: End of range (exclusive)
            what: Type of address to find. Use SearchTarget enum:
                - SearchTarget.UNDEFINED: Find undefined/unexplored bytes
                - SearchTarget.DEFINED: Find defined items (instructions or data)
                - SearchTarget.CODE: Find code addresses
                - SearchTarget.DATA: Find data addresses
                - SearchTarget.CODE_OUTSIDE_FUNCTION: Find orphaned code
                String values also accepted for backward compatibility.

        Yields:
            Addresses of matching type in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea or what is not a valid option

        Example:
            >>> db = Database.open_current()
            >>> # Find all code addresses using enum (preferred)
            >>> for ea in db.search.find_all(0x401000, 0x402000, SearchTarget.CODE):
            ...     print(hex(ea))
            >>> # Find all code addresses using string (backward compatible)
            >>> for ea in db.search.find_all(0x401000, 0x402000, "code"):
            ...     print(hex(ea))

        Note:
            This method provides a simpler API for LLMs that don't need to
            remember the specific method names for each search type.
        """
        # Validate inputs first
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        # Normalize target to enum
        target = _normalize_target(what)

        # Dispatch to appropriate method based on target
        if target == SearchTarget.UNDEFINED:
            yield from self.all_undefined(start_ea, end_ea)
        elif target == SearchTarget.DEFINED:
            yield from self.all_defined(start_ea, end_ea)
        elif target == SearchTarget.CODE:
            yield from self.all_code(start_ea, end_ea)
        elif target == SearchTarget.DATA:
            yield from self.all_data(start_ea, end_ea)
        elif target == SearchTarget.CODE_OUTSIDE_FUNCTION:
            yield from self.all_code_outside_functions(start_ea, end_ea)

    # ============================================================================
    # STATE-BASED SEARCHES
    # ============================================================================

    def next_undefined(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> Optional[ea_t]:
        """
        Find the next unexplored/undefined address.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Address of next undefined byte, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_undefined(0x401000)
            >>> if ea:
            ...     print(f"Undefined bytes at {hex(ea)}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        ea = ida_search.find_unknown(start_ea, sflag)
        return ea if ea != BADADDR else None

    def next_defined(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> Optional[ea_t]:
        """
        Find the next defined address (start of instruction or data).

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Address of next defined item, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_defined(0x401000)
            >>> if ea:
            ...     print(f"Defined item at {hex(ea)}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        ea = ida_search.find_defined(start_ea, sflag)
        return ea if ea != BADADDR else None

    def all_undefined(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[ea_t]:
        """
        Iterate over all undefined addresses in a range.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Undefined addresses in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_undefined():
            ...     print(f"Undefined at {hex(ea)}")
            ...     break  # Process first undefined address
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            ea = ida_search.find_unknown(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == BADADDR or ea >= end_ea:
                break
            yield ea

    def all_defined(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[ea_t]:
        """
        Iterate over all defined addresses in a range.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Defined addresses in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_defined():
            ...     item = db.bytes.get_item_at(ea)
            ...     break  # Process first defined item
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            ea = ida_search.find_defined(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == BADADDR or ea >= end_ea:
                break
            yield ea

    # ============================================================================
    # TYPE-BASED SEARCHES
    # ============================================================================

    def next_code(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> Optional[ea_t]:
        """
        Find the next code address.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Address of next code byte, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_code(0x401000)
            >>> if ea:
            ...     insn = db.instructions.get_at(ea)
            ...     print(f"Next instruction: {insn.mnemonic}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        ea = ida_search.find_code(start_ea, sflag)
        return ea if ea != BADADDR else None

    def next_data(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> Optional[ea_t]:
        """
        Find the next data address.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Address of next data byte, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_data(0x401000)
            >>> if ea:
            ...     data = db.bytes.get_bytes(ea, 4)
            ...     print(f"Data at {hex(ea)}: {data.hex()}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        ea = ida_search.find_data(start_ea, sflag)
        return ea if ea != BADADDR else None

    def next_code_outside_function(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> Optional[ea_t]:
        """
        Find the next code address that does not belong to a function.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Address of next non-function code, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_code_outside_function(0x401000)
            >>> if ea:
            ...     if db.functions.create(ea):
            ...         print(f"Created function at {hex(ea)}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        ea = ida_search.find_not_func(start_ea, sflag)
        return ea if ea != BADADDR else None

    def all_code(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[ea_t]:
        """
        Iterate over all code addresses in a range.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Code addresses in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_code():
            ...     insn = db.instructions.get_at(ea)
            ...     break  # Process first instruction
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            ea = ida_search.find_code(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == BADADDR or ea >= end_ea:
                break
            yield ea

    def all_data(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[ea_t]:
        """
        Iterate over all data addresses in a range.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Data addresses in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_data():
            ...     # Process data item
            ...     break
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            ea = ida_search.find_data(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == BADADDR or ea >= end_ea:
                break
            yield ea

    def all_code_outside_functions(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[ea_t]:
        """
        Iterate over all code addresses not belonging to functions.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Non-function code addresses in the specified range

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_code_outside_functions():
            ...     db.functions.create(ea)
            ...     break  # Create first orphaned function
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            ea = ida_search.find_not_func(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == BADADDR or ea >= end_ea:
                break
            yield ea

    # ============================================================================
    # PROBLEM-BASED SEARCHES
    # ============================================================================

    def next_error(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> tuple[Optional[ea_t], Optional[int]]:
        """
        Find the next error or problem address.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Tuple of (address, operand_number) or (None, None) if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea, opnum = db.search.next_error(0x401000)
            >>> if ea:
            ...     print(f"Error at {hex(ea)}, operand {opnum}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        result = ida_search.find_error(start_ea, sflag)

        # Handle tuple return from SWIG wrapper
        if isinstance(result, tuple):
            ea, opnum = result
            if ea != BADADDR:
                return (ea, opnum)
        elif result != BADADDR:
            # If only address returned, operand number is unknown
            return (result, 0)

        return (None, None)

    def next_untyped_operand(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> tuple[Optional[ea_t], Optional[int]]:
        """
        Find the next operand without type information.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Tuple of (address, operand_number) or (None, None) if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea, opnum = db.search.next_untyped_operand(0x401000)
            >>> if ea:
            ...     insn = db.instructions.get_at(ea)
            ...     print(f"Untyped operand at {hex(ea)}, op {opnum}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        result = ida_search.find_notype(start_ea, sflag)

        # Handle tuple return from SWIG wrapper
        if isinstance(result, tuple):
            ea, opnum = result
            if ea != BADADDR:
                return (ea, opnum)
        elif result != BADADDR:
            return (result, 0)

        return (None, None)

    def next_suspicious_operand(
        self, start_ea: ea_t, direction: SearchDirection = SearchDirection.DOWN
    ) -> tuple[Optional[ea_t], Optional[int]]:
        """
        Find the next suspicious operand.

        Args:
            start_ea: Starting address for search
            direction: Search direction (default: DOWN)

        Returns:
            Tuple of (address, operand_number) or (None, None) if not found

        Raises:
            InvalidEAError: If start_ea is invalid

        Example:
            >>> db = Database.open_current()
            >>> ea, opnum = db.search.next_suspicious_operand(0x401000)
            >>> if ea:
            ...     print(f"Suspicious operand at {hex(ea)}, op {opnum}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        result = ida_search.find_suspop(start_ea, sflag)

        # Handle tuple return from SWIG wrapper
        if isinstance(result, tuple):
            ea, opnum = result
            if ea != BADADDR:
                return (ea, opnum)
        elif result != BADADDR:
            return (result, 0)

        return (None, None)

    def all_errors(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[tuple[ea_t, int]]:
        """
        Iterate over all error addresses in a range.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Tuples of (address, operand_number)

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea, opnum in db.search.all_errors():
            ...     print(f"Error at {hex(ea)}, operand {opnum}")
            ...     break
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            result = ida_search.find_error(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)

            if isinstance(result, tuple):
                ea, opnum = result
                if ea == BADADDR or ea >= end_ea:
                    break
                yield (ea, opnum)
            else:
                ea = result
                if ea == BADADDR or ea >= end_ea:
                    break
                yield (ea, 0)

    def all_untyped_operands(
        self, start_ea: Optional[ea_t] = None, end_ea: Optional[ea_t] = None
    ) -> Iterator[tuple[ea_t, int]]:
        """
        Iterate over all operands without type information.

        Args:
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)

        Yields:
            Tuples of (address, operand_number)

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea, opnum in db.search.all_untyped_operands():
            ...     # Type recovery logic
            ...     break
        """
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        while ea < end_ea:
            result = ida_search.find_notype(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)

            if isinstance(result, tuple):
                ea, opnum = result
                if ea == BADADDR or ea >= end_ea:
                    break
                yield (ea, opnum)
            else:
                ea = result
                if ea == BADADDR or ea >= end_ea:
                    break
                yield (ea, 0)
