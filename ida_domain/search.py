from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Iterator, Optional

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

__all__ = ['Search', 'SearchDirection', 'AccessType']


class SearchDirection(IntEnum):
    """Direction for search operations."""

    UP = 0
    """Search towards lower addresses"""
    DOWN = 1
    """Search towards higher addresses"""


class AccessType(IntEnum):
    """Type of register access to search for."""

    READ = ida_search.SEARCH_USE  # 0x200
    """Search for register read access"""
    WRITE = ida_search.SEARCH_DEF  # 0x400
    """Search for register write access"""


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
        self, ea: ea_t, what: str, direction: str = "forward"
    ) -> Optional[ea_t]:
        """
        Find next address of specified type (LLM-friendly unified search).

        This is an LLM-friendly unified interface for finding addresses. Instead
        of remembering multiple method names (next_undefined, next_code, etc.),
        LLMs can use this single method with a string parameter.

        Args:
            ea: Starting address for search
            what: Type of address to find. One of:
                - "undefined": Find next undefined/unexplored byte
                - "defined": Find next defined item (instruction or data)
                - "code": Find next code address
                - "data": Find next data address
                - "code_outside_function": Find next orphaned code
            direction: Search direction. Either:
                - "forward": Search towards higher addresses (default)
                - "backward": Search towards lower addresses

        Returns:
            Address of next match, or None if not found

        Raises:
            InvalidEAError: If address is invalid
            InvalidParameterError: If what or direction is not a valid option

        Example:
            >>> db = Database.open_current()
            >>> # Find next code
            >>> ea = db.search.find_next(0x401000, "code")
            >>> # Find previous data
            >>> ea = db.search.find_next(0x401000, "data", direction="backward")

        Note:
            This method provides a simpler API for LLMs that don't need to
            remember the specific method names for each search type.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Map direction string to enum
        direction_lower = direction.lower()
        if direction_lower == "forward":
            search_dir = SearchDirection.DOWN
        elif direction_lower == "backward":
            search_dir = SearchDirection.UP
        else:
            raise InvalidParameterError(
                'direction', direction, 'must be one of: "forward", "backward"'
            )

        # Dispatch to appropriate method based on what
        what_lower = what.lower()
        if what_lower == "undefined":
            return self.next_undefined(ea, direction=search_dir)
        elif what_lower == "defined":
            return self.next_defined(ea, direction=search_dir)
        elif what_lower == "code":
            return self.next_code(ea, direction=search_dir)
        elif what_lower == "data":
            return self.next_data(ea, direction=search_dir)
        elif what_lower == "code_outside_function":
            return self.next_code_outside_function(ea, direction=search_dir)
        else:
            raise InvalidParameterError(
                'what', what,
                'must be one of: "undefined", "defined", "code", "data", '
                '"code_outside_function"'
            )

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

    # ============================================================================
    # REGISTER ACCESS SEARCHES
    # ============================================================================

    def next_register_access(
        self,
        register_name: str,
        start_ea: ea_t,
        end_ea: Optional[ea_t] = None,
        access_type: AccessType = AccessType.READ,
        direction: SearchDirection = SearchDirection.DOWN,
    ) -> Optional[ea_t]:
        """
        Find the next access to a specific register.

        Args:
            register_name: Name of register to search for (e.g., "eax", "rdi")
            start_ea: Starting address for search
            end_ea: Ending address (default: None means unlimited)
            access_type: Type of access to find (READ or WRITE)
            direction: Search direction (default: DOWN)

        Returns:
            Address of register access, or None if not found

        Raises:
            InvalidEAError: If start_ea is invalid
            InvalidParameterError: If register_name is empty

        Note:
            Does not follow control flow (scans linearly).
            Only detects direct register references.
            Ignores function calls and system traps.

        Example:
            >>> db = Database.open_current()
            >>> ea = db.search.next_register_access("eax", 0x401000,
            ...                                     access_type=AccessType.READ)
            >>> if ea:
            ...     insn = db.instructions.get_at(ea)
            ...     print(f"EAX read at {hex(ea)}: {insn.mnemonic}")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not register_name:
            raise InvalidParameterError('register_name', register_name, 'cannot be empty')

        if end_ea is None:
            end_ea = BADADDR

        sflag = ida_search.SEARCH_NEXT
        if direction == SearchDirection.DOWN:
            sflag |= ida_search.SEARCH_DOWN
        else:
            sflag |= ida_search.SEARCH_UP

        # Add access type flag
        sflag |= access_type.value

        # Call legacy API - requires reg_access_t output parameter
        # Note: reg_access_t is a SWIG-generated class that may not be accessible
        # We create a simple object to satisfy the SWIG wrapper
        class RegAccess:
            pass

        out = RegAccess()
        ea = ida_search.find_reg_access(out, start_ea, end_ea, register_name, sflag)

        return ea if ea != BADADDR else None

    def all_register_accesses(
        self,
        register_name: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
        access_type: AccessType = AccessType.READ,
    ) -> Iterator[ea_t]:
        """
        Iterate over all accesses to a specific register.

        Args:
            register_name: Name of register to search for
            start_ea: Start of range (default: database minimum)
            end_ea: End of range (default: database maximum)
            access_type: Type of access to find (READ or WRITE)

        Yields:
            Addresses where register is accessed

        Raises:
            InvalidEAError: If start_ea or end_ea is invalid
            InvalidParameterError: If register_name is empty or start_ea >= end_ea

        Example:
            >>> db = Database.open_current()
            >>> for ea in db.search.all_register_accesses("rsp",
            ...                                            access_type=AccessType.READ):
            ...     print(f"RSP read at {hex(ea)}")
            ...     break
        """
        if not register_name:
            raise InvalidParameterError('register_name', register_name, 'cannot be empty')

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
            # Build flags
            sflag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT | access_type.value

            # Find next access - requires reg_access_t output parameter
            out = ida_search.reg_access_t()
            ea = ida_search.find_reg_access(out, ea, end_ea, register_name, sflag)

            if ea == BADADDR or ea >= end_ea:
                break

            yield ea
