"""
Switch statement analysis and management entity for IDA Domain API.

Provides comprehensive access to switch statement operations within the IDA database,
including switch information retrieval, creation, modification, and jump table analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from typing import TYPE_CHECKING, Optional

import ida_bytes
import ida_nalt
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

__all__ = ['Switches', 'SwitchInfo', 'SwitchFlags']


# ============================================================================
# Enumerations
# ============================================================================


class SwitchFlags(IntFlag):
    """
    Switch information flags from ida_nalt module.

    These flags control the interpretation and behavior of switch statements,
    including table formats, element sizes, and addressing modes.
    """

    SPARSE = 0x00000001
    """Sparse switch (value table present)"""
    V32 = 0x00000002
    """32-bit values in value table"""
    J32 = 0x00000004
    """32-bit jump offsets"""
    VSPLIT = 0x00000008
    """Value table is split (32-bit values only)"""
    USER = 0x00000010
    """User-specified switch"""
    DEF_IN_TBL = 0x00000020
    """Default case is an entry in the jump table"""
    JMP_INV = 0x00000040
    """Jump table is inverted (reversed order)"""
    SHIFT_MASK = 0x00000180
    """Mask for shift value (bits 7-8)"""
    ELBASE = 0x00000200
    """Element base address is present"""
    JSIZE = 0x00000400
    """Jump offset expansion bit"""
    VSIZE = 0x00000800
    """Value table element size expansion bit"""
    SEPARATE = 0x00001000
    """Create array of individual elements"""
    SIGNED = 0x00002000
    """Jump table entries are signed"""
    CUSTOM = 0x00004000
    """Custom jump table"""
    INDIRECT = 0x00010000
    """Value table elements are indices into jump table"""
    SUBTRACT = 0x00020000
    """Table values are subtracted from elbase"""
    HXNOLOWCASE = 0x00040000
    """Lowcase should not be used by decompiler (internal)"""
    STDTBL = 0x00080000
    """Custom jump table with standard formatting"""
    DEFRET = 0x00100000
    """Return in default case (defjump==BADADDR)"""
    SELFREL = 0x00200000
    """Jump address is relative to element, not ELBASE"""
    JMPINSN = 0x00400000
    """Jump table entries are instructions"""
    VERSION = 0x00800000
    """Structure contains VERSION member"""
    DEFAULT = 0x00000000
    """Default value (no special flags)"""


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class SwitchInfo:
    """
    Complete switch statement information wrapping IDA's switch_info_t structure.

    This dataclass represents all properties of a switch statement including
    jump tables, value tables, case handling, and configuration flags.
    """

    flags: int
    """Switch flags (see SwitchFlags enum)"""
    ncases: int
    """Number of cases (excluding default)"""
    jumps: ea_t
    """Jump table start address"""
    values: Optional[ea_t]
    """Values table address (for sparse switches, when SWI_SPARSE is set)"""
    lowcase: int
    """Lowest case value (for non-sparse switches)"""
    defjump: ea_t
    """Default jump address (BADADDR if no default case)"""
    startea: ea_t
    """Start of the switch idiom (typically the comparison instruction)"""
    jcases: int
    """Number of entries in jump table (for indirect switches, when SWI_INDIRECT is set)"""
    ind_lowcase: int
    """Indirect lowcase value (for indirect switches)"""
    elbase: ea_t
    """Element base address (when SWI_ELBASE is set)"""
    regnum: int
    """Register number containing switch expression (-1 if unknown)"""
    regdtype: int = 0
    """Size of switch expression register"""
    custom: int = 0
    """Information for custom tables"""
    version: int = 2
    """Version (default = 2)"""
    expr_ea: ea_t = BADADDR
    """Address where expression is in regnum"""

    @property
    def is_sparse(self) -> bool:
        """True if switch uses value table (sparse switch)."""
        return (self.flags & SwitchFlags.SPARSE) != 0

    @property
    def is_indirect(self) -> bool:
        """True if indirect switch (value table elements are indices into jump table)."""
        return (self.flags & SwitchFlags.INDIRECT) != 0

    @property
    def has_default(self) -> bool:
        """True if switch has a default case."""
        return bool(self.defjump != BADADDR)

    @property
    def jtable_element_size(self) -> int:
        """Size of jump table elements (1, 2, 4, or 8 bytes)."""
        code = self.flags & (SwitchFlags.J32 | SwitchFlags.JSIZE)
        if code == 0:
            return 2
        elif code == SwitchFlags.J32:
            return 4
        elif code == SwitchFlags.JSIZE:
            return 1
        else:  # Both J32 and JSIZE
            return 8

    @property
    def vtable_element_size(self) -> int:
        """Size of value table elements (1, 2, 4, or 8 bytes)."""
        code = self.flags & (SwitchFlags.V32 | SwitchFlags.VSIZE)
        if code == 0:
            return 2
        elif code == SwitchFlags.V32:
            return 4
        elif code == SwitchFlags.VSIZE:
            return 1
        else:  # Both V32 and VSIZE
            return 8

    @property
    def shift(self) -> int:
        """Shift amount for jump target calculation (0-3)."""
        return (self.flags & SwitchFlags.SHIFT_MASK) >> 7


# ============================================================================
# Switches Entity
# ============================================================================


@decorate_all_methods(check_db_open)
class Switches(DatabaseEntity):
    """
    Provides comprehensive access to switch statement analysis and manipulation.

    This entity wraps the ida_nalt module's switch-related functionality, providing
    a Pythonic interface for managing switch statement information including jump
    tables, value tables, case handling, and parent relationships.
    """

    def __init__(self, database: Database):
        """
        Initialize the Switches entity.

        Args:
            database: Reference to the Database instance
        """
        super().__init__(database)

    # ========================================================================
    # Query Methods
    # ========================================================================

    def get_at(self, ea: ea_t) -> Optional[SwitchInfo]:
        """
        Retrieves switch information at the specified address.

        Args:
            ea: Address where switch info is stored (typically the jump instruction)

        Returns:
            SwitchInfo object if switch exists at address, None otherwise

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> switch = db.switches.get_at(0x401000)
            >>> if switch:
            ...     print(f"Found switch with {switch.ncases} cases")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Get switch info from IDA database
        # Returns switch_info_t object on success, None on failure
        si = ida_nalt.get_switch_info(ea)

        if si is None:
            return None

        # Map switch_info_t fields to SwitchInfo dataclass
        return SwitchInfo(
            flags=si.flags,
            ncases=si.ncases,
            jumps=si.jumps,
            values=si.values if si.is_sparse() else None,
            lowcase=si.lowcase if not si.is_sparse() else 0,
            defjump=si.defjump,
            startea=si.startea,
            jcases=si.jcases,
            ind_lowcase=si.ind_lowcase,
            elbase=si.elbase,
            regnum=si.regnum,
            regdtype=getattr(si, 'regdtype', 0),
            custom=getattr(si, 'custom', 0),
            version=getattr(si, 'version', 2),
            expr_ea=getattr(si, 'expr_ea', BADADDR),
        )

    def exists_at(self, ea: ea_t) -> bool:
        """
        Checks whether switch information exists at the specified address.

        Args:
            ea: Address to check

        Returns:
            True if switch exists, False otherwise

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.switches.exists_at(0x401000):
            ...     switch = db.switches.get_at(0x401000)
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return self.get_at(ea) is not None

    # ========================================================================
    # Creation and Deletion
    # ========================================================================

    def create(self, ea: ea_t, switch_info: SwitchInfo) -> bool:
        """
        Creates switch statement information at the specified address.

        Args:
            ea: Address where switch info should be stored
            switch_info: Complete switch information to store

        Returns:
            True if switch was successfully created, False otherwise

        Raises:
            InvalidEAError: If the effective address is invalid
            InvalidParameterError: If switch_info contains invalid data

        Example:
            >>> db = Database.open_current()
            >>> switch_info = SwitchInfo(
            ...     flags=SwitchFlags.DEFAULT,
            ...     ncases=5,
            ...     jumps=0x405000,
            ...     values=None,
            ...     lowcase=0,
            ...     defjump=0x401100,
            ...     startea=0x401000,
            ...     jcases=0,
            ...     ind_lowcase=0,
            ...     elbase=0,
            ...     regnum=-1
            ... )
            >>> success = db.switches.create(0x401000, switch_info)
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if switch_info.ncases < 0:
            raise InvalidParameterError(
                'ncases', switch_info.ncases, 'Number of cases must be non-negative'
            )

        # Create ida_nalt.switch_info_t structure
        si = self._switch_info_to_ida_struct(switch_info)

        # Set switch info in IDA database
        try:
            ida_nalt.set_switch_info(ea, si)
            return True
        except Exception:
            return False

    def delete(self, ea: ea_t) -> bool:
        """
        Deletes switch statement information at the specified address.

        Args:
            ea: Address of switch info to delete

        Returns:
            True if switch was successfully deleted, False if no switch existed

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.switches.delete(0x401000):
            ...     print("Switch deleted")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Check if switch exists before attempting deletion
        if not self.exists_at(ea):
            return False

        # Delete switch info from IDA database
        ida_nalt.del_switch_info(ea)
        return True

    @deprecated("Use delete() instead")
    def remove(self, ea: ea_t) -> bool:
        """
        Remove switch statement information at the specified address.

        .. deprecated::
            Use :meth:`delete` instead.

        Args:
            ea: Address of switch info to delete

        Returns:
            True if switch was successfully deleted, False if no switch existed

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.switches.remove(0x401000):
            ...     print("Switch deleted")
        """
        return self.delete(ea)

    # ========================================================================
    # Update Operations
    # ========================================================================

    def update(self, ea: ea_t, switch_info: SwitchInfo) -> bool:
        """
        Updates existing switch statement information at the specified address.

        This is equivalent to create() - it will create the switch if it doesn't
        exist or update if it does.

        Args:
            ea: Address where switch info is stored
            switch_info: Updated switch information

        Returns:
            True if switch was successfully updated, False otherwise

        Raises:
            InvalidEAError: If the effective address is invalid
            InvalidParameterError: If switch_info contains invalid data

        Example:
            >>> db = Database.open_current()
            >>> switch = db.switches.get_at(0x401000)
            >>> if switch:
            ...     switch.ncases = 10
            ...     db.switches.update(0x401000, switch)
        """
        # set_switch_info handles both creation and update
        return self.create(ea, switch_info)

    # ========================================================================
    # Parent Relationships
    # ========================================================================

    def get_parent(self, ea: ea_t) -> Optional[ea_t]:
        """
        Gets the address holding switch information for a jump target.

        When multiple locations (e.g., case targets) need to reference the same
        switch information, IDA stores the switch info at one location (the parent)
        and other locations store a reference to the parent address.

        Args:
            ea: Address of a jump target or case

        Returns:
            Address of the parent switch info, or None if no parent relationship exists

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> parent_ea = db.switches.get_parent(0x401050)
            >>> if parent_ea:
            ...     print(f"This case references switch at 0x{parent_ea:x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        parent = ida_nalt.get_switch_parent(ea)

        # get_switch_parent returns BADADDR when no parent relationship exists
        if parent == BADADDR:
            return None

        return parent

    def set_parent(self, ea: ea_t, parent_ea: ea_t) -> bool:
        """
        Sets the parent switch address for a jump target or case.

        Args:
            ea: Address of the jump target or case
            parent_ea: Address where the switch info is stored

        Returns:
            True if parent relationship was successfully set, False otherwise

        Raises:
            InvalidEAError: If either address is invalid

        Example:
            >>> db = Database.open_current()
            >>> switch_ea = 0x401000
            >>> case_ea = 0x401050
            >>> if db.switches.set_parent(case_ea, switch_ea):
            ...     print(f"Case at 0x{case_ea:x} now references switch at 0x{switch_ea:x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not self.database.is_valid_ea(parent_ea):
            raise InvalidEAError(parent_ea)

        try:
            ida_nalt.set_switch_parent(ea, parent_ea)
            return True
        except Exception:
            return False

    def delete_parent(self, ea: ea_t) -> bool:
        """
        Delete the switch parent at the specified address.

        Args:
            ea: The effective address.

        Returns:
            True if deleted successfully.

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.switches.delete_parent(0x401050):
            ...     print("Parent relationship removed")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Check if parent relationship exists
        if self.get_parent(ea) is None:
            return False

        # Delete parent relationship
        ida_nalt.del_switch_parent(ea)
        return True

    @deprecated("Use delete_parent() instead")
    def remove_parent(self, ea: ea_t) -> bool:
        """Deprecated: Use delete_parent() instead."""
        return self.delete_parent(ea)

    # ========================================================================
    # Switch Analysis
    # ========================================================================

    def get_jump_table_addresses(self, switch_info: SwitchInfo) -> list[ea_t]:
        """
        Computes all jump target addresses from the switch's jump table.

        Args:
            switch_info: Switch information object

        Returns:
            List of effective addresses for all jump targets

        Example:
            >>> db = Database.open_current()
            >>> switch = db.switches.get_at(0x401000)
            >>> if switch:
            ...     targets = db.switches.get_jump_table_addresses(switch)
            ...     for i, target in enumerate(targets):
            ...         print(f"Case {i}: 0x{target:x}")
        """
        addresses: list[ea_t] = []

        # Determine jump table size
        jtable_size = switch_info.jcases if switch_info.is_indirect else switch_info.ncases
        element_size = switch_info.jtable_element_size

        # Read jump table entries
        for i in range(jtable_size):
            # Calculate address of this jump table entry
            entry_ea = switch_info.jumps + (i * element_size)

            # Read offset from jump table based on element size
            offset = 0
            if element_size == 1:
                offset = ida_bytes.get_byte(entry_ea)
                if switch_info.flags & SwitchFlags.SIGNED and (offset & 0x80):
                    offset |= 0xFFFFFFFFFFFFFF00
            elif element_size == 2:
                offset = ida_bytes.get_word(entry_ea)
                if switch_info.flags & SwitchFlags.SIGNED and (offset & 0x8000):
                    offset |= 0xFFFFFFFFFFFF0000
            elif element_size == 4:
                offset = ida_bytes.get_dword(entry_ea)
                if switch_info.flags & SwitchFlags.SIGNED and (offset & 0x80000000):
                    offset |= 0xFFFFFFFF00000000
            elif element_size == 8:
                offset = ida_bytes.get_qword(entry_ea)
            else:
                continue

            # Calculate target address
            shift = switch_info.shift
            base = switch_info.elbase if (switch_info.flags & SwitchFlags.ELBASE) else 0

            if switch_info.flags & SwitchFlags.SUBTRACT:
                target = base - (offset << shift)
            else:
                target = base + (offset << shift)

            addresses.append(target)

        return addresses

    def get_case_values(self, switch_info: SwitchInfo) -> list[int]:
        """
        Gets the case values for a switch statement.

        For dense switches, computes values based on lowcase and ncases.
        For sparse switches, reads values from the value table.

        Args:
            switch_info: Switch information object

        Returns:
            List of case values

        Example:
            >>> db = Database.open_current()
            >>> switch = db.switches.get_at(0x401000)
            >>> if switch:
            ...     values = db.switches.get_case_values(switch)
            ...     targets = db.switches.get_jump_table_addresses(switch)
            ...     for value, target in zip(values, targets):
            ...         print(f"case {value}: goto 0x{target:x}")
        """
        values: list[int] = []

        if switch_info.is_sparse:
            # Sparse switch: read values from value table
            if switch_info.values is None:
                return []

            element_size = switch_info.vtable_element_size

            for i in range(switch_info.ncases):
                entry_ea = switch_info.values + (i * element_size)

                # Read value based on element size
                value = 0
                if element_size == 1:
                    value = ida_bytes.get_byte(entry_ea)
                elif element_size == 2:
                    value = ida_bytes.get_word(entry_ea)
                elif element_size == 4:
                    value = ida_bytes.get_dword(entry_ea)
                elif element_size == 8:
                    value = ida_bytes.get_qword(entry_ea)
                else:
                    continue

                # Handle signed values if needed
                if switch_info.flags & SwitchFlags.SIGNED:
                    if element_size == 1 and (value & 0x80):
                        value |= 0xFFFFFFFFFFFFFF00
                    elif element_size == 2 and (value & 0x8000):
                        value |= 0xFFFFFFFFFFFF0000
                    elif element_size == 4 and (value & 0x80000000):
                        value |= 0xFFFFFFFF00000000

                values.append(value)
        else:
            # Dense switch: compute values from lowcase
            lowcase = switch_info.lowcase
            for i in range(switch_info.ncases):
                values.append(lowcase + i)

        return values

    def get_case_count(self, ea: ea_t) -> int:
        """
        Gets the number of cases for the switch at the specified address.

        Args:
            ea: Address of the switch

        Returns:
            Number of cases (0 if no switch exists)

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> db = Database.open_current()
            >>> case_count = db.switches.get_case_count(0x401000)
            >>> print(f"Switch has {case_count} cases")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        switch_info = self.get_at(ea)
        return switch_info.ncases if switch_info else 0

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _switch_info_to_ida_struct(self, switch_info: SwitchInfo) -> ida_nalt.switch_info_t:
        """
        Converts SwitchInfo dataclass to ida_nalt.switch_info_t structure.

        Args:
            switch_info: SwitchInfo dataclass instance

        Returns:
            Populated switch_info_t structure ready for IDA API
        """
        si = ida_nalt.switch_info_t()

        # Map all fields from SwitchInfo to switch_info_t
        si.flags = switch_info.flags
        si.ncases = switch_info.ncases
        si.jumps = switch_info.jumps

        # Handle union field: values (sparse) or lowcase (dense)
        if switch_info.is_sparse and switch_info.values is not None:
            si.values = switch_info.values
        else:
            si.lowcase = switch_info.lowcase

        si.defjump = switch_info.defjump
        si.startea = switch_info.startea
        si.jcases = switch_info.jcases
        si.ind_lowcase = switch_info.ind_lowcase
        si.elbase = switch_info.elbase
        si.regnum = switch_info.regnum

        # Optional attributes (may not exist in all IDA versions)
        if hasattr(si, 'regdtype'):
            si.regdtype = switch_info.regdtype
        if hasattr(si, 'custom'):
            si.custom = switch_info.custom
        if hasattr(si, 'version'):
            si.version = switch_info.version
        if hasattr(si, 'expr_ea'):
            si.expr_ea = switch_info.expr_ea

        return si
