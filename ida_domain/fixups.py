"""
Fixup (relocation) management entity for IDA Domain API.

Provides comprehensive access to fixup operations within the IDA database,
including fixup information retrieval, creation, modification, and analysis
of relocation records.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Iterator, Optional, cast

import ida_fixup
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

__all__ = ['Fixups', 'FixupInfo', 'FixupType']


# ============================================================================
# Enumerations
# ============================================================================


class FixupType(IntEnum):
    """
    Fixup types enumeration.

    Maps to ida_fixup.FIXUP_* constants. These specify how addresses should
    be adjusted when loading a binary at different base addresses.
    """

    OFF8 = 13
    """8-bit offset"""
    OFF16 = 1
    """16-bit offset"""
    SEG16 = 2
    """16-bit segment base (selector)"""
    PTR16 = 3
    """32-bit long pointer (16-bit base:16-bit offset)"""
    OFF32 = 4
    """32-bit offset (most common in 32-bit binaries)"""
    PTR32 = 5
    """48-bit pointer (16-bit base:32-bit offset)"""
    HI8 = 6
    """High 8 bits of 16-bit offset"""
    HI16 = 7
    """High 16 bits of 32-bit offset"""
    LOW8 = 8
    """Low 8 bits of 16-bit offset"""
    LOW16 = 9
    """Low 16 bits of 32-bit offset"""
    OFF64 = 12
    """64-bit offset (most common in 64-bit binaries)"""
    OFF8S = 14
    """8-bit signed offset"""
    OFF16S = 15
    """16-bit signed offset"""
    OFF32S = 16
    """32-bit signed offset"""
    CUSTOM = 0x8000
    """Start of custom fixup types (processor-specific)"""


# ============================================================================
# Data Classes
# ============================================================================


@dataclass(frozen=True)
class FixupInfo:
    """
    Immutable fixup information.

    Represents a single fixup (relocation) record in the database. Fixups
    are relocation records that specify how to adjust addresses when loading
    a binary at different base addresses.
    """

    address: ea_t
    """Source address where fixup is located"""
    type: FixupType
    """Type of fixup (OFF32, OFF64, etc.)"""
    target_offset: ea_t
    """Target address that fixup points to"""
    displacement: int
    """Additional displacement from target"""
    is_relative: bool
    """True if fixup is relative to a base address"""
    is_extdef: bool
    """True if target is external symbol"""
    is_unused: bool
    """True if fixup is ignored by IDA"""
    was_created: bool
    """True if fixup was artificially created (not in input file)"""

    @property
    def target(self) -> ea_t:
        """
        Get final target address (target_offset + displacement).

        Returns:
            The computed target address after applying displacement.
        """
        return self.target_offset + self.displacement


# ============================================================================
# Entity
# ============================================================================


@decorate_all_methods(check_db_open)
class Fixups(DatabaseEntity):
    """
    Manages fixup (relocation) information in the IDA database.

    Fixups are relocation records created by loaders to handle
    position-independent code, DLL imports, and segment references.
    They specify how addresses should be adjusted when loading at
    different base addresses.
    """

    def __init__(self, database: Database) -> None:
        """
        Initialize the Fixups entity.

        Args:
            database: Reference to the active IDA database.
        """
        super().__init__(database)

    # ========================================================================
    # Properties
    # ========================================================================

    @property
    def count(self) -> int:
        """
        Get the total number of fixups in the database.

        Returns:
            Total count of fixup records.

        Example:
            >>> db = Database.open("sample.exe")
            >>> print(f"Total fixups: {db.fixups.count}")
        """
        count = 0
        ea = ida_fixup.get_first_fixup_ea()
        while ea != BADADDR:
            count += 1
            ea = ida_fixup.get_next_fixup_ea(ea)
        return count

    # ========================================================================
    # Query Methods
    # ========================================================================

    def get_at(self, address: ea_t) -> Optional[FixupInfo]:
        """
        Get fixup information at a specific address.

        Args:
            address: Address to query.

        Returns:
            FixupInfo if fixup exists at address, None otherwise.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> fixup = db.fixups.get_at(0x401000)
            >>> if fixup:
            ...     print(f"Fixup type: {fixup.type.name}")
            ...     print(f"Target: {fixup.target:#x}")
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Get fixup data
        fd = ida_fixup.fixup_data_t()
        if not ida_fixup.get_fixup(fd, address):
            return None

        # Convert to FixupInfo
        return self._fixup_data_to_info(address, fd)

    def has_fixup(self, address: ea_t) -> bool:
        """
        Check if a fixup exists at the given address.

        Args:
            address: Address to check.

        Returns:
            True if fixup exists, False otherwise.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> if db.fixups.has_fixup(0x401000):
            ...     print("Address has fixup")
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        return cast(bool, ida_fixup.exists_fixup(address))

    def get_all(self) -> Iterator[FixupInfo]:
        """
        Get all fixups in the database.

        Yields:
            FixupInfo objects for all fixups in the database.

        Example:
            >>> # Count fixups by type
            >>> from collections import Counter
            >>> fixup_types = Counter(f.type for f in db.fixups.get_all())
            >>> for ftype, count in fixup_types.most_common():
            ...     print(f"{ftype.name}: {count}")
        """
        ea = ida_fixup.get_first_fixup_ea()
        while ea != BADADDR:
            # Get fixup data
            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                yield self._fixup_data_to_info(ea, fd)

            # Move to next
            ea = ida_fixup.get_next_fixup_ea(ea)

    def get_between(self, start_address: ea_t, end_address: ea_t) -> Iterator[FixupInfo]:
        """
        Get all fixups within an address range.

        Args:
            start_address: Start of range (inclusive).
            end_address: End of range (exclusive).

        Yields:
            FixupInfo objects in the specified range.

        Raises:
            InvalidEAError: If addresses are invalid.
            InvalidParameterError: If start >= end.

        Example:
            >>> # Get fixups in .text section
            >>> text = db.segments.get_by_name(".text")
            >>> if text:
            ...     text_fixups = list(db.fixups.get_between(text.start_ea, text.end_ea))
            ...     print(f"Found {len(text_fixups)} fixups in .text")
        """
        if not self.database.is_valid_ea(start_address, strict_check=False):
            raise InvalidEAError(start_address)
        if not self.database.is_valid_ea(end_address, strict_check=False):
            raise InvalidEAError(end_address)
        if start_address >= end_address:
            raise InvalidParameterError(
                'start_address', start_address, 'must be less than end_address'
            )

        # Iterate and filter
        ea = ida_fixup.get_first_fixup_ea()
        while ea != BADADDR:
            # Check if in range
            if start_address <= ea < end_address:
                fd = ida_fixup.fixup_data_t()
                if ida_fixup.get_fixup(fd, ea):
                    yield self._fixup_data_to_info(ea, fd)

            # Move to next
            ea = ida_fixup.get_next_fixup_ea(ea)

    def contains_fixups(self, start_address: ea_t, size: int) -> bool:
        """
        Check if an address range contains any fixups.

        Args:
            start_address: Start of range.
            size: Size of range in bytes.

        Returns:
            True if range contains at least one fixup, False otherwise.

        Raises:
            InvalidEAError: If address is invalid.
            InvalidParameterError: If size <= 0.

        Example:
            >>> # Check if function contains fixups
            >>> func = db.functions.get_at(0x401000)
            >>> if func and db.fixups.contains_fixups(func.start_ea, func.size()):
            ...     print("Function contains fixups (possibly calls imports)")
        """
        if not self.database.is_valid_ea(start_address):
            raise InvalidEAError(start_address)
        if size <= 0:
            raise InvalidParameterError('size', size, 'must be positive')

        return cast(bool, ida_fixup.contains_fixups(start_address, size))

    def get_description(self, address: ea_t) -> str:
        """
        Get a human-readable description of the fixup at address.

        Args:
            address: Address of fixup.

        Returns:
            Text description of fixup, or empty string if no fixup exists.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> desc = db.fixups.get_description(0x401000)
            >>> print(f"Fixup description: {desc}")
            # Example output: "offset __imp_MessageBoxA"
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Get fixup data
        fd = ida_fixup.fixup_data_t()
        if not ida_fixup.get_fixup(fd, address):
            return ''

        # Get description
        desc = ida_fixup.get_fixup_desc(address, fd)
        return desc if desc is not None else ''

    # ========================================================================
    # Mutation Methods
    # ========================================================================

    def add(
        self,
        address: ea_t,
        fixup_type: FixupType,
        target_offset: ea_t,
        displacement: int = 0,
        is_relative: bool = False,
        is_extdef: bool = True,
    ) -> bool:
        """
        Add a new fixup at the specified address.

        Args:
            address: Source address where fixup is located.
            fixup_type: Type of fixup (from FixupType enum).
            target_offset: Target address that fixup points to.
            displacement: Additional displacement from target (default: 0).
            is_relative: True if fixup is relative to base (default: False).
            is_extdef: True if target is external definition (default: True).

        Returns:
            True if fixup was successfully added, False otherwise.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> # Manually add a fixup (advanced use case)
            >>> success = db.fixups.add(
            ...     address=0x401000,
            ...     fixup_type=FixupType.OFF32,
            ...     target_offset=0x405000,
            ...     is_extdef=True
            ... )
            >>> if success:
            ...     print("Fixup added successfully")
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Create fixup data
        fd = ida_fixup.fixup_data_t()
        fd.set_type(int(fixup_type))
        fd.off = target_offset
        fd.displacement = displacement

        # Set flags
        if is_relative:
            fd.set_base(0)  # Set relative base

        if is_extdef:
            fd.set_extdef()
        else:
            fd.clr_extdef()

        # Set fixup
        try:
            ida_fixup.set_fixup(address, fd)
            return True
        except Exception:
            return False

    def remove(self, address: ea_t) -> bool:
        """
        Remove the fixup at the specified address.

        Args:
            address: Address where fixup is located.

        Returns:
            True if fixup was removed, False if no fixup existed.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> # Remove a fixup
            >>> if db.fixups.remove(0x401000):
            ...     print("Fixup removed")
            >>> else:
            ...     print("No fixup at address")
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Check if fixup exists
        if not ida_fixup.exists_fixup(address):
            return False

        # Delete fixup
        try:
            ida_fixup.del_fixup(address)
            return True
        except Exception:
            return False

    def patch_value(self, address: ea_t) -> bool:
        """
        Apply the fixup at address to the database bytes.

        This calculates the fixup target and writes the appropriate
        value to memory at the fixup location.

        Args:
            address: Address of fixup to apply.

        Returns:
            True if fixup was successfully applied, False otherwise.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> # Apply a fixup (recalculate and patch memory)
            >>> if db.fixups.patch_value(0x401000):
            ...     print("Fixup applied to memory")

        Note:
            This is an advanced operation. Most fixups are automatically
            applied by loaders.
        """
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Get fixup data
        fd = ida_fixup.fixup_data_t()
        if not ida_fixup.get_fixup(fd, address):
            return False

        # Patch fixup value
        return cast(bool, ida_fixup.patch_fixup_value(address, fd))

    # ========================================================================
    # Collection Protocol
    # ========================================================================

    def __iter__(self) -> Iterator[FixupInfo]:
        """
        Iterate over all fixups in the database.

        Yields:
            FixupInfo objects for all fixups.

        Example:
            >>> # Iterate all fixups
            >>> for fixup in db.fixups:
            ...     print(f"{fixup.address:#x}: {fixup.type.name} -> {fixup.target:#x}")
        """
        return self.get_all()

    def __len__(self) -> int:
        """
        Get the total number of fixups in the database.

        Returns:
            Total fixup count.

        Example:
            >>> print(f"Database has {len(db.fixups)} fixups")
        """
        return self.count

    # ========================================================================
    # Internal Helper Methods
    # ========================================================================

    def _fixup_data_to_info(self, address: ea_t, fd: ida_fixup.fixup_data_t) -> FixupInfo:
        """
        Convert fixup_data_t to FixupInfo dataclass.

        Args:
            address: Address where fixup is located.
            fd: Fixup data from ida_fixup.

        Returns:
            FixupInfo dataclass with all fields populated.
        """
        return FixupInfo(
            address=address,
            type=FixupType(fd.get_type()),
            target_offset=fd.off,
            displacement=fd.displacement,
            is_relative=fd.has_base(),
            is_extdef=fd.is_extdef(),
            is_unused=fd.is_unused(),
            was_created=fd.was_created(),
        )
