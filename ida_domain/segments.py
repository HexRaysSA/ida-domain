from __future__ import annotations

import logging
from enum import Enum, IntEnum, IntFlag
from typing import Union

import ida_bytes
import ida_segment
from ida_idaapi import ea_t
from ida_segment import segment_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class AddSegmentFlags(IntFlag):
    NONE = 0x0000  # No flag
    NOSREG = 0x0001  # Set all default segment register values to BADSEL
    OR_DIE = 0x0002  # qexit() if can't add a segment
    NOTRUNC = 0x0004  # Don't truncate the new segment at the beginning of the next segment
    QUIET = 0x0008  # Silent mode, no "Adding segment..." in the messages window
    FILLGAP = 0x0010  # Fill gap between new segment and previous one
    SPARSE = 0x0020  # Use sparse storage method for the new ranges
    NOAA = 0x0040  # Do not mark new segment for auto-analysis
    IDBENC = 0x0080  # 'name' and 'sclass' are given in the IDB encoding

class PredefinedClass(Enum):
    CODE = "CODE"  # SEG_CODE
    DATA = "DATA"  # SEG_DATA
    CONST = "CONST"  # SEG_DATA
    STACK = "STACK"  # SEG_BSS
    BSS = "BSS"  # SEG_BSS
    XTRN = "XTRN"  # SEG_XTRN
    COMM = "COMM"  # SEG_COMM
    ABS = "ABS"  # SEG_ABSSYM

class SegmentPermissions(IntFlag):
    NONE  = 0
    EXEC  = ida_segment.SEGPERM_EXEC
    WRITE = ida_segment.SEGPERM_WRITE
    READ  = ida_segment.SEGPERM_READ
    ALL   = ida_segment.SEGPERM_MAXVAL

class AddressingMode(IntEnum):
    BIT16 = 0  # 16-bit segment
    BIT32 = 1  # 32-bit segment
    BIT64 = 2  # 64-bit segment

@decorate_all_methods(check_db_open)
class Segments(DatabaseEntity):
    """
    Provides access to segment-related operations in the IDA database.

    Can be used to iterate over all segments in the opened database.

    Args:
        database: Reference to the active IDA database.

    Note:
        Since this class does not manage the lifetime of IDA kernel objects (segment_t*),
        it is recommended to use these pointers within a limited scope. Obtain the pointer,
        perform the necessary operations, and avoid retaining references beyond the
        immediate context to prevent potential issues with object invalidation.
    """
    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[segment_t]:
        return self.get_all()

    def get_at(self, ea: ea_t) -> Optional[segment_t]:
        """
        Retrieves the segment that contains the given address.

        Args:
            ea: The effective address to search.

        Returns:
            A pointer to the containing segment, or None if none found.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_segment.getseg(ea)

    def get_name(self, segment: segment_t) -> str:
        """
        Retrieves the name of the given segment.

        Args:
            segment: Pointer to the segment.

        Returns:
            The segment name as a string, or an empty string if unavailable.
        """
        return ida_segment.get_segm_name(segment)

    def set_name(self, segment: segment_t, name: str) -> bool:
        """
        Renames a segment.

        Args:
            segment: Pointer to the segment to rename.
            name: The new name to assign to the segment.

        Returns:
            True if the rename operation succeeded, False otherwise.
        """
        return ida_segment.set_segm_name(segment, name)

    def __len__(self) -> int:
        """
        Returns the number of segments in the database.

        Returns:
            The total count of segments.
        """
        return ida_segment.get_segm_qty()

    def get_all(self) -> Iterator[segment_t]:
        """
        Retrieves an iterator over all segments in the database.

        Returns:
            A generator yielding all segments in the database.
        """
        for current_index in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(current_index)
            if seg:
                yield seg

    def add(self, seg_para: ea_t, start_ea: ea_t, end_ea: ea_t, seg_name: Optional[str] = None, 
            seg_class: Optional[Union[str, PredefinedClass]] = None, 
            flags: AddSegmentFlags = AddSegmentFlags.NONE) -> Optional[segment_t]:
        """
        Adds a new segment to the IDA database.

        Args:
            seg_para: Segment base paragraph.
            start_ea: Start address of the segment (linear EA).
            end_ea: End address of the segment (exclusive).
            seg_name: Name of new segment (optional).
            seg_class: Class of the segment (optional). Accepts str or PredefinedClass.
            flags: Add segment flags (AddSegmentFlags).

        Returns:
            The created segment_t on success, or None on failure.
        """

        # Sanit check for ea valid range
        if start_ea >= end_ea:
            raise ValueError("start_ea must be strictly less than end_ea")

        # Convert PredefinedClass enum to string if needed, normalize None -> ""
        if isinstance(seg_class, PredefinedClass):
            seg_class_str = seg_class.value
        else:
            seg_class_str = seg_class or ""

        seg_name_str = seg_name or ""

        # Allowing developers to pass ints or AddSegmentFlags
        if not isinstance(flags, AddSegmentFlags):
            flags = AddSegmentFlags(int(flags))

        # Call IDA's add_segm (returns True on success)
        ok = ida_segment.add_segm(seg_para, start_ea, end_ea, seg_name_str, seg_class_str, flags)
        if not ok:
            # failed to add segment
            return None

        # Prefer to get the segment by its start EA (safer than get_last_seg)
        seg = ida_segment.getseg(start_ea) # Better approach to retrieve added segment
        if seg is None:
            # fallback: try get_last_seg (should rarely be needed)
            seg = ida_segment.get_last_seg()

        return seg

    def append(self, seg_para: ea_t, seg_size: ea_t, seg_name: Optional[str] = None, 
        seg_class: Optional[Union[str, PredefinedClass]] = None, 
        flags: AddSegmentFlags = AddSegmentFlags.NONE) -> Optional[segment_t]:
        """
        Append a new segment directly after the last segment in the database.

        Args:
            seg_para: Segment base paragraph (selector/paragraph as used by IDA).
            seg_size: Desired size in bytes for the new segment (must be > 0).
            seg_name: Optional name for the new segment.
            seg_class: Optional class for the new segment (str or PredefinedClass).
            flags: Add segment flags (AddSegmentFlags).

        Returns:
            The created segment_t on success, or None on failure.

        Raises:
            ValueError: If seg_size is <= 0.
            RuntimeError: If there are no existing segments to append after.
        """
        # Sanit check for size
        if seg_size is None or seg_size <= 0:
            raise ValueError("seg_size must be a positive integer/ea")

        # Find last segment
        last_seg = ida_segment.get_last_seg()
        if last_seg is None: # Theres one last segment ?
            # No segments exist in database: require explicit addresses via add.
            raise RuntimeError(
                "No existing segments found, cannot append. "
                "Use add(...) with explicit addresses."
            )

        start_ea = last_seg.end_ea
        end_ea = start_ea + seg_size

        # Delegate to the canonical add(...) method (it normalizes name/class/flags)
        return self.add(seg_para, start_ea, end_ea, seg_name, seg_class, flags)

    def set_permissions(self, segment: segment_t, perms: SegmentPermissions) -> bool:
        """
        Set the segment permissions exactly to `perms` (overwrites existing flags).
        """
        seg = ida_segment.getseg(segment.start_ea)
        if not seg:
            return False

        try:
            seg.perm = int(perms)
            return True
        except Exception:
            return False

    def add_permissions(self, segment: segment_t, perms: SegmentPermissions) -> bool:
        """
        OR the given permission bits into the existing segment permissions.
        """
        seg = ida_segment.getseg(segment.start_ea)
        if not seg:
            return False

        seg.perm |= int(perms)
        return True

    def remove_permissions(self, segment: segment_t, perms: SegmentPermissions) -> bool:
        """
        Clear the given permission bits from the existing segment permissions.
        """
        seg = ida_segment.getseg(segment.start_ea)
        if not seg:
            return False

        seg.perm &= ~int(perms)

        return True

    def set_addressing_mode(self, segment: segment_t, mode: AddressingMode) -> bool:
        """
        Sets the segment addressing mode (16-bit, 32-bit, or 64-bit).

        Args:
            segment: The target segment object.
            mode: AddressingMode enum value.

        Returns:
            True if successful, False otherwise.
        """
        try:
            return ida_segment.set_segm_addressing(segment, int(mode))
        except Exception:
            return False