from __future__ import annotations

import logging
from enum import Enum, IntEnum, IntFlag
from typing import Union

import ida_segment
import idautils
from ida_idaapi import ea_t
from ida_segment import segment_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class AddSegmentFlags(IntFlag):
    NONE = 0  # No flag
    NOSREG = ida_segment.ADDSEG_NOSREG  # Set all default segment register values to BADSEL
    OR_DIE = ida_segment.ADDSEG_OR_DIE  # qexit() if can't add a segment
    NOTRUNC = ida_segment.ADDSEG_NOTRUNC  # Don't truncate the new segment on next segment start
    QUIET = ida_segment.ADDSEG_QUIET  # Silent mode, no "Adding segment..." in the messages window
    FILLGAP = ida_segment.ADDSEG_FILLGAP  # Fill gap between new segment and previous one
    SPARSE = ida_segment.ADDSEG_SPARSE  # Use sparse storage method for the new ranges
    NOAA = ida_segment.ADDSEG_NOAA  # Do not mark new segment for auto-analysis
    IDBENC = ida_segment.ADDSEG_IDBENC  # 'name' and 'sclass' are given in the IDB encoding


class PredefinedClass(Enum):
    CODE = 'CODE'  # SEG_CODE
    DATA = 'DATA'  # SEG_DATA
    CONST = 'CONST'  # SEG_DATA
    STACK = 'STACK'  # SEG_BSS
    BSS = 'BSS'  # SEG_BSS
    XTRN = 'XTRN'  # SEG_XTRN
    COMM = 'COMM'  # SEG_COMM
    ABS = 'ABS'  # SEG_ABSSYM


class SegmentPermissions(IntFlag):
    NONE = 0
    EXEC = ida_segment.SEGPERM_EXEC
    WRITE = ida_segment.SEGPERM_WRITE
    READ = ida_segment.SEGPERM_READ
    ALL = ida_segment.SEGPERM_MAXVAL


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
            A segment_t object, or None if none found.

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
            segment: The segment to get the name from.

        Returns:
            The segment name as a string, or an empty string if unavailable.
        """
        return ida_segment.get_segm_name(segment)

    def set_name(self, segment: segment_t, name: str) -> bool:
        """
        Renames a segment.

        Args:
            segment: The segment to rename.
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
            A generator yielding all segment_t objects in the database.
        """
        for current_index in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(current_index)
            if seg:
                yield seg

    def get_by_name(self, name: str) -> Optional[segment_t]:
        """Find segment by name.

        Args:
            name: Segment name to search for

        Returns:
            segment_t if found, None otherwise
        """
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg and ida_segment.get_segm_name(seg) == name:
                return seg
        return None

    def add(
        self,
        seg_para: ea_t,
        start_ea: ea_t,
        end_ea: ea_t,
        seg_name: Optional[str] = None,
        seg_class: Optional[Union[str, PredefinedClass]] = None,
        flags: AddSegmentFlags = AddSegmentFlags.NONE,
    ) -> Optional[segment_t]:
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
            raise ValueError('start_ea must be strictly less than end_ea')

        # Convert PredefinedClass enum to string if needed, normalize None -> ""
        if isinstance(seg_class, PredefinedClass):
            seg_class_str = seg_class.value
        else:
            seg_class_str = seg_class or ''

        seg_name_str = seg_name or ''

        # Allowing developers to pass ints or AddSegmentFlags
        if not isinstance(flags, AddSegmentFlags):
            flags = AddSegmentFlags(int(flags))

        # Call IDA's add_segm (returns True on success)
        ok = ida_segment.add_segm(seg_para, start_ea, end_ea, seg_name_str, seg_class_str, flags)
        if not ok:
            # failed to add segment
            return None

        # Prefer to get the segment by its start EA (safer than get_last_seg)
        seg = ida_segment.getseg(start_ea)  # Better approach to retrieve added segment
        if seg is None:
            # fallback: try get_last_seg (should rarely be needed)
            seg = ida_segment.get_last_seg()

        return seg

    def append(
        self,
        seg_para: ea_t,
        seg_size: ea_t,
        seg_name: Optional[str] = None,
        seg_class: Optional[Union[str, PredefinedClass]] = None,
        flags: AddSegmentFlags = AddSegmentFlags.NONE,
    ) -> Optional[segment_t]:
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
            raise ValueError('seg_size must be a positive integer/ea')

        # Find last segment
        last_seg = ida_segment.get_last_seg()
        if last_seg is None:  # Theres one last segment ?
            # No segments exist in database: require explicit addresses via add.
            raise RuntimeError(
                'No existing segments found, cannot append. Use add(...) with explicit addresses.'
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

        seg.perm = int(perms)
        return True

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
        return ida_segment.set_segm_addressing(segment, int(mode))

    def get_size(self, segment: segment_t) -> int:
        """Calculate segment size in bytes."""
        return segment.end_ea - segment.start_ea

    def get_bitness(self, segment: segment_t) -> int:
        """Get segment bitness (16/32/64)."""
        # Determine bitness from segment attributes
        if segment.is_64bit():
            return 64
        elif segment.is_32bit():
            return 32
        else:
            return 16

    def get_class(self, segment: segment_t) -> Optional[str]:
        """Get segment class name."""
        cls = ida_segment.get_segm_class(segment)
        return cls if cls else None

    def set_comment(self, segment: segment_t, comment: str, repeatable: bool = False) -> bool:
        """
        Set comment for segment.

        Args:
            segment: The segment to set comment for.
            comment: Comment text to set.
            repeatable: If True, creates a repeatable comment (shows at all identical operands).
                        If False, creates a non-repeatable comment (shows only at this segment).

        Returns:
            True if successful, False otherwise.
        """
        ida_segment.set_segment_cmt(segment, comment, repeatable)
        return self.get_comment(segment, repeatable) == comment

    def get_comment(self, segment: segment_t, repeatable: bool = False) -> str:
        """
        Get comment for segment.

        Args:
            segment: The segment to get comment from.
            repeatable: If True, retrieves repeatable comment (shows at all identical operands).
                        If False, retrieves non-repeatable comment (shows only at this segment).

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return ida_segment.get_segment_cmt(segment, repeatable) or ''
