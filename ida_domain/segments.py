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


class SegmentType(IntEnum):
    """Segment type enumeration."""

    NORM = ida_segment.SEG_NORM  # Unknown type, no assumptions
    XTRN = ida_segment.SEG_XTRN  # Segment with 'extern' definitions
    CODE = ida_segment.SEG_CODE  # Code segment
    DATA = ida_segment.SEG_DATA  # Data segment
    IMP = ida_segment.SEG_IMP  # Java: implementation segment
    GRP = ida_segment.SEG_GRP  # Group of segments
    NULL = ida_segment.SEG_NULL  # Zero-length segment
    UNDF = ida_segment.SEG_UNDF  # Undefined segment type
    BSS = ida_segment.SEG_BSS  # Uninitialized segment
    ABSSYM = ida_segment.SEG_ABSSYM  # Segment with absolute symbol definitions
    COMM = ida_segment.SEG_COMM  # Segment with communal definitions
    IMEM = ida_segment.SEG_IMEM  # Internal processor memory & SFR (8051)


class MoveSegmentResult(IntEnum):
    """Result codes for move/rebase operations."""

    OK = ida_segment.MOVE_SEGM_OK  # Success
    PARAM = ida_segment.MOVE_SEGM_PARAM  # Segment doesn't exist
    ROOM = ida_segment.MOVE_SEGM_ROOM  # Not enough free room at target
    IDP = ida_segment.MOVE_SEGM_IDP  # IDP module forbids moving
    CHUNK = ida_segment.MOVE_SEGM_CHUNK  # Too many chunks defined
    LOADER = ida_segment.MOVE_SEGM_LOADER  # Segment moved but loader complained
    ODD = ida_segment.MOVE_SEGM_ODD  # Can't move by odd number of bytes
    ORPHAN = ida_segment.MOVE_SEGM_ORPHAN  # Orphan bytes hinder movement
    DEBUG = ida_segment.MOVE_SEGM_DEBUG  # Debugger segments can't be moved
    SOURCEFILES = ida_segment.MOVE_SEGM_SOURCEFILES  # Source file ranges hinder movement
    MAPPING = ida_segment.MOVE_SEGM_MAPPING  # Memory mapping ranges hinder movement
    INVAL = ida_segment.MOVE_SEGM_INVAL  # Invalid argument


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

    def get_by_index(self, index: int) -> Optional[segment_t]:
        """
        Get segment by its index (0-based).

        Args:
            index: Segment index (0 to len(segments)-1)

        Returns:
            segment_t if index is valid, None otherwise

        Example:
            >>> first_seg = db.segments.get_by_index(0)
            >>> if first_seg:
            ...     print(f"First segment: {db.segments.get_name(first_seg)}")
        """
        if index < 0 or index >= ida_segment.get_segm_qty():
            return None
        return ida_segment.getnseg(index)

    def get_index(self, segment: segment_t) -> int:
        """
        Get the index of a segment.

        Args:
            segment: The segment to find the index of

        Returns:
            Index of the segment (0-based), or -1 if not found

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> if seg:
            ...     idx = db.segments.get_index(seg)
            ...     print(f".text is segment #{idx}")
        """
        if not segment:
            return -1
        return ida_segment.get_segm_num(segment.start_ea)

    def get_first(self) -> Optional[segment_t]:
        """
        Get the first segment in the database.

        Returns:
            First segment_t, or None if no segments exist

        Example:
            >>> first = db.segments.get_first()
            >>> if first:
            ...     print(f"First segment: {db.segments.get_name(first)}")
        """
        return ida_segment.get_first_seg()

    def get_last(self) -> Optional[segment_t]:
        """
        Get the last segment in the database.

        Returns:
            Last segment_t, or None if no segments exist

        Example:
            >>> last = db.segments.get_last()
            >>> if last:
            ...     print(f"Last segment: {db.segments.get_name(last)}")
        """
        return ida_segment.get_last_seg()

    def get_next(self, segment: segment_t) -> Optional[segment_t]:
        """
        Get the next segment after the given segment.

        Args:
            segment: Current segment

        Returns:
            Next segment_t, or None if this is the last segment

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> next_seg = db.segments.get_next(seg)
            >>> if next_seg:
            ...     print(f"After .text: {db.segments.get_name(next_seg)}")
        """
        if not segment:
            return None
        return ida_segment.get_next_seg(segment.end_ea)

    def get_previous(self, segment: segment_t) -> Optional[segment_t]:
        """
        Get the previous segment before the given segment.

        Args:
            segment: Current segment

        Returns:
            Previous segment_t, or None if this is the first segment

        Example:
            >>> seg = db.segments.get_by_name(".data")
            >>> prev_seg = db.segments.get_previous(seg)
            >>> if prev_seg:
            ...     print(f"Before .data: {db.segments.get_name(prev_seg)}")
        """
        if not segment:
            return None
        return ida_segment.get_prev_seg(segment.start_ea)

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

    def get_type(self, segment: segment_t) -> SegmentType:
        """
        Get segment type (SEG_NORM, SEG_CODE, SEG_DATA, etc.).

        Args:
            segment: The segment to query

        Returns:
            SegmentType enum value

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> seg_type = db.segments.get_type(seg)
            >>> if seg_type == SegmentType.CODE:
            ...     print("This is a code segment")
        """
        return SegmentType(segment.type)

    def get_paragraph(self, segment: segment_t) -> ea_t:
        """
        Get segment base paragraph.

        Segment base paragraph determines the offsets in the segment.
        For 16-bit programs, this corresponds to the segment register value.

        Args:
            segment: The segment to query

        Returns:
            Segment base paragraph value

        Example:
            >>> seg = db.segments.get_at(0x401000)
            >>> para = db.segments.get_paragraph(seg)
            >>> print(f"Paragraph: {para:x}")
        """
        return ida_segment.get_segm_para(segment)

    def get_base(self, segment: segment_t) -> ea_t:
        """
        Get segment base linear address.

        The virtual address of the first byte of the segment is (start_ea - base_address).

        Args:
            segment: The segment to query

        Returns:
            Segment base linear address

        Example:
            >>> seg = db.segments.get_at(0x401000)
            >>> base = db.segments.get_base(seg)
            >>> virtual_addr = seg.start_ea - base
            >>> print(f"First virtual address: {virtual_addr:x}")
        """
        return ida_segment.get_segm_base(segment)

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

    def set_class(self, segment: segment_t, sclass: Union[str, PredefinedClass]) -> bool:
        """
        Set segment class.

        If segment type is SEG_NORM and class is a predefined name,
        the type is automatically changed (e.g., "CODE" → SEG_CODE).

        Args:
            segment: The segment to modify
            sclass: Segment class (str or PredefinedClass enum)

        Returns:
            True if successful, False otherwise

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> success = db.segments.set_class(seg, PredefinedClass.CODE)
        """
        if isinstance(sclass, PredefinedClass):
            sclass_str = sclass.value
        else:
            sclass_str = sclass or ''

        return ida_segment.set_segm_class(segment, sclass_str) != 0

    def set_start(self, segment: segment_t, new_start: ea_t, keep_data: bool = True) -> bool:
        """
        Set segment start address.

        The previous segment is trimmed to allow expansion.
        The kernel may delete the previous segment if necessary.

        Args:
            segment: The segment to modify
            new_start: New start address (must be higher than segment base)
            keep_data: If False, may destroy instructions/data going out of scope

        Returns:
            True if successful, False otherwise

        Raises:
            InvalidEAError: If new_start is invalid

        Example:
            >>> seg = db.segments.get_by_name(".data")
            >>> success = db.segments.set_start(seg, seg.start_ea - 0x100)
        """
        if not self.database.is_valid_ea(new_start, strict_check=False):
            raise InvalidEAError(new_start)

        flags = ida_segment.SEGMOD_KEEP if keep_data else ida_segment.SEGMOD_KILL
        return ida_segment.set_segm_start(segment.start_ea, new_start, flags)

    def set_end(self, segment: segment_t, new_end: ea_t, keep_data: bool = True) -> bool:
        """
        Set segment end address.

        The next segment is shrunk to allow expansion.
        The kernel may delete the next segment if necessary.

        Args:
            segment: The segment to modify
            new_end: New end address
            keep_data: If False, may destroy instructions/data going out of scope

        Returns:
            True if successful, False otherwise

        Raises:
            InvalidEAError: If new_end is invalid

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> success = db.segments.set_end(seg, seg.end_ea + 0x1000)
        """
        if not self.database.is_valid_ea(new_end, strict_check=False):
            raise InvalidEAError(new_end)

        flags = ida_segment.SEGMOD_KEEP if keep_data else ida_segment.SEGMOD_KILL
        return ida_segment.set_segm_end(segment.start_ea, new_end, flags)

    def delete(self, segment: segment_t, keep_data: bool = False) -> bool:
        """
        Delete a segment.

        Args:
            segment: The segment to delete
            keep_data: If True, preserve instructions/data; if False, disable addresses

        Returns:
            True if successful, False if segment deletion failed

        Example:
            >>> seg = db.segments.get_by_name(".debug")
            >>> if db.segments.delete(seg):
            ...     print("Debug segment removed")
        """
        flags = ida_segment.SEGMOD_KEEP if keep_data else ida_segment.SEGMOD_KILL
        return ida_segment.del_segm(segment.start_ea, flags)

    def update(self, segment: segment_t) -> bool:
        """
        Update segment information after modification.

        Important: Must call this after directly modifying segment_t fields.
        Not all fields can be modified directly - use specific setter methods where available.

        Args:
            segment: The segment that was modified

        Returns:
            True if successful, False otherwise

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> seg.perm = SegmentPermissions.READ | SegmentPermissions.EXEC
            >>> db.segments.update(seg)  # Commit the changes
        """
        return ida_segment.update_segm(segment)

    def move(
        self, segment: segment_t, to: ea_t, fix_relocations: bool = True
    ) -> MoveSegmentResult:
        """
        Move segment to a new address.

        This moves all information to the new address and fixes up address-sensitive data.
        The total effect equals reloading the segment at the target address.

        Args:
            segment: The segment to move
            to: New segment start address
            fix_relocations: If True, call loader to fix relocations

        Returns:
            MoveSegmentResult indicating success or error reason

        Example:
            >>> seg = db.segments.get_by_name(".data")
            >>> result = db.segments.move(seg, 0x500000)
            >>> if result == MoveSegmentResult.OK:
            ...     print(f"Moved segment to {seg.start_ea:x}")
            >>> else:
            ...     print(f"Move failed: {result}")
        """
        flags = 0 if fix_relocations else ida_segment.MSF_NOFIX
        result = ida_segment.move_segm(segment, to, flags)
        return MoveSegmentResult(result)

    def rebase(self, delta: int, fix_once: bool = True) -> MoveSegmentResult:
        """
        Rebase the entire program by delta bytes.

        Args:
            delta: Number of bytes to move the program (can be negative)
            fix_once: If True, call loader only once with special method

        Returns:
            MoveSegmentResult indicating success or error reason

        Example:
            >>> # Rebase program from 0x400000 to 0x10000000
            >>> result = db.segments.rebase(0x10000000 - 0x400000)
            >>> if result == MoveSegmentResult.OK:
            ...     print("Program rebased successfully")
        """
        flags = ida_segment.MSF_FIXONCE if fix_once else 0
        result = ida_segment.rebase_program(delta, flags)
        return MoveSegmentResult(result)

    def set_visible(self, segment: segment_t, visible: bool) -> None:
        """
        Set segment visibility in the disassembly view.

        Args:
            segment: The segment to modify
            visible: True to show, False to hide

        Example:
            >>> seg = db.segments.get_by_name(".debug")
            >>> db.segments.set_visible(seg, False)  # Hide debug segment
        """
        ida_segment.set_visible_segm(segment, visible)

    def is_visible(self, segment: segment_t) -> bool:
        """
        Check if segment is visible.

        Args:
            segment: The segment to check

        Returns:
            True if visible, False if hidden

        Example:
            >>> seg = db.segments.get_by_name(".text")
            >>> if db.segments.is_visible(seg):
            ...     print("Segment is visible in disassembly")
        """
        return ida_segment.is_visible_segm(segment)
