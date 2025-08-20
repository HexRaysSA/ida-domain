from __future__ import annotations

import logging

import ida_bytes
import ida_segment
from ida_idaapi import ea_t
from ida_segment import segment_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


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

    def add_new(self, seg_para: ea_t, start_ea : ea_t, end_ea: ea_t, seg_name: str, seg_class: str, flags: int) -> segment_t:
        """
        Adds a new segment to the IDA database.

        Args:
            seg_para: Segment base paragraph.
            start_ea: Start address of the segment.
            end_ea: End address of the segment.
            seg_name: Name of new segment.
            seg_class: Class of the segment.
                "CODE" -> SEG_CODE
                "DATA" -> SEG_DATA
                "CONST" -> SEG_DATA
                "STACK" -> SEG_BSS
                "BSS" -> SEG_BSS
                "XTRN" -> SEG_XTRN
                "COMM" -> SEG_COMM
                "ABS" -> SEG_ABSSYM
            flags: Add segment flags(https://cpp.docs.hex-rays.com/group___a_d_d_s_e_g__.html)

        Returns:
            Return the "segment_t*" from the new added segment.
        """

        if ida_segment.add_segm(seg_para, start_ea, end_ea, seg_name, seg_class, flags):
            return ida_segment.get_last_seg() # The last segment in our database will always be the last entry.

        # Since ida_segment.add_segm returns True, we’ll just return None because we failed to add the section.
        return None

    def add_new_last(self, seg_para: ea_t, seg_size: ea_t, seg_name: str, seg_class: str, flags: int) -> segment_t:
        """
        Add a new segment directly after the last segment in the database. A hackfix  
        so that the user only needs to provide the desired size for the segment and its class name. 

        Args:
            seg_para: Segment base paragraph.
            seg_size: Desired size in bytes to store information in the new segment (segment size).
            seg_name: Name of new segment.
            seg_class: Class of the segment.
                "CODE" -> SEG_CODE
                "DATA" -> SEG_DATA
                "CONST" -> SEG_DATA
                "STACK" -> SEG_BSS
                "BSS" -> SEG_BSS
                "XTRN" -> SEG_XTRN
                "COMM" -> SEG_COMM
                "ABS" -> SEG_ABSSYM
            flags: Add segment flags(https://cpp.docs.hex-rays.com/group___a_d_d_s_e_g__.html)

        Returns:
            Return the "segment_t*" from the new added segment.
        """
        last_seg = ida_segment.get_last_seg()

        return self.add_new(seg_para, last_seg.end_ea, last_seg.end_ea + seg_size, seg_name, seg_class, flags)

    def set_segment_rwx(self, segment: segment_t) -> bool:
        """
        Configures the segment to be RWX.
        
        Args:
            segment: The target segment object.
        
        Returns:
            True if it was possible to configure the referenced segment as RWX, 
            False otherwise.
        """
        if not segment: return False

        seg = ida_segment.getseg(segment.start_ea)
        if seg:
            seg.perm = ida_segment.SEGPERM_MAXVAL
            return True

        return False

    def set_segment_addr_mode(self, segment: segment_t, mode: int) -> bool:
        """
        Sets the segment addressing mode (16-bit, 32-bit, or 64-bit).
        
        Args:
            segment: The target segment object.
            mode: The desired segment mode, one of: (16 - 16-bit, 32 - 32-bit, 64 - 64-bit).
        
        Returns:
            True if it was possible to set the segment addressing mode to the user’s choice, 
            False otherwise.
        """
        # Translating para IDA Segment mode
        if mode == 16: mode = 0 # 16-bit mode
        elif mode == 32: mode = 1 # 32-bit mode
        else: mode = 2 # 64-bit mode

        return ida_segment.set_segm_addressing(segment, mode)