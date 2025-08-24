from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, IntEnum

import ida_bytes
import ida_funcs
import ida_lines
import ida_nalt
import ida_xref
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional, Tuple, Union

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


# Human-readable type names mapping
_ref_types = {
    ida_xref.fl_U: 'Data_Unknown',
    ida_xref.dr_O: 'Data_Offset',
    ida_xref.dr_W: 'Data_Write',
    ida_xref.dr_R: 'Data_Read',
    ida_xref.dr_T: 'Data_Text',
    ida_xref.dr_I: 'Data_Informational',
    ida_xref.dr_S: 'Data_Symbolic',
    ida_xref.fl_CF: 'Code_Far_Call',
    ida_xref.fl_CN: 'Code_Near_Call',
    ida_xref.fl_JF: 'Code_Far_Jump',
    ida_xref.fl_JN: 'Code_Near_Jump',
    ida_xref.fl_USobsolete: 'Code_User_Specified',
    ida_xref.fl_F: 'Ordinary_Flow',
}


@dataclass
class CallReference:
    """Information about a function call reference."""

    call_address: ea_t  # Address where the call instruction is located
    caller_func: Optional[func_t]  # Function containing the call (if any)


@dataclass
class XrefInfo:
    """Enhanced cross-reference information."""

    frm: ea_t  # Source address of the xref
    to: ea_t  # Target address of the xref
    iscode: bool  # True if this is a code xref, False for data xref
    type: int  # Raw xref type value
    user: bool  # True if this is a user-defined xref

    @property
    def type_name(self) -> str:
        """Get human-readable type name."""
        return _ref_types.get(self.type, 'Unknown')


@dataclass
class CallerInfo:
    """Information about a function caller."""

    ea: ea_t  # Address of the calling instruction
    name: str  # Name of the calling function (if available)
    xref_type: int  # Type of the xref (usually CALL_NEAR or CALL_FAR)
    call_site: ea_t  # The exact address where the call occurs

    @property
    def type_name(self) -> str:
        """Get human-readable xref type name."""
        return _ref_types.get(self.xref_type, 'Unknown')


@dataclass
class StringRef:
    """Information about a string reference in a function."""

    ea: ea_t  # Address of the instruction referencing the string
    string_ea: ea_t  # Address of the string being referenced
    string_value: str  # The actual string value
    instruction: str  # Disassembled instruction text


class CodeRefType(IntEnum):
    """Code reference types."""

    UNKNOWN = ida_xref.fl_U
    """Unknown - for compatibility with old versions"""
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


class DataRefType(IntEnum):
    """Data reference types."""

    UNKNOWN = ida_xref.dr_U
    """Unknown - for compatibility with old versions"""
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




def is_call_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a call reference."""
    return xref_type in [CodeRefType.CALL_NEAR, CodeRefType.CALL_FAR]


def is_jump_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a jump reference."""
    return xref_type in [CodeRefType.JUMP_NEAR, CodeRefType.JUMP_FAR]


def is_code_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a code reference."""
    return xref_type in [
        CodeRefType.CALL_NEAR,
        CodeRefType.CALL_FAR,
        CodeRefType.JUMP_NEAR,
        CodeRefType.JUMP_FAR,
        CodeRefType.ORDINARY_FLOW,
        CodeRefType.USER_SPECIFIED,
    ]


def is_data_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data reference."""
    return xref_type in [
        DataRefType.OFFSET,
        DataRefType.WRITE,
        DataRefType.READ,
        DataRefType.TEXT,
        DataRefType.INFORMATIONAL,
        DataRefType.SYMBOLIC,
    ]


def is_read_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data read reference."""
    return xref_type == DataRefType.READ


def is_write_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is a data write reference."""
    return xref_type == DataRefType.WRITE


def is_offset_ref(xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
    """Check if xref type is an offset reference."""
    return xref_type == DataRefType.OFFSET


def get_ref_type_name(xref_type: Union[int, CodeRefType, DataRefType]) -> str:
    """Get human-readable name for xref type."""
    return _ref_types.get(xref_type, 'Unknown')


class XrefsKind(Enum):
    """
    Enumeration for IDA Xrefs types.
    """

    CODE = 'code'
    DATA = 'data'
    ALL = 'all'


@decorate_all_methods(check_db_open)
class Xrefs(DatabaseEntity):
    """
    Provides access to cross-reference (xref) analysis in the IDA database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def get_to(
        self, ea: ea_t, kind: XrefsKind = XrefsKind.ALL, flow: bool = True
    ) -> Iterator[Any]:
        """
        Creates an iterator over all xrefs pointing to a given address.

        Args:
            ea: Target effective address.
            kind: Xrefs kind (defaults to XrefsKind.ALL).
            flow: Follow normal code flow or not (defaults to True).

        Returns:
            An iterator over references to input target addresses.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xref = ida_xref.xrefblk_t()
        if kind == XrefsKind.CODE:
            if flow:
                yield from xref.crefs_to(ea)
            else:
                yield from xref.fcrefs_to(ea)

        elif kind == XrefsKind.DATA:
            yield from xref.drefs_to(ea)

        elif kind == XrefsKind.ALL:
            success = xref.first_to(ea, ida_xref.XREF_ALL)

            while success:
                yield xref
                success = xref.next_to()

    def get_from(
        self, ea: ea_t, kind: XrefsKind = XrefsKind.ALL, flow: bool = False
    ) -> Iterator[Any]:
        """
        Creates an iterator over all xrefs originating from a given address.

        Args:
            ea: Source effective address.
            kind: Xrefs kind (defaults to XrefsKind.ALL).
            flow: Follow normal code flow or not (defaults to True).

        Returns:
            An iterator over outgoing xrefs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xref = ida_xref.xrefblk_t()
        if kind == XrefsKind.CODE:
            if flow:
                yield from xref.crefs_from(ea)
            else:
                yield from xref.fcrefs_from(ea)

        elif kind == XrefsKind.DATA:
            yield from xref.drefs_from(ea)

        elif kind == XrefsKind.ALL:
            success = xref.first_from(ea, ida_xref.XREF_ALL)

            while success:
                yield xref
                success = xref.next_from()

    def get_name(self, ref: ida_xref.xrefblk_t) -> str:
        """
        Get human-readable xref type name.

        Args:
            ref: A xref block.

        Returns:
            A human-readable xref type name.
        """
        return _ref_types.get(ref.type, 'Unknown')

    def get_calls_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all call references to the specified address.

        Args:
            ea: Target effective address.

        Returns:
            An iterator over call references to the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_call_ref(xref.type):
                yield xref

    def get_calls_to_exact(self, func_ea: ea_t) -> List[CallReference]:
        """
        Get exact addresses where calls to this function occur.

        Args:
            func_ea: Function start address

        Returns:
            List of CallReference objects with call locations and caller info

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(func_ea):
            raise InvalidEAError(func_ea)

        results = []
        xb = ida_xref.xrefblk_t()
        for ref in xb.crefs_to(func_ea):
            caller_func = ida_funcs.get_func(ref)
            results.append(CallReference(call_address=ref, caller_func=caller_func))
        return results

    def get_calls_from(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all call references from the specified address.

        Args:
            ea: Source effective address.

        Returns:
            An iterator over call references from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_from(ea, XrefsKind.ALL):
            if is_call_ref(xref.type):
                yield xref

    def get_jumps_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all jump references to the specified address.

        Args:
            ea: Target effective address.

        Returns:
            An iterator over jump references to the address.
        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_jump_ref(xref.type):
                yield xref

    def get_jumps_from(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all jump references from the specified address.

        Args:
            ea: Source effective address.

        Returns:
            An iterator over jump references from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_from(ea, XrefsKind.ALL):
            if is_jump_ref(xref.type):
                yield xref

    def get_data_reads_of(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all places that read data from the specified address.

        Args:
            ea: Target effective address (the data being read).

        Returns:
            An iterator over references that read data from the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_read_ref(xref.type):
                yield xref

    def get_data_writes_to(self, ea: ea_t) -> Iterator[Any]:
        """
        Get all places that write data to the specified address.

        Args:
            ea: Target effective address (the data being written to).

        Returns:
            An iterator over references that write data to the address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for xref in self.get_to(ea, XrefsKind.ALL):
            if is_write_ref(xref.type):
                yield xref

    def is_call_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a call reference."""
        return is_call_ref(xref_type)

    def is_jump_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a jump reference."""
        return is_jump_ref(xref_type)

    def is_code_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a code reference."""
        return is_code_ref(xref_type)

    def is_data_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data reference."""
        return is_data_ref(xref_type)

    def is_read_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data read reference."""
        return is_read_ref(xref_type)

    def is_write_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is a data write reference."""
        return is_write_ref(xref_type)

    def is_offset_ref(self, xref_type: Union[int, CodeRefType, DataRefType]) -> bool:
        """Check if xref type is an offset reference."""
        return is_offset_ref(xref_type)

    def get_ref_type_name(self, xref_type: Union[int, CodeRefType, DataRefType]) -> str:
        """Get human-readable name for xref type."""
        return get_ref_type_name(xref_type)

    def get_code_refs_to(self, ea: ea_t) -> List[ea_t]:
        """
        Get all code references to an address.

        Args:
            ea: Target address

        Returns:
            List of addresses that have code references to ea

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        refs = []
        xb = ida_xref.xrefblk_t()
        for ref in xb.crefs_to(ea):
            refs.append(ref)
        return refs

    def get_code_refs_from(self, ea: ea_t) -> List[ea_t]:
        """
        Get all code references from an address.

        Args:
            ea: Source address

        Returns:
            List of addresses referenced by code at ea

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        refs = []
        xb = ida_xref.xrefblk_t()
        for ref in xb.crefs_from(ea):
            refs.append(ref)
        return refs

    def get_data_refs_to(self, ea: ea_t) -> List[ea_t]:
        """
        Get all data references to an address.

        Args:
            ea: Target address

        Returns:
            List of addresses that have data references to ea

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        refs = []
        xb = ida_xref.xrefblk_t()
        for ref in xb.drefs_to(ea):
            refs.append(ref)
        return refs

    def get_data_refs_from(self, ea: ea_t) -> List[ea_t]:
        """
        Get all data references from an address.

        Args:
            ea: Source address

        Returns:
            List of addresses referenced by data at ea

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        refs = []
        xb = ida_xref.xrefblk_t()
        for ref in xb.drefs_from(ea):
            refs.append(ref)
        return refs

    def get_xrefs_to(self, ea: ea_t, flags: int = 0) -> List[XrefInfo]:
        """
        Get enhanced cross-reference information for all xrefs to an address.

        Args:
            ea: Target address
            flags: Optional flags for xref iteration (default: 0 for all xrefs)

        Returns:
            List of XrefInfo objects with detailed xref information

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xrefs = []
        xb = ida_xref.xrefblk_t()

        # Use ida_xref.XREF_ALL if no specific flags provided
        if flags == 0:
            flags = ida_xref.XREF_ALL

        ok = xb.first_to(ea, flags)
        while ok:
            xrefs.append(XrefInfo(
                frm=xb.frm,
                to=xb.to,
                iscode=xb.iscode,
                type=xb.type,
                user=xb.user
            ))
            ok = xb.next_to()

        return xrefs

    def get_function_callers(self, func_ea: ea_t) -> List[CallerInfo]:
        """
        Get detailed information about all callers of a function.

        Args:
            func_ea: Function start address

        Returns:
            List of CallerInfo objects with caller details

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(func_ea):
            raise InvalidEAError(func_ea)

        callers = []

        # Get all xrefs to the function
        for xref in self.get_xrefs_to(func_ea):
            # Only process call references
            if is_call_ref(xref.type):
                # Get the function containing the caller
                caller_func = ida_funcs.get_func(xref.frm)
                caller_name = ""

                if caller_func:
                    # Try to get function name
                    name = ida_nalt.get_func_name(caller_func.start_ea)
                    if name:
                        caller_name = name
                    else:
                        caller_name = f"sub_{caller_func.start_ea:X}"
                else:
                    # Not in a function, use location name
                    caller_name = f"loc_{xref.frm:X}"

                callers.append(CallerInfo(
                    ea=xref.frm,
                    name=caller_name,
                    xref_type=xref.type,
                    call_site=xref.frm
                ))

        return callers

    def get_xrefs_from(self, ea: ea_t, flags: int = 0) -> List[XrefInfo]:
        """
        Get enhanced cross-reference information for all xrefs from an address.

        Args:
            ea: Source address
            flags: Optional flags for xref iteration (default: 0 for all xrefs)

        Returns:
            List of XrefInfo objects with detailed xref information

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        xrefs = []
        xb = ida_xref.xrefblk_t()

        # Use ida_xref.XREF_ALL if no specific flags provided
        if flags == 0:
            flags = ida_xref.XREF_ALL

        ok = xb.first_from(ea, flags)
        while ok:
            xrefs.append(XrefInfo(
                frm=xb.frm,
                to=xb.to,
                iscode=xb.iscode,
                type=xb.type,
                user=xb.user
            ))
            ok = xb.next_from()

        return xrefs

    def get_string_refs_in_function(self, func_ea: ea_t) -> List[StringRef]:
        """
        Get all string references within a function.

        Args:
            func_ea: Function start address

        Returns:
            List of StringRef objects with string reference details

        Raises:
            InvalidEAError: If the effective address is invalid
        """
        if not self.database.is_valid_ea(func_ea):
            raise InvalidEAError(func_ea)

        # Get function boundaries
        func = ida_funcs.get_func(func_ea)
        if not func:
            return []

        string_refs = []

        # Iterate through the function
        ea = func.start_ea
        while ea < func.end_ea:
            # Get all data references from this address
            for ref_ea in self.get_data_refs_from(ea):
                # Check if the target is a string
                flags = ida_bytes.get_flags(ref_ea)
                if ida_bytes.is_strlit(flags):
                    # Get the string value
                    str_type = ida_bytes.get_str_type(ref_ea)
                    if str_type is not None:
                        max_len = ida_bytes.get_max_strlit_length(ref_ea, str_type)
                        string_bytes = ida_bytes.get_strlit_contents(ref_ea, max_len, str_type)
                        if string_bytes:
                            try:
                                string_value = string_bytes.decode('utf-8', errors='replace')
                            except:
                                string_value = str(string_bytes)

                            # Get the instruction text
                            instruction = ida_lines.generate_disasm_line(ea, 0)
                            if instruction:
                                # Remove color codes
                                instruction = ida_lines.tag_remove(instruction)

                            string_refs.append(StringRef(
                                ea=ea,
                                string_ea=ref_ea,
                                string_value=string_value,
                                instruction=instruction or ""
                            ))

            # Move to next instruction
            next_ea = ida_bytes.next_head(ea, func.end_ea)
            if next_ea == BADADDR:
                break
            ea = next_ea

        return string_refs
