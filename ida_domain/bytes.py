from __future__ import annotations

import logging
import struct
from enum import IntEnum, IntFlag

import ida_bytes
import ida_hexrays
import ida_ida
import ida_lines
import ida_nalt
import ida_range
import ida_search
import idc
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, List, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .strings import StringType

if TYPE_CHECKING:
    from .database import Database


class SearchFlags(IntFlag):
    """Search flags for text and pattern searching."""

    DOWN = ida_search.SEARCH_DOWN
    """Search towards higher addresses"""
    UP = ida_search.SEARCH_UP
    """Search towards lower addresses"""
    CASE = ida_search.SEARCH_CASE
    """Case-sensitive search (case-insensitive otherwise)"""
    REGEX = ida_search.SEARCH_REGEX
    """Regular expressions in search string"""
    NOBRK = ida_search.SEARCH_NOBRK
    """Don't test if the user interrupted the search"""
    NOSHOW = ida_search.SEARCH_NOSHOW
    """Don't display the search progress/refresh screen"""
    IDENT = ida_search.SEARCH_IDENT
    """Search for an identifier (text search). It means that the
    characters before and after the match cannot be is_visible_char(). """
    BRK = ida_search.SEARCH_BRK
    """Return BADADDR if the search was cancelled."""


class ByteFlags(IntFlag):
    """Byte flag constants for flag checking operations."""

    IVL = ida_bytes.FF_IVL
    """Byte has value."""
    MS_VAL = ida_bytes.MS_VAL
    """Mask for byte value."""

    # Item State Flags
    CODE = ida_bytes.FF_CODE
    """Code?"""
    DATA = ida_bytes.FF_DATA
    """Data?"""
    TAIL = ida_bytes.FF_TAIL
    """Tail?"""
    UNK = ida_bytes.FF_UNK
    """Unknown?"""

    # Common State Information
    COMM = ida_bytes.FF_COMM
    """Has comment?"""
    REF = ida_bytes.FF_REF
    """Has references"""
    LINE = ida_bytes.FF_LINE
    """Has next or prev lines?"""
    NAME = ida_bytes.FF_NAME
    """Has name?"""
    LABL = ida_bytes.FF_LABL
    """Has dummy name?"""
    FLOW = ida_bytes.FF_FLOW
    """Exec flow from prev instruction"""
    SIGN = ida_bytes.FF_SIGN
    """Inverted sign of operands"""
    BNOT = ida_bytes.FF_BNOT
    """Bitwise negation of operands"""
    UNUSED = ida_bytes.FF_UNUSED
    """Unused bit"""

    # Data Type Flags
    BYTE = ida_bytes.FF_BYTE
    """Byte"""
    WORD = ida_bytes.FF_WORD
    """Word"""
    DWORD = ida_bytes.FF_DWORD
    """Double word"""
    QWORD = ida_bytes.FF_QWORD
    """Quad word"""
    TBYTE = ida_bytes.FF_TBYTE
    """TByte"""
    OWORD = ida_bytes.FF_OWORD
    """Octaword/XMM word (16 bytes)"""
    YWORD = ida_bytes.FF_YWORD
    """YMM word (32 bytes)"""
    ZWORD = ida_bytes.FF_ZWORD
    """ZMM word (64 bytes)"""
    FLOAT = ida_bytes.FF_FLOAT
    """Float"""
    DOUBLE = ida_bytes.FF_DOUBLE
    """Double"""
    PACKREAL = ida_bytes.FF_PACKREAL
    """Packed decimal real"""
    STRLIT = ida_bytes.FF_STRLIT
    """String literal"""
    STRUCT = ida_bytes.FF_STRUCT
    """Struct variable"""
    ALIGN = ida_bytes.FF_ALIGN
    """Alignment directive"""
    CUSTOM = ida_bytes.FF_CUSTOM
    """Custom data type"""

    # Code-Specific Flags
    FUNC = ida_bytes.FF_FUNC
    """Function start?"""
    IMMD = ida_bytes.FF_IMMD
    """Has immediate value?"""
    JUMP = ida_bytes.FF_JUMP
    """Has jump table or switch_info?"""

    # Composite Flags
    ANYNAME = ida_bytes.FF_ANYNAME
    """Has name or dummy name?"""

    # Operand Type Flags (for operand representation)
    N_VOID = ida_bytes.FF_N_VOID
    """Void (unknown)?"""
    N_NUMH = ida_bytes.FF_N_NUMH
    """Hexadecimal number?"""
    N_NUMD = ida_bytes.FF_N_NUMD
    """Decimal number?"""
    N_CHAR = ida_bytes.FF_N_CHAR
    """Char ('x')?"""
    N_SEG = ida_bytes.FF_N_SEG
    """Segment?"""
    N_OFF = ida_bytes.FF_N_OFF
    """Offset?"""
    N_NUMB = ida_bytes.FF_N_NUMB
    """Binary number?"""
    N_NUMO = ida_bytes.FF_N_NUMO
    """Octal number?"""
    N_ENUM = ida_bytes.FF_N_ENUM
    """Enumeration?"""
    N_FOP = ida_bytes.FF_N_FOP
    """Forced operand?"""
    N_STRO = ida_bytes.FF_N_STRO
    """Struct offset?"""
    N_STK = ida_bytes.FF_N_STK
    """Stack variable?"""
    N_FLT = ida_bytes.FF_N_FLT
    """Floating point number?"""
    N_CUST = ida_bytes.FF_N_CUST
    """Custom representation?"""


class NoValueError(ValueError):
    """
    Raised when a read operation is attempted on an uninitialized address.
    """

    def __init__(self, ea: ea_t) -> None:
        super().__init__(f'The effective address: 0x{ea:x} has no value')


class UnsupportedValueError(ValueError):
    """
    Raised when a read operation is attempted on a value which has an unsupported format.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Bytes(DatabaseEntity):
    """
    Handles operations related to raw data access from the IDA database.

    This class provides methods to read various data types (bytes, words, floats, etc.)
    from memory addresses in the disassembled binary.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def get_byte_at(self, ea: ea_t, allow_uninitialized: bool = False) -> int:
        """
        Retrieves a single byte (8 bits) at the specified address.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The byte value (0-255).

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return ida_bytes.get_byte(ea)

    def get_word_at(self, ea: ea_t, allow_uninitialized: bool = False) -> int:
        """
        Retrieves a word (16 bits/2 bytes) at the specified address.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The word value.

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return ida_bytes.get_word(ea)

    def get_dword_at(self, ea: ea_t, allow_uninitialized: bool = False) -> int:
        """
        Retrieves a double word (32 bits/4 bytes) at the specified address.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The dword value.

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return ida_bytes.get_dword(ea)

    def get_qword_at(self, ea: ea_t, allow_uninitialized: bool = False) -> int:
        """
        Retrieves a quad word (64 bits/8 bytes) at the specified address.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The qword value.

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return ida_bytes.get_qword(ea)

    def _read_floating_point(self, ea: ea_t, data_flags: int) -> float:
        """
        Helper method to read floating-point values from memory.

        Best-effort implementation that may fail on some architectures
        or non-standard floating-point formats.

        Args:
            ea: The effective address.
            data_flags: Data flags - float flags or double flags.

        Returns:
            The floating-point value.

        Raises:
            UnsupportedValueError: If the floating-point format is not supported

        Note:
            Only works for standard IEEE 754 32-bit and 64-bit floats.
            May not work on embedded systems or architectures with
            custom floating-point representations.
        """
        size = ida_bytes.get_data_elsize(ea, data_flags)
        if size is None or size <= 0 or size > 16:
            raise UnsupportedValueError(
                f'Unsupported float value size {size} for floating-point data at 0x{ea:x}'
            )

        # Read bytes from address
        data = ida_bytes.get_bytes(ea, size)
        if data is None or len(data) != size:
            raise UnsupportedValueError(f'Failed to read {size} bytes from address 0x{ea:x}')

        # Convert bytes to floating-point value

        # Get processor endianness
        is_little_endian = not ida_ida.inf_is_be()
        endian = '<' if is_little_endian else '>'

        if size == 4:
            # IEEE 754 single precision (32-bit float)
            return struct.unpack(f'{endian}f', data)[0]
        elif size == 8:
            # IEEE 754 double precision (64-bit double)
            return struct.unpack(f'{endian}d', data)[0]
        else:
            raise UnsupportedValueError(
                f'Unsupported float value size {size} for floating-point data at 0x{ea:x}'
            )

    def get_float_at(self, ea: ea_t, allow_uninitialized: bool = False) -> Optional[float]:
        """
        Retrieves a single-precision floating-point value at the specified address.

        Best-effort implementation that may fail on some architectures
        or non-standard floating-point formats.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The float value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
            UnsupportedValueError: If the floating-point format is not supported

        Note:
            Only works for standard IEEE 754 32-bit and 64-bit floats.
            May not work on embedded systems or architectures with
            custom floating-point representations.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return self._read_floating_point(ea, ida_bytes.float_flag())

    def get_double_at(self, ea: ea_t, allow_uninitialized: bool = False) -> Optional[float]:
        """
        Retrieves a double-precision floating-point value at the specified address.

        Best-effort implementation that may fail on some architectures
        or non-standard floating-point formats.

        Args:
            ea: The effective address.
            allow_uninitialized: If True, allows reading addresses with uninitialized values.

        Returns:
            The double value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
            NoValueError: If allow_uninitialized is False and the address contains an
            uninitialized value.
            UnsupportedValueError: If the floating-point format is not supported

        Note:
            Only works for standard IEEE 754 32-bit and 64-bit floats.
            May not work on embedded systems or architectures with
            custom floating-point representations.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not allow_uninitialized and not ida_bytes.is_loaded(ea):
            raise NoValueError(ea)

        return self._read_floating_point(ea, ida_bytes.double_flag())

    def get_disassembly_at(self, ea: ea_t, remove_tags: bool = True) -> Optional[str]:
        """
        Retrieves the disassembly text at the specified address.

        Args:
            ea: The effective address.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            The disassembly string, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        options = ida_lines.GENDSM_MULTI_LINE
        if remove_tags:
            options |= ida_lines.GENDSM_REMOVE_TAGS
        line = ida_lines.generate_disasm_line(ea, options)
        if line:
            return line
        else:
            logger.error(f'Failed to generate disassembly line at address 0x{ea:x}')
            return None

    def set_byte_at(self, ea: ea_t, value: int) -> bool:
        """
        Sets a byte value at the specified address.

        Args:
            ea: The effective address.
            value: Byte value to set.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid byte (0-0xFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFF')

        return ida_bytes.put_byte(ea, value)

    def set_word_at(self, ea: ea_t, value: int) -> None:
        """
        Sets a word (2 bytes) value at the specified address.

        Args:
            ea: The effective address.
            value: Word value to set.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid word (0-0xFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFF')

        ida_bytes.put_word(ea, value)

    def set_dword_at(self, ea: ea_t, value: int) -> None:
        """
        Sets a double word (4 bytes) value at the specified address.

        Args:
            ea: The effective address.
            value: Double word value to set.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid dword (0-0xFFFFFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFFFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFFFFFF')

        ida_bytes.put_dword(ea, value)

    def set_qword_at(self, ea: ea_t, value: int) -> None:
        """
        Sets a quad word (8 bytes) value at the specified address.

        Args:
            ea: The effective address.
            value: Quad word value to set.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid qword (0-0xFFFFFFFFFFFFFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFFFFFFFFFFFFFF')

        ida_bytes.put_qword(ea, value)

    def set_bytes_at(self, ea: ea_t, data: bytes) -> None:
        """
        Sets a sequence of bytes at the specified address.

        Args:
            ea: The effective address.
            data: Bytes to write.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If data is not bytes or is empty.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not isinstance(data, bytes):
            raise InvalidParameterError('data', type(data), 'must be bytes')

        if len(data) == 0:
            raise InvalidParameterError('data', len(data), 'cannot be empty')

        ida_bytes.put_bytes(ea, data)

    def patch_byte_at(self, ea: ea_t, value: int) -> bool:
        """
        Patch a byte of the program.
        The original value is saved and can be obtained by get_original_byte_at().

        Args:
            ea: The effective address.
            value: Byte value to patch.

        Returns:
            True if the database has been modified, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid byte (0-0xFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not (0 <= value <= 0xFF):
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFF')

        return ida_bytes.patch_byte(ea, value)

    def patch_word_at(self, ea: ea_t, value: int) -> bool:
        """
        Patch a word of the program.
        The original value is saved and can be obtained by get_original_word_at().

        Args:
            ea: The effective address.
            value: Word value to patch.

        Returns:
            True if the database has been modified, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid word (0-0xFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFF')

        return ida_bytes.patch_word(ea, value)

    def patch_dword_at(self, ea: ea_t, value: int) -> bool:
        """
        Patch a dword of the program.
        The original value is saved and can be obtained by get_original_dword_at().

        Args:
            ea: The effective address.
            value: Dword value to patch.

        Returns:
            True if the database has been modified, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid dword (0-0xFFFFFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFFFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFFFFFF')

        return ida_bytes.patch_dword(ea, value)

    def patch_qword_at(self, ea: ea_t, value: int) -> bool:
        """
        Patch a qword of the program.
        The original value is saved and can be obtained by get_original_qword_at().

        Args:
            ea: The effective address.
            value: Qword value to patch.

        Returns:
            True if the database has been modified, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If value is not a valid qword (0-0xFFFFFFFFFFFFFFFF).
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise InvalidParameterError('value', value, 'must be between 0 and 0xFFFFFFFFFFFFFFFF')

        return ida_bytes.patch_qword(ea, value)

    def patch_bytes_at(self, ea: ea_t, data: bytes) -> None:
        """
        Patch the specified number of bytes of the program.
        Original values are saved and available with get_original_bytes_at().

        Args:
            ea: The effective address.
            data: Bytes to patch.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If data is not bytes or is empty.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not isinstance(data, bytes):
            raise InvalidParameterError('data', type(data), 'must be bytes')

        if len(data) == 0:
            raise InvalidParameterError('data', len(data), 'cannot be empty')

        ida_bytes.patch_bytes(ea, data)

    def revert_byte_at(self, ea: ea_t) -> bool:
        """
        Revert patched byte to its original value.

        Args:
            ea: The effective address.

        Returns:
            True if byte was patched before and reverted now, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.revert_byte(ea)

    def get_original_byte_at(self, ea: ea_t) -> Optional[int]:
        """
        Get original byte value (that was before patching).

        Args:
            ea: The effective address.

        Returns:
            The original byte value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.get_original_byte(ea)

    def get_original_word_at(self, ea: ea_t) -> Optional[int]:
        """
        Get original word value (that was before patching).

        Args:
            ea: The effective address.

        Returns:
            The original word value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.get_original_word(ea)

    def get_original_dword_at(self, ea: ea_t) -> Optional[int]:
        """
        Get original dword value (that was before patching).

        Args:
            ea: The effective address.

        Returns:
            The original dword value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.get_original_dword(ea)

    def get_original_qword_at(self, ea: ea_t) -> Optional[int]:
        """
        Get original qword value (that was before patching).

        Args:
            ea: The effective address.

        Returns:
            The original qword value, or None if an error occurs.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.get_original_qword(ea)

    def find_bytes_between(
        self, pattern: bytes, start_ea: ea_t = None, end_ea: ea_t = None
    ) -> Optional[ea_t]:
        """
        Finds a byte pattern in memory.

        Args:
            pattern: Byte pattern to search for.
            start_ea: Search start address; defaults to database minimum ea if None
            end_ea: Search end address; defaults to database maximum ea if None

        Returns:
            Address where pattern was found, or None if not found.

        Raises:
            InvalidParameterError: If pattern or interval are invalid.
            InvalidEAError: If start_ea or end_ea are specified but invalid.
        """
        if not isinstance(pattern, bytes):
            raise InvalidParameterError('pattern', type(pattern), 'must be bytes')

        if len(pattern) == 0:
            raise InvalidParameterError('pattern', len(pattern), 'cannot be empty')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)

        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = ida_bytes.find_bytes(pattern, start_ea, None, end_ea)
        return ea if ea != BADADDR else None

    def find_text_between(
        self,
        text: str,
        start_ea: ea_t = None,
        end_ea: ea_t = None,
        flags: SearchFlags = SearchFlags.DOWN,
    ) -> Optional[ea_t]:
        """
        Finds a text string in memory.

        Args:
            text: Text to search for.
            start_ea: Search Start address; defaults to database minimum ea if None
            end_ea: Search end address; defaults to database maximum ea if None
            flags: Search flags (default: SearchFlags.DOWN).

        Returns:
            Address where text was found, or None if not found.

        Raises:
            InvalidParameterError: If text or interval are invalid.
            InvalidEAError: If start_ea or end_ea are specified but invalid.
        """
        if not isinstance(text, str):
            raise InvalidParameterError('text', type(text), 'must be string')

        if len(text) == 0:
            raise InvalidParameterError('text', len(text), 'cannot be empty')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = ida_search.find_text(start_ea, 0, 0, text, flags)
        return ea if ea != BADADDR else None

    def find_immediate_between(
        self, value: int, start_ea: ea_t = None, end_ea: ea_t = None
    ) -> Optional[ea_t]:
        """
        Finds an immediate value in instructions.

        Args:
            value: Immediate value to search for.
            start_ea: Search start address; defaults to database minimum ea if None
            end_ea: Search end address; defaults to database maximum ea if None

        Returns:
            Address where immediate was found, or None if not found.

        Raises:
            InvalidParameterError: If value is not an integer.
            InvalidEAError: If start_ea or end_ea are specified but invalid.
        """
        if not isinstance(value, int):
            raise InvalidParameterError('value', type(value), 'must be integer')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        result = ida_search.find_imm(start_ea, ida_search.SEARCH_DOWN, value)
        # find_imm returns a tuple (address, operand_number) or None
        if result and isinstance(result, tuple) and len(result) >= 1:
            ea = result[0]
            return ea if ea != BADADDR else None
        return None

    def create_byte_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates byte data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating bytes.
            count: Number of consecutive byte elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.byte_flag())
        length = element_size * count
        return ida_bytes.create_byte(ea, length, force)

    def create_word_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates word data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating words.
            count: Number of consecutive word elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.word_flag())
        length = element_size * count
        return ida_bytes.create_word(ea, length, force)

    def create_dword_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates dword data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating dwords.
            count: Number of consecutive dword elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.dword_flag())
        length = element_size * count
        return ida_bytes.create_dword(ea, length, force)

    def create_qword_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates qword data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating qwords.
            count: Number of consecutive qword elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.qword_flag())
        length = element_size * count
        return ida_bytes.create_qword(ea, length, force)

    def create_oword_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates oword data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating owords.
            count: Number of consecutive oword elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.oword_flag())
        length = element_size * count
        return ida_bytes.create_oword(ea, length, force)

    def create_yword_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates yword data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating ywords.
            count: Number of consecutive yword elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.yword_flag())
        length = element_size * count
        return ida_bytes.create_yword(ea, length, force)

    def create_zword_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates zword data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating zwords.
            count: Number of consecutive zword elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.zword_flag())
        length = element_size * count
        return ida_bytes.create_zword(ea, length, force)

    def create_tbyte_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates tbyte data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating tbytes.
            count: Number of consecutive tbyte elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.tbyte_flag())
        length = element_size * count
        return ida_bytes.create_tbyte(ea, length, force)

    def create_float_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates float data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating floats.
            count: Number of consecutive float elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.float_flag())
        length = element_size * count
        return ida_bytes.create_float(ea, length, force)

    def create_double_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates double data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating doubles.
            count: Number of consecutive double elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.double_flag())
        length = element_size * count
        return ida_bytes.create_double(ea, length, force)

    def create_packed_real_at(self, ea: ea_t, count: int = 1, force: bool = False) -> bool:
        """
        Creates packed real data items at consecutive addresses starting
        from the specified address.

        Args:
            ea: The effective address to start creating packed reals.
            count: Number of consecutive packed real elements to create.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        element_size = ida_bytes.get_data_elsize(ea, ida_bytes.packreal_flag())
        length = element_size * count
        return ida_bytes.create_packed_real(ea, length, force)

    def create_struct_at(self, ea: ea_t, count: int, tid: int, force: bool = False) -> bool:
        """
        Creates struct data items at consecutive addresses starting from the specified address.

        Args:
            ea: The effective address to start creating structs.
            count: Number of consecutive struct elements to create.
            tid: Structure type ID.
            force: Forces creation overriding an existing item if there is one.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If count is not positive or tid is invalid.

        Example:
            ```python
            tif = db.types.parse_one_declaration(None, 'struct Point {int x; int y;};')
            db.bytes.create_struct_at(ea, 1, tif.get_tid())
            ```
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if count <= 0:
            raise InvalidParameterError('count', count, 'must be positive')

        if not isinstance(tid, int) or tid < 0:
            raise InvalidParameterError('tid', tid, 'must be a non-negative integer')

        # Get struct size from type info
        element_size = idc.get_struc_size(tid)
        if element_size is None or element_size <= 0:
            raise InvalidParameterError('tid', tid, 'invalid struct type ID')

        length = element_size * count
        return ida_bytes.create_struct(ea, length, tid, force)

    def create_alignment_at(self, ea: ea_t, length: int, alignment: int) -> bool:
        """
        Create an alignment item.

        Args:
            ea: The effective address.
            length: Size of the item in bytes. 0 means to infer from alignment.
            alignment: Alignment exponent. Example: 3 means align to 8 bytes,
            0 means to infer from length.

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If length or alignment are invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if length < 0:
            raise InvalidParameterError('length', length, 'must be non-negative')

        if alignment < 0:
            raise InvalidParameterError('alignment', alignment, 'must be non-negative')

        return ida_bytes.create_align(ea, length, alignment)

    def create_string_at(
        self, ea: ea_t, length: Optional[int] = None, string_type: StringType = StringType.C
    ) -> bool:
        """
        Converts data at address to string type.

        Args:
            ea: The effective address.
            length: String length (auto-detect if None).
            string_type: String type (default: StringType.C).

        Returns:
            True if successful, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If length is specified but not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if length is not None and length <= 0:
            raise InvalidParameterError('length', length, 'must be positive when specified')

        if length is None:
            # Auto-detect string length
            return ida_bytes.create_strlit(ea, 0, string_type)
        else:
            return ida_bytes.create_strlit(ea, length, string_type)

    def get_data_size_at(self, ea: ea_t) -> int:
        """
        Gets the size of the data item at the specified address.

        Args:
            ea: The effective address.

        Returns:
            Size of the data item in bytes.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.get_item_size(ea)

    def is_value_initialized_at(self, ea: ea_t) -> bool:
        """
        Check if the value at the specified address is initialized

        Args:
            ea: The effective address.

        Returns:
            True if byte is loaded, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_loaded(ea)

    def delete_value_at(self, ea: ea_t) -> None:
        """
        Delete value from flags. The corresponding address becomes uninitialized.

        Args:
            ea: The effective address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        ida_bytes.del_value(ea)

    def is_code_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains code.

        Args:
            ea: The effective address.

        Returns:
            True if code, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_code(ida_bytes.get_flags(ea))

    def is_data_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains data.

        Args:
            ea: The effective address.

        Returns:
            True if data, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_data(ida_bytes.get_flags(ea))

    def is_tail_at(self, ea: ea_t) -> bool:
        """
        Checks if the address is part of a multi-byte data item.

        Args:
            ea: The effective address.

        Returns:
            True if tail, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_tail(ida_bytes.get_flags(ea))

    def is_not_tail_at(self, ea: ea_t) -> bool:
        """
        Checks if the address is not a tail byte.

        Args:
            ea: The effective address.

        Returns:
            True if not tail, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_not_tail(ida_bytes.get_flags(ea))

    def is_unknown_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains unknown/undefined data.

        Args:
            ea: The effective address.

        Returns:
            True if unknown, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_unknown(ida_bytes.get_flags(ea))

    def is_head_at(self, ea: ea_t) -> bool:
        """
        Checks if the address is the start of a data item.

        Args:
            ea: The effective address.

        Returns:
            True if head, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_head(ida_bytes.get_flags(ea))

    def is_flowed_at(self, ea: ea_t) -> bool:
        """
        Does the previous instruction exist and pass execution flow to the current byte?

        Args:
            ea: The effective address.

        Returns:
            True if flow, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_flow(ida_bytes.get_flags(ea))

    def is_byte_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a byte data type.

        Args:
            ea: The effective address.

        Returns:
            True if byte type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_byte(ida_bytes.get_flags(ea))

    def is_word_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a word data type.

        Args:
            ea: The effective address.

        Returns:
            True if word type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_word(ida_bytes.get_flags(ea))

    def is_dword_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a dword data type.

        Args:
            ea: The effective address.

        Returns:
            True if dword type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_dword(ida_bytes.get_flags(ea))

    def is_qword_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a qword data type.

        Args:
            ea: The effective address.

        Returns:
            True if qword type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_qword(ida_bytes.get_flags(ea))

    def is_oword_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains an oword data type.

        Args:
            ea: The effective address.

        Returns:
            True if oword type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_oword(ida_bytes.get_flags(ea))

    def is_yword_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a yword data type.

        Args:
            ea: The effective address.

        Returns:
            True if yword type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_yword(ida_bytes.get_flags(ea))

    def is_zword_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a zword data type.

        Args:
            ea: The effective address.

        Returns:
            True if zword type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_zword(ida_bytes.get_flags(ea))

    def is_tbyte_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a tbyte data type.

        Args:
            ea: The effective address.

        Returns:
            True if tbyte type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_tbyte(ida_bytes.get_flags(ea))

    def is_float_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a float data type.

        Args:
            ea: The effective address.

        Returns:
            True if float type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_float(ida_bytes.get_flags(ea))

    def is_double_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a double data type.

        Args:
            ea: The effective address.

        Returns:
            True if double type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_double(ida_bytes.get_flags(ea))

    def is_packed_real_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a packed real data type.

        Args:
            ea: The effective address.

        Returns:
            True if packed real type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_pack_real(ida_bytes.get_flags(ea))

    def is_string_literal_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a string literal data type.

        Args:
            ea: The effective address.

        Returns:
            True if string literal type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_strlit(ida_bytes.get_flags(ea))

    def is_struct_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains a struct data type.

        Args:
            ea: The effective address.

        Returns:
            True if struct type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_struct(ida_bytes.get_flags(ea))

    def is_alignment_at(self, ea: ea_t) -> bool:
        """
        Checks if the address contains an alignment directive.

        Args:
            ea: The effective address.

        Returns:
            True if alignment type, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_align(ida_bytes.get_flags(ea))

    def is_manual_insn_at(self, ea: ea_t) -> bool:
        """
        Is the instruction overridden?

        Args:
            ea: The effective address.

        Returns:
            True if instruction is manually overridden, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.is_manual_insn(ea)

    def is_forced_operand_at(self, ea: ea_t, n: int) -> bool:
        """
        Is operand manually defined?

        Args:
            ea: The effective address.
            n: Operand number (0-based).

        Returns:
            True if operand is forced, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If operand number is negative.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if n < 0:
            raise InvalidParameterError('n', n, 'operand number must be non-negative')

        return ida_bytes.is_forced_operand(ea, n)

    def get_string_at(self, ea: ea_t, max_length: Optional[int] = None) -> Optional[str]:
        """
        Gets a string from the specified address.

        Args:
            ea: The effective address.
            max_length: Maximum string length to read.

        Returns:
            The string if it was successfully extracted or None in case of error

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If max_length is specified but not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if max_length is not None and max_length <= 0:
            raise InvalidParameterError(
                'max_length', max_length, 'must be positive when specified'
            )

        if max_length is None:
            # Try to get string length from IDA's analysis
            str_len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
            if str_len <= 0:
                str_len = 256  # Default max length
        else:
            str_len = max_length

        string_data = ida_bytes.get_strlit_contents(ea, str_len, ida_nalt.STRTYPE_C)
        if string_data is not None:
            try:
                # Decode bytes to string
                decoded_string = string_data.decode('utf-8')
                return decoded_string
            except Exception:
                # Try latin-1 as fallback
                decoded_string = string_data.decode('latin-1')
                return decoded_string
        else:
            return None

    def get_cstring_at(self, ea: ea_t, max_length: int = 1024) -> Optional[str]:
        """
        Gets a C-style null-terminated string.

        Args:
            ea: The effective address.
            max_length: Maximum string length to read (default: 1024).

        Returns:
            The string if it was successfully extracted or None in case of error

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If max_length is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if max_length <= 0:
            raise InvalidParameterError('max_length', max_length, 'must be positive')

        # Read bytes until null terminator or max_length limit
        data = []
        current_ea = ea

        for i in range(max_length):
            byte_val = ida_bytes.get_byte(current_ea)
            if byte_val == 0:  # Null terminator
                break
            data.append(byte_val)
            current_ea += 1

        if data:
            try:
                # Convert bytes to string
                string_data = bytes(data)
                decoded_string = string_data.decode('utf-8')
                return decoded_string
            except Exception:
                decoded_string = string_data.decode('latin-1')
                return decoded_string
        else:
            return None

    def get_original_bytes_at(self, ea: ea_t, size: int) -> Optional[bytes]:
        """
        Gets the original bytes before any patches by reading individual bytes.

        Args:
            ea: The effective address.
            size: Number of bytes to read.

        Returns:
            The original bytes or None in case of error.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If size is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if size <= 0:
            raise InvalidParameterError('size', size, 'must be positive')

        original_bytes = []
        for i in range(size):
            orig_byte = ida_bytes.get_original_byte(ea + i)
            original_bytes.append(orig_byte & 0xFF)  # Ensure it's a byte value
        return bytes(original_bytes) if original_bytes else None

    def get_bytes_at(self, ea: ea_t, size: int) -> Optional[bytes]:
        """
        Gets the specified number of bytes of the program.

        Args:
            ea: The effective address.
            size: Number of bytes to read.

        Returns:
            The bytes (as bytes object), or None in case of failure

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If size is not positive.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if size <= 0:
            raise InvalidParameterError('size', size, 'must be positive')

        return ida_bytes.get_bytes(ea, size, ida_bytes.GMB_READALL)

    def has_user_name_at(self, ea: ea_t) -> bool:
        """
        Checks if the address has a user-defined name.

        Args:
            ea: The effective address.

        Returns:
            True if has user name, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_bytes.has_user_name(ida_bytes.get_flags(ea))

    def get_flags_at(self, ea: ea_t) -> ByteFlags:
        """
        Gets the flags for the specified address masked with IVL and MS_VAL

        Args:
            ea: The effective address.

        Returns:
            ByteFlags enum value representing the flags.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ByteFlags(ida_bytes.get_flags(ea))

    def get_all_flags_at(self, ea: ea_t) -> ByteFlags:
        """
        Gets all the full flags for the specified address.

        Args:
            ea: The effective address.

        Returns:
            ByteFlags enum value representing the full flags.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ByteFlags(ida_bytes.get_full_flags(ea))

    def get_next_head(self, ea: ea_t, max_ea: ea_t = None) -> Optional[ea_t]:
        """
        Gets the next head (start of data item) after the specified address.

        Args:
            ea: The effective address.
            max_ea: Maximum address to search.

        Returns:
            Address of next head, or None if not found.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if max_ea is None:
            max_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(max_ea):
            raise InvalidEAError(max_ea)

        ret = ida_bytes.next_head(ea, max_ea)
        return ret if ret != BADADDR else None

    def get_previous_head(self, ea: ea_t, min_ea: ea_t = None) -> Optional[ea_t]:
        """
        Gets the previous head (start of data item) before the specified address.

        Args:
            ea: The effective address.
            min_ea: Minimum address to search.

        Returns:
            Address of previous head, or None if not found.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if min_ea is None:
            min_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(min_ea):
            raise InvalidEAError(min_ea)

        ret = ida_bytes.prev_head(ea, min_ea)
        return ret if ret != BADADDR else None

    def get_next_address(self, ea: ea_t) -> Optional[ea_t]:
        """
        Gets the next valid address after the specified address.

        Args:
            ea: The effective address.

        Returns:
            Next valid address or None.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        ret = ida_bytes.next_addr(ea)
        return ret if ret != BADADDR else None

    def get_previous_address(self, ea: ea_t) -> Optional[ea_t]:
        """
        Gets the previous valid address before the specified address.

        Args:
            ea: The effective address.

        Returns:
            Previous valid address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        ret = ida_bytes.prev_addr(ea)
        return ret if ret != BADADDR else None

    def check_flags_at(self, ea: ea_t, flag_mask: ByteFlags) -> bool:
        """
        Checks if the specified flags are set at the given address.

        Args:
            ea: The effective address.
            flag_mask: ByteFlags enum value(s) to check.

        Returns:
            True if all specified flags are set, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        flags = ida_bytes.get_flags(ea)
        return (flags & flag_mask) == flag_mask

    def has_any_flags_at(self, ea: ea_t, flag_mask: ByteFlags) -> bool:
        """
        Checks if any of the specified flags are set at the given address.

        Args:
            ea: The effective address.
            flag_mask: ByteFlags enum value(s) to check.

        Returns:
            True if any of the specified flags are set, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        flags = ida_bytes.get_flags(ea)
        return (flags & flag_mask) != 0

    def find_binary_sequence(
        self, pattern: bytes, start_ea: ea_t = None, end_ea: ea_t = None
    ) -> List[ea_t]:
        """
        Find all occurrences of a binary pattern.

        Args:
            pattern: Binary pattern to search for.
            start_ea: Search start address; defaults to database minimum ea if None.
            end_ea: Search end address; defaults to database maximum ea if None.

        Returns:
            List of addresses where pattern was found.

        Raises:
            InvalidParameterError: If pattern is invalid.
            InvalidEAError: If start_ea or end_ea are specified but invalid.
        """
        if not isinstance(pattern, bytes):
            raise InvalidParameterError('pattern', type(pattern), 'must be bytes')

        if len(pattern) == 0:
            raise InvalidParameterError('pattern', len(pattern), 'cannot be empty')

        if start_ea is None:
            start_ea = self.database.minimum_ea
        elif not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)

        if end_ea is None:
            end_ea = self.database.maximum_ea
        elif not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)

        results = []
        ea = ida_bytes.find_bytes(pattern, start_ea, None, end_ea)
        while ea != BADADDR:
            results.append(ea)
            ea = ida_bytes.find_bytes(pattern, ea + 1, None, end_ea)
        return results

    def get_microcode_between(
        self, start_ea: ea_t, end_ea: ea_t, remove_tags: bool = True
    ) -> List[str]:
        """
        Retrieves the microcode of the given range.

        Args:
            start_ea: The range start.
            end_ea: The range end.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of microcode. Returns empty list if
            range is invalid or decompilation fails.

        Raises:
            RuntimeError: If microcode generation fails for the range.
        """
        mbr = ida_hexrays.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(start_ea, end_ea))
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, ml, ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_GENERATED
        )

        if not mba:
            raise RuntimeError(f'Failed to generate microcode for range {start_ea:x}:{end_ea:x}')

        mba.build_graph()
        total = mba.qty
        for i in range(total):
            if i == 0:
                continue

            block = mba.get_mblock(i)
            if block.type == ida_hexrays.BLT_STOP:
                continue

            vp = ida_hexrays.qstring_printer_t(None, True)
            block._print(vp)
            src = vp.s
            lines = src.splitlines()

            if not remove_tags:
                return lines

            microcode = []
            for line in lines:
                new_line = ida_lines.tag_remove(line)
                if new_line:
                    microcode.append(new_line)

            return microcode
        return []
