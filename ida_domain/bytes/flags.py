"""Flag enumerations for the bytes module."""
from __future__ import annotations

from enum import IntFlag

import ida_bytes
import ida_search


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
