from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass
from enum import Enum, EnumMeta, Flag, IntEnum, IntFlag, auto
from pathlib import Path

import ida_nalt
import ida_typeinf
from ida_typeinf import (
    BT_FLOAT,
    BT_INT8,
    BT_INT16,
    BT_INT32,
    BT_INT64,
    BT_VOID,
    BTF_STRUCT,
    BTF_UNION,
    BTMT_DOUBLE,
    array_type_data_t,
    bitfield_type_data_t,
    enum_type_data_t,
    func_type_data_t,
    funcarg_t,
    ptr_type_data_t,
    til_t,
    tinfo_t,
    udm_t,
    udt_type_data_t,
)
from typing_extensions import TYPE_CHECKING, Callable, Dict, Iterator, List, Optional, Tuple, Union

from . import __ida_version__
from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from ida_idaapi import ea_t

    from .database import Database


logger = logging.getLogger(__name__)


class NotSupportedWarning(Warning):
    """Warning for unsupported features in the underlying idapython API"""

    pass


warnings.simplefilter('ignore', category=NotSupportedWarning)

_VERSION_SUPPORT_CHECK: Dict[Tuple[str, str], Callable[[], bool]] = {
    ('UdtAttr', 'TUPLE'): lambda: __ida_version__ >= 920
}


def _is_supported(type_name: str, attr: str, warn: bool = True) -> bool:
    checker = _VERSION_SUPPORT_CHECK.get((type_name, attr))
    supported = checker is None or checker()
    if not supported and warn:
        warnings.warn(
            f'{type_name}.{attr} is not supported in IDA version {__ida_version__}',
            category=NotSupportedWarning,
            stacklevel=1,
        )
    return supported


class _CheckAttrSupport(EnumMeta):
    def __getattribute__(cls, name):  # type: ignore
        obj = super().__getattribute__(name)
        _is_supported(type(obj).__name__, name)
        return obj


class LibraryAddFlags(IntFlag):
    """Flags for changing the way type libraries are added to the database"""

    ADD_DEFAULT = ida_typeinf.ADDTIL_DEFAULT
    """Default behavior"""
    ADD_INCOMPATIBLE = ida_typeinf.ADDTIL_INCOMP
    """Add incompatible type libraries"""
    ADD_SILENT = ida_typeinf.ADDTIL_SILENT
    """Do not ask any questions"""


class LibraryAddResult(IntEnum):
    """Return values for library add operation"""

    FAILED = ida_typeinf.ADDTIL_FAILED
    """Loading library failed"""
    SUCCESS = ida_typeinf.ADDTIL_OK
    """Library successfully loaded"""
    INCOMPATIBLE = ida_typeinf.ADDTIL_COMP
    """Library loaded but is incompatible"""
    ABORTED = ida_typeinf.ADDTIL_ABORTED
    """Library not loaded, rejected by the user"""


class TypeManipulationFlags(IntFlag):
    """Flags to be used"""

    NTF_TYPE = ida_typeinf.NTF_TYPE
    """type name
    """
    NTF_SYMU = ida_typeinf.NTF_SYMU
    """symbol, name is unmangled ('func')
    """
    NTF_SYMM = ida_typeinf.NTF_SYMM
    """symbol, name is mangled ('_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used
            """
    NTF_NOBASE = ida_typeinf.NTF_NOBASE
    """don't inspect base tils (for get_named_type)
    """
    NTF_REPLACE = ida_typeinf.NTF_REPLACE
    """replace original type (for set_named_type)
    """
    NTF_UMANGLED = ida_typeinf.NTF_UMANGLED
    """name is unmangled (don't use this flag)
    """
    NTF_NOCUR = ida_typeinf.NTF_NOCUR
    """don't inspect current til file (for get_named_type)
    """
    NTF_64BIT = ida_typeinf.NTF_64BIT
    """value is 64bit
    """
    NTF_FIXNAME = ida_typeinf.NTF_FIXNAME
    """force-validate the name of the type when setting (set_named_type, set_numbered_type only)
            """
    NTF_IDBENC = ida_typeinf.NTF_IDBENC
    """the name is given in the IDB encoding;
        non-ASCII bytes will be decoded accordingly (set_named_type, set_numbered_type only)
            """
    NTF_CHKSYNC = ida_typeinf.NTF_CHKSYNC
    """check that synchronization to IDB passed OK (set_numbered_type, set_named_type)
            """
    NTF_NO_NAMECHK = ida_typeinf.NTF_NO_NAMECHK
    """do not validate type name (set_numbered_type, set_named_type)
            """
    NTF_COPY = ida_typeinf.NTF_COPY
    """save a new type definition, not a typeref
      (tinfo_t::set_numbered_type, tinfo_t::set_named_type)
    """


class TypeApplyFlags(IntFlag):
    """Flags that control how type information is applied to a given address"""

    GUESSED = ida_typeinf.TINFO_GUESSED  # this is a guessed type
    DEFINITE = ida_typeinf.TINFO_DEFINITE  # this is a definite type
    DELAYFUNC = ida_typeinf.TINFO_DELAYFUNC
    # if type is a function and no function exists at ea
    # schedule its creation and argument renaming to auto-analysis
    # otherwise try to create it immediately
    STRICT = ida_typeinf.TINFO_STRICT
    # never convert given type to another one before applying


class TypeFormattingFlags(IntFlag):
    """Type formatting flags used to control type parsing, formatting and printing"""

    HTI_INT = ida_typeinf.HTI_INT
    """Debug: print internal representation of types"""
    HTI_EXT = ida_typeinf.HTI_EXT
    """Debug: print external representation of types"""
    HTI_LEX = ida_typeinf.HTI_LEX
    """Debug: print tokens"""
    HTI_UNP = ida_typeinf.HTI_UNP
    """Debug: check the result by unpacking it"""
    HTI_TST = ida_typeinf.HTI_TST
    """Test mode: discard the result"""
    HTI_FIL = ida_typeinf.HTI_FIL
    """"Input" is file name, otherwise "input" contains a C declaration"""
    HTI_MAC = ida_typeinf.HTI_MAC
    """Define macros from the base tils"""
    HTI_NWR = ida_typeinf.HTI_NWR
    """No warning messages"""
    HTI_NER = ida_typeinf.HTI_NER
    """Ignore all errors but display them"""
    HTI_DCL = ida_typeinf.HTI_DCL
    """Don't complain about redeclarations"""
    HTI_NDC = ida_typeinf.HTI_NDC
    """Don't decorate names"""
    HTI_PAK = ida_typeinf.HTI_PAK
    """Explicit structure pack value (#pragma pack)"""
    HTI_PAK_SHIFT = ida_typeinf.HTI_PAK_SHIFT
    """Shift for HTI_PAK. This field should be used if you want to remember
        an explicit pack value for each structure/union type.
        See HTI_PAK... definitions"""
    HTI_PAKDEF = ida_typeinf.HTI_PAKDEF
    """Default pack value"""
    HTI_PAK1 = ida_typeinf.HTI_PAK1
    """#pragma pack(1)"""
    HTI_PAK2 = ida_typeinf.HTI_PAK2
    """#pragma pack(2)"""
    HTI_PAK4 = ida_typeinf.HTI_PAK4
    """#pragma pack(4)"""
    HTI_PAK8 = ida_typeinf.HTI_PAK8
    """#pragma pack(8)"""
    HTI_PAK16 = ida_typeinf.HTI_PAK16
    """#pragma pack(16)"""
    HTI_HIGH = ida_typeinf.HTI_HIGH
    """Assume high level prototypes (with hidden args, etc)"""
    HTI_LOWER = ida_typeinf.HTI_LOWER
    """Lower the function prototypes"""
    HTI_RAWARGS = ida_typeinf.HTI_RAWARGS
    """Leave argument names unchanged (do not remove underscores)"""
    HTI_RELAXED = ida_typeinf.HTI_RELAXED
    """Accept references to unknown namespaces"""
    HTI_NOBASE = ida_typeinf.HTI_NOBASE
    """Do not inspect base tils"""
    HTI_SEMICOLON = ida_typeinf.HTI_SEMICOLON
    """Do not complain if the terminating semicolon is absent"""


class TypeKind(Enum):
    """Type category enumeration."""

    NAMED = 1
    NUMBERED = 2


class UdtAttr(Flag, metaclass=_CheckAttrSupport):
    """User Defined Type flags"""

    CPP_OBJ = auto()
    FIXED = auto()
    MS_STRUCT = auto()
    UNALIGNED = auto()
    VFTABLE = auto()
    UNION = auto()
    TUPLE = auto()


class UdtDetails:
    """User Defined Type details"""

    @staticmethod
    def _is_tuple(u: udt_type_data_t) -> bool:
        type_name = UdtAttr.__name__
        attr_name = str(UdtAttr.TUPLE.name)
        if _is_supported(type_name, attr_name, warn=False):
            return u.is_tuple()
        return False

    _HANDLERS: Dict[UdtAttr, Callable[[udt_type_data_t], bool]] = {
        UdtAttr.FIXED: lambda t: t.is_fixed(),
        UdtAttr.UNALIGNED: lambda t: t.is_unaligned(),
        UdtAttr.MS_STRUCT: lambda t: t.is_msstruct(),
        UdtAttr.CPP_OBJ: lambda t: t.is_cppobj(),
        UdtAttr.VFTABLE: lambda t: t.is_vftable(),
        UdtAttr.TUPLE: _is_tuple,
    }

    def __init__(self) -> None:
        self._attributes: Optional[UdtAttr] = None
        self._num_members = 0

    @property
    def attributes(self) -> Optional[UdtAttr]:
        """Get UDT attributes."""
        return self._attributes

    @property
    def num_members(self) -> int:
        """Get number of members."""
        return self._num_members

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[UdtDetails]:
        """
        Extract UDT type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            UDT type details object filled with extracted information.
        """
        details = UdtDetails()
        details._attributes = UdtAttr(0)
        data = ida_typeinf.udt_type_data_t()

        if type_info.get_udt_details(data):
            details._num_members = type_info.get_udt_nmembers()
            if data.is_union:
                details._attributes |= UdtAttr.UNION
            for flag, handler in cls._HANDLERS.items():
                if handler(data):
                    details._attributes |= flag

            details._attributes = details._attributes or None
            return details
        else:
            return None


class EnumAttr(Flag):
    """Enum Type flags"""

    BITMASK = auto()
    SIGNED = auto()
    CHAR = auto()
    DECIMAL = auto()
    HEXADECIMAL = auto()
    OCTAL = auto()
    BINARY = auto()
    UNSIGNED_DECIMAL = auto()
    SIGNED_HEXADECIMAL = auto()
    SIGNED_OCTAL = auto()
    SIGNED_BINARY = auto()
    LEADING_ZEROS = auto()


class EnumDetails:
    """
    Enum type details.
    """

    _HANDLERS: Dict[EnumAttr, Callable[[enum_type_data_t], bool]] = {
        EnumAttr.BITMASK: lambda t: t.is_bf(),
        EnumAttr.SIGNED: lambda t: t.is_number_signed(),
        EnumAttr.CHAR: lambda t: t.is_char(),
        EnumAttr.DECIMAL: lambda t: t.is_dec(),
        EnumAttr.HEXADECIMAL: lambda t: t.is_hex(),
        EnumAttr.OCTAL: lambda t: t.is_oct(),
        EnumAttr.BINARY: lambda t: t.is_bin(),
        EnumAttr.UNSIGNED_DECIMAL: lambda t: t.is_udec(),
        EnumAttr.SIGNED_HEXADECIMAL: lambda t: t.is_shex(),
        EnumAttr.SIGNED_OCTAL: lambda t: t.is_soct(),
        EnumAttr.SIGNED_BINARY: lambda t: t.is_sbin(),
        EnumAttr.LEADING_ZEROS: lambda t: t.has_lzero(),
    }

    def __init__(self) -> None:
        self._attributes: Optional[EnumAttr] = None

    @property
    def attributes(self) -> Optional[EnumAttr]:
        """Get enum type attributes"""
        return self._attributes

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[EnumDetails]:
        """
        Extract enum type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Enum type details object filled with extracted information.
        """
        details = EnumDetails()
        details._attributes = EnumAttr(0)
        data = ida_typeinf.enum_type_data_t()

        if type_info.get_enum_details(data):
            for flag, handler in cls._HANDLERS.items():
                if handler(data):
                    details._attributes |= flag

            details._attributes = details._attributes or None
            return details
        else:
            return None


class PtrAttr(Flag):
    """Pointer Type Flags"""

    CODE_POINTER = auto()
    SHIFTED = auto()


class PtrDetails:
    _HANDLERS: Dict[PtrAttr, Callable[[ptr_type_data_t], bool]] = {
        PtrAttr.CODE_POINTER: lambda t: t.is_code_ptr(),
        PtrAttr.SHIFTED: lambda t: t.is_shifted(),
    }

    def __init__(self) -> None:
        self._attributes: Optional[PtrAttr] = None

    @property
    def attributes(self) -> Optional[PtrAttr]:
        """Get pointer type attributes."""
        return self._attributes

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[PtrDetails]:
        """
        Extract pointer type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Pointer type details object filled with extracted information.
        """
        details = PtrDetails()
        details._attributes = PtrAttr(0)
        data = ida_typeinf.ptr_type_data_t()

        if type_info.get_ptr_details(data):
            for flag, handler in cls._HANDLERS.items():
                if handler(data):
                    details._attributes |= flag

            details._attributes = details._attributes or None
            return details
        else:
            return None


class ArrayDetails:
    def __init__(self) -> None:
        self._element_type: tinfo_t
        self._base: int
        self._number_of_elements: int

    @property
    def element_type(self) -> tinfo_t:
        """Get array element type."""
        return self._element_type

    @property
    def base(self) -> int:
        """Get array base."""
        return self._base

    @property
    def length(self) -> int:
        """Get number of elements."""
        return self._number_of_elements

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[ArrayDetails]:
        """
        Extract array type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Array type details object filled with extracted information.
        """
        details: ArrayDetails = ArrayDetails()
        data = ida_typeinf.array_type_data_t()

        if type_info.get_array_details(data):
            details._element_type = data.elem_type
            details._base = data.base
            details._number_of_elements = data.nelems
            return details
        else:
            return None


class FuncAttr(Flag):
    """Function Type flags"""

    HIGH_LEVEL = auto()
    NO_RET = auto()  # No return
    PURE = auto()
    STATIC = auto()
    VIRTUAL = auto()
    CONST = auto()
    CONSTRUCTOR = auto()  # Constructor
    DESTRUCTOR = auto()  # Destructor
    VARARG_CC = auto()  # Variable argument calling convention
    GOLANG_CC = auto()  # Go calling convention
    SWIFT_CC = auto()  # Swift calling convention
    USER_CC = auto()  # User-defined calling convention


class FuncDetails:
    """
    Function type details.
    """

    _HANDLERS: Dict[FuncAttr, Callable[[func_type_data_t], bool]] = {
        FuncAttr.HIGH_LEVEL: lambda f: f.is_high(),
        FuncAttr.NO_RET: lambda f: f.is_noret(),
        FuncAttr.PURE: lambda f: f.is_pure(),
        FuncAttr.STATIC: lambda f: f.is_static(),
        FuncAttr.VIRTUAL: lambda f: f.is_virtual(),
        FuncAttr.CONST: lambda f: f.is_const(),
        FuncAttr.CONSTRUCTOR: lambda f: f.is_ctor(),
        FuncAttr.DESTRUCTOR: lambda f: f.is_dtor(),
        FuncAttr.VARARG_CC: lambda f: f.is_vararg_cc(),
        FuncAttr.GOLANG_CC: lambda f: f.is_golang_cc(),
        FuncAttr.SWIFT_CC: lambda f: f.is_swift_cc(),
        FuncAttr.USER_CC: lambda f: f.is_user_cc(),
    }

    def __init__(self) -> None:
        self._attributes: Optional[FuncAttr] = None

    @property
    def attributes(self) -> Optional[FuncAttr]:
        """Get the function type attributes."""
        return self._attributes

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[FuncDetails]:
        """
        Extract function type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Function type details object filled with extracted information.
        """
        details = FuncDetails()
        details._attributes = FuncAttr(0)
        data = ida_typeinf.func_type_data_t()

        if type_info.get_func_details(data):
            for flag, handler in cls._HANDLERS.items():
                if handler(data):
                    details._attributes |= flag

            details._attributes = details.attributes or None
            return details
        else:
            return None


class BitfieldAttr(Flag):
    """Bitfield Type flags"""

    UNSIGNED = auto()
    VALID = auto()


class BitfieldDetails:
    """Bitfield type details"""

    _HANDLERS: Dict[BitfieldAttr, Callable[[bitfield_type_data_t], bool]] = {
        BitfieldAttr.UNSIGNED: lambda f: f.is_unsigned,
        BitfieldAttr.VALID: lambda f: f.is_valid_bitfield(),
    }

    def __init__(self) -> None:
        self._attributes: Optional[BitfieldAttr] = None

    @property
    def attributes(self) -> Optional[BitfieldAttr]:
        """Get the bitfield type attributes."""
        return self._attributes

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> Optional[BitfieldDetails]:
        """
        Extract bitfield type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Bitfield type details object filled with extracted information.
        """
        details = BitfieldDetails()
        details._attributes = BitfieldAttr(0)
        data = ida_typeinf.bitfield_type_data_t()

        if type_info.get_bitfield_details(data):
            for flag, handler in cls._HANDLERS.items():
                if handler(data):
                    details._attributes |= flag

            details._attributes = details.attributes or None
            return details
        else:
            return None


class TypeAttr(Flag):
    """General Type attributes"""

    ATTACHED = auto()  # type is attached to a library
    ARITHMETIC = auto()
    ARRAY = auto()
    BITFIELD = auto()
    BOOL = auto()
    CHAR = auto()
    COMPLEX = auto()
    CONST = auto()
    CORRECT = auto()
    DECL_ARRAY = auto()
    DECL_BITFIELD = auto()
    DECL_BOOL = auto()
    DECL_CHAR = auto()
    DECL_COMPLEX = auto()
    DECL_CONST = auto()
    DECL_DOUBLE = auto()
    DECL_ENUM = auto()
    DECL_FLOAT = auto()
    DECL_FLOATING = auto()
    DECL_FUNC = auto()
    DECL_INT = auto()
    DECL_INT128 = auto()
    DECL_INT16 = auto()
    DECL_INT32 = auto()
    DECL_INT64 = auto()
    DECL_LAST = auto()
    DECL_LDOUBLE = auto()
    DECL_PAF = auto()
    DECL_PARTIAL = auto()
    DECL_PTR = auto()
    DECL_STRUCT = auto()
    DECL_SUE = auto()
    DECL_TBYTE = auto()
    DECL_TYPEDEF = auto()
    DECL_UCHAR = auto()
    DECL_UDT = auto()
    DECL_UINT = auto()
    DECL_UINT128 = auto()
    DECL_UINT16 = auto()
    DECL_UINT32 = auto()
    DECL_UINT64 = auto()
    DECL_UNION = auto()
    DECL_UNKNOWN = auto()
    DECL_VOID = auto()
    DECL_VOLATILE = auto()
    DOUBLE = auto()
    ENUM = auto()
    EXT_ARITHMETIC = auto()
    EXT_INTEGRAL = auto()
    FLOAT = auto()
    FLOATING = auto()
    FUNC = auto()
    FUNC_PTR = auto()
    HIGH_LEVEL_FUNC = auto()
    INT = auto()
    INT128 = auto()
    INT16 = auto()
    INT32 = auto()
    INT64 = auto()
    INTEGRAL = auto()
    LDOUBLE = auto()
    PAF = auto()
    PARTIAL = auto()
    POINTER_UNKNOWN = auto()
    POINTER_VOID = auto()
    PTR = auto()
    PTR_OR_ARRAY = auto()
    PURGING_CALLING_CONVENTION = auto()
    SCALAR = auto()
    SHIFTED_PTR = auto()
    STRUCT = auto()
    SUE = auto()
    TBYTE = auto()
    UCHAR = auto()
    UDT = auto()
    UINT = auto()
    UINT128 = auto()
    UINT16 = auto()
    UINT32 = auto()
    UINT64 = auto()
    UNION = auto()
    UNKNOWN = auto()
    USER_CALLING_CONVENTION = auto()
    VARARG_CALLING_CONVENTION = auto()
    VARIABLE_STRUCT = auto()
    VARIABLE_STRUCT_MEMBER = auto()
    VOID = auto()
    VOLATILE = auto()
    WELL_DEFINED = auto()


class TypeDetails:
    """Comprehensive type information with category-specific attributes"""

    _HANDLERS: Dict[TypeAttr, Callable[[tinfo_t], bool]] = {
        TypeAttr.ATTACHED: lambda t: t.is_typeref(),
        TypeAttr.ARITHMETIC: lambda t: t.is_arithmetic(),
        TypeAttr.ARRAY: lambda t: t.is_array(),
        TypeAttr.BITFIELD: lambda t: t.is_bitfield(),
        TypeAttr.BOOL: lambda t: t.is_bool(),
        TypeAttr.CHAR: lambda t: t.is_char(),
        TypeAttr.COMPLEX: lambda t: t.is_complex(),
        TypeAttr.CONST: lambda t: t.is_const(),
        TypeAttr.CORRECT: lambda t: t.is_correct(),
        TypeAttr.DECL_ARRAY: lambda t: t.is_decl_array(),
        TypeAttr.DECL_BITFIELD: lambda t: t.is_decl_bitfield(),
        TypeAttr.DECL_BOOL: lambda t: t.is_decl_bool(),
        TypeAttr.DECL_CHAR: lambda t: t.is_decl_char(),
        TypeAttr.DECL_COMPLEX: lambda t: t.is_decl_complex(),
        TypeAttr.DECL_CONST: lambda t: t.is_decl_const(),
        TypeAttr.DECL_DOUBLE: lambda t: t.is_decl_double(),
        TypeAttr.DECL_ENUM: lambda t: t.is_decl_enum(),
        TypeAttr.DECL_FLOAT: lambda t: t.is_decl_float(),
        TypeAttr.DECL_FLOATING: lambda t: t.is_decl_floating(),
        TypeAttr.DECL_FUNC: lambda t: t.is_decl_func(),
        TypeAttr.DECL_INT128: lambda t: t.is_decl_int128(),
        TypeAttr.DECL_INT16: lambda t: t.is_decl_int16(),
        TypeAttr.DECL_INT32: lambda t: t.is_decl_int32(),
        TypeAttr.DECL_INT64: lambda t: t.is_decl_int64(),
        TypeAttr.DECL_INT: lambda t: t.is_decl_int(),
        TypeAttr.DECL_LAST: lambda t: t.is_decl_last(),
        TypeAttr.DECL_LDOUBLE: lambda t: t.is_decl_ldouble(),
        TypeAttr.DECL_PAF: lambda t: t.is_decl_paf(),
        TypeAttr.DECL_PARTIAL: lambda t: t.is_decl_partial(),
        TypeAttr.DECL_PTR: lambda t: t.is_decl_ptr(),
        TypeAttr.DECL_STRUCT: lambda t: t.is_decl_struct(),
        TypeAttr.DECL_SUE: lambda t: t.is_decl_sue(),
        TypeAttr.DECL_TBYTE: lambda t: t.is_decl_tbyte(),
        TypeAttr.DECL_TYPEDEF: lambda t: t.is_decl_typedef(),
        TypeAttr.DECL_UCHAR: lambda t: t.is_decl_uchar(),
        TypeAttr.DECL_UDT: lambda t: t.is_decl_udt(),
        TypeAttr.DECL_UINT128: lambda t: t.is_decl_uint128(),
        TypeAttr.DECL_UINT16: lambda t: t.is_decl_uint16(),
        TypeAttr.DECL_UINT32: lambda t: t.is_decl_uint32(),
        TypeAttr.DECL_UINT64: lambda t: t.is_decl_uint64(),
        TypeAttr.DECL_UINT: lambda t: t.is_decl_uint(),
        TypeAttr.DECL_UNION: lambda t: t.is_decl_union(),
        TypeAttr.DECL_UNKNOWN: lambda t: t.is_decl_unknown(),
        TypeAttr.DECL_VOID: lambda t: t.is_decl_void(),
        TypeAttr.DECL_VOLATILE: lambda t: t.is_decl_volatile(),
        TypeAttr.DOUBLE: lambda t: t.is_double(),
        TypeAttr.ENUM: lambda t: t.is_enum(),
        TypeAttr.EXT_ARITHMETIC: lambda t: t.is_ext_arithmetic(),
        TypeAttr.EXT_INTEGRAL: lambda t: t.is_ext_integral(),
        TypeAttr.FLOAT: lambda t: t.is_float(),
        TypeAttr.FLOATING: lambda t: t.is_floating(),
        TypeAttr.FUNC: lambda t: t.is_func(),
        TypeAttr.FUNC_PTR: lambda t: t.is_funcptr(),
        TypeAttr.HIGH_LEVEL_FUNC: lambda t: t.is_high_func(),
        TypeAttr.INT128: lambda t: t.is_int128(),
        TypeAttr.INT16: lambda t: t.is_int16(),
        TypeAttr.INT32: lambda t: t.is_int32(),
        TypeAttr.INT64: lambda t: t.is_int64(),
        TypeAttr.INT: lambda t: t.is_int(),
        TypeAttr.INTEGRAL: lambda t: t.is_integral(),
        TypeAttr.LDOUBLE: lambda t: t.is_ldouble(),
        TypeAttr.PAF: lambda t: t.is_paf(),
        TypeAttr.PARTIAL: lambda t: t.is_partial(),
        TypeAttr.POINTER_UNKNOWN: lambda t: t.is_punknown(),
        TypeAttr.POINTER_VOID: lambda t: t.is_pvoid(),
        TypeAttr.PTR: lambda t: t.is_ptr(),
        TypeAttr.PTR_OR_ARRAY: lambda t: t.is_ptr_or_array(),
        TypeAttr.PURGING_CALLING_CONVENTION: lambda t: t.is_purging_cc(),
        TypeAttr.SCALAR: lambda t: t.is_scalar(),
        TypeAttr.SHIFTED_PTR: lambda t: t.is_shifted_ptr(),
        TypeAttr.STRUCT: lambda t: t.is_struct(),
        TypeAttr.SUE: lambda t: t.is_sue(),
        TypeAttr.TBYTE: lambda t: t.is_tbyte(),
        TypeAttr.UCHAR: lambda t: t.is_uchar(),
        TypeAttr.UDT: lambda t: t.is_udt(),
        TypeAttr.UINT128: lambda t: t.is_uint128(),
        TypeAttr.UINT16: lambda t: t.is_uint16(),
        TypeAttr.UINT32: lambda t: t.is_uint32(),
        TypeAttr.UINT64: lambda t: t.is_uint64(),
        TypeAttr.UINT: lambda t: t.is_uint(),
        TypeAttr.UNION: lambda t: t.is_union(),
        TypeAttr.UNKNOWN: lambda t: t.is_unknown(),
        TypeAttr.USER_CALLING_CONVENTION: lambda t: t.is_user_cc(),
        TypeAttr.VARARG_CALLING_CONVENTION: lambda t: t.is_vararg_cc(),
        TypeAttr.VARIABLE_STRUCT: lambda t: t.is_varstruct(),
        TypeAttr.VARIABLE_STRUCT_MEMBER: lambda t: t.is_varmember(),
        TypeAttr.VOID: lambda t: t.is_void(),
        TypeAttr.VOLATILE: lambda t: t.is_volatile(),
        TypeAttr.WELL_DEFINED: lambda t: t.is_well_defined(),
    }

    def __init__(self) -> None:
        self._attributes = TypeAttr(0)
        self._name: str = ''
        self._size: int = 0
        self._udt_details: Optional[UdtDetails] = None
        self._enum_details: Optional[EnumDetails] = None
        self._ptr_details: Optional[PtrDetails] = None
        self._array_details: Optional[ArrayDetails] = None
        self._func_details: Optional[FuncDetails] = None
        self._bitfield_details: Optional[BitfieldDetails] = None

    @property
    def attributes(self) -> TypeAttr:
        """Get the general type attributes."""
        return self._attributes

    @property
    def name(self) -> str:
        """Get the name of the type."""
        return self._name

    @property
    def size(self) -> int:
        """Get the size of the type."""
        return self._size

    @property
    def udt(self) -> Optional[UdtDetails]:
        """Get the user-defined type details, if any."""
        return self._udt_details

    @property
    def enum(self) -> Optional[EnumDetails]:
        """Get the enum type details, if any."""
        return self._enum_details

    @property
    def ptr(self) -> Optional[PtrDetails]:
        """Get the pointer type details, if any."""
        return self._ptr_details

    @property
    def array(self) -> Optional[ArrayDetails]:
        """Get the array type details, if any."""
        return self._array_details

    @property
    def func(self) -> Optional[FuncDetails]:
        """Get the function type details, if any."""
        return self._func_details

    @property
    def bitfield(self) -> Optional[BitfieldDetails]:
        """Get the bitfield type details, if any."""
        return self._bitfield_details

    @classmethod
    def from_tinfo_t(cls, type_info: tinfo_t) -> TypeDetails:
        """
        Extract all type attributes and details.

        Args:
            type_info: The type information objects for which to extract details.

        Returns:
            Type details object filled with extracted information.
        """
        details = TypeDetails()
        details._name = type_info.get_type_name()
        details._size = type_info.get_size()
        for flag, handler in cls._HANDLERS.items():
            if handler(type_info):
                details._attributes |= flag

        details._udt_details = UdtDetails.from_tinfo_t(type_info)
        details._enum_details = EnumDetails.from_tinfo_t(type_info)
        details._func_details = FuncDetails.from_tinfo_t(type_info)
        details._ptr_details = PtrDetails.from_tinfo_t(type_info)
        details._array_details = ArrayDetails.from_tinfo_t(type_info)
        details._bitfield_details = BitfieldDetails.from_tinfo_t(type_info)

        return details


class TypeDetailsVisitor(ida_typeinf.tinfo_visitor_t):
    """
    Visitor class for types.
    Used to recursively traverse types and gather the type members details.
    Instances of this class can be passed to the traverse() method to initiate the traversal.
    """

    def __init__(self, db: Database):
        ida_typeinf.tinfo_visitor_t.__init__(self, ida_typeinf.TVST_DEF)
        self.output: list[TypeDetails] = []
        self.db = db

    def visit_type(
        self, out: ida_typeinf.type_mods_t, tif: tinfo_t, name: str, comment: str
    ) -> int:
        details = self.db.types.get_details(tif)
        self.output.append(details)

        return 0


# =============================================================================
# Member Information Dataclasses
# =============================================================================


@dataclass
class UdtMemberInfo:
    """Details about a struct/union member."""

    name: str
    """Member name."""

    type: tinfo_t
    """Member type information."""

    offset: int
    """Byte offset within the structure."""

    size: int
    """Size in bytes."""

    is_bitfield: bool
    """True if this is a bitfield member."""

    bit_offset: Optional[int] = None
    """Bit offset within the byte (for bitfields only)."""

    bit_size: Optional[int] = None
    """Bit size (for bitfields only)."""


@dataclass
class EnumMemberInfo:
    """Details about an enum member."""

    name: str
    """Member name."""

    value: int
    """Numeric value."""


@dataclass
class FuncArgumentInfo:
    """Details about a function argument."""

    index: int
    """Argument index (0-based)."""

    name: str
    """Argument name (may be empty/auto-generated)."""

    type: tinfo_t
    """Argument type information."""


# =============================================================================
# Type Member Lookup Mode
# =============================================================================


class TypeMemberLookupMode(Enum):
    """Mode for member lookup operations."""

    NAME = 'name'
    """Look up member by name"""

    OFFSET = 'offset'
    """Look up member by offset (for UDT)"""

    INDEX = 'index'
    """Look up member by index (for enum, func args)"""

    VALUE = 'value'
    """Look up member by value (for enum)"""


# =============================================================================
# Calling Convention Enum
# =============================================================================


class CallingConvention(Enum):
    """Calling convention for function types."""

    CDECL = 'cdecl'
    STDCALL = 'stdcall'
    FASTCALL = 'fastcall'
    THISCALL = 'thiscall'
    DEFAULT = 'default'


# =============================================================================
# Type Builders
# =============================================================================


class StructBuilder:
    """
    Builder for creating struct types.

    Example:
        >>> builder = db.types.create_struct("MyStruct")
        >>> builder.add_member("x", db.types.create_primitive(4))
        >>> builder.add_member("y", db.types.create_primitive(4))
        >>> my_struct = builder.build()
    """

    def __init__(self, name: str) -> None:
        """
        Initialize a struct builder.

        Args:
            name: Name for the struct type.
        """
        self._name = name
        self._members: List[Tuple[str, tinfo_t, Optional[int]]] = []
        self._packed = False
        self._alignment: Optional[int] = None

    def add_member(
        self, name: str, member_type: tinfo_t, offset: Optional[int] = None
    ) -> 'StructBuilder':
        """
        Add a member to the struct.

        Args:
            name: Member name.
            member_type: Member type.
            offset: Explicit byte offset (auto-calculated if None).

        Returns:
            Self for method chaining.
        """
        self._members.append((name, member_type, offset))
        return self

    def set_packed(self, packed: bool = True) -> 'StructBuilder':
        """
        Set whether the struct is packed (no padding).
        """
        self._packed = packed
        return self

    def set_alignment(self, alignment: int) -> 'StructBuilder':
        """
        Set explicit alignment for the struct.
        """
        self._alignment = alignment
        return self

    def build(self) -> tinfo_t:
        """
        Build and return the struct type.

        Returns:
            The constructed tinfo_t.

        Raises:
            RuntimeError: If struct creation fails.
        """
        udt = udt_type_data_t()
        udt.is_union = False

        for name, member_type, offset in self._members:
            if offset is not None:
                udt_member = udt.add_member(name, member_type, offset)
            else:
                udt_member = udt.add_member(name, member_type)
            if udt_member is None:
                raise RuntimeError(f"Failed to add member '{name}' to struct '{self._name}'")

        result = tinfo_t()
        if not result.create_udt(udt, BTF_STRUCT):
            raise RuntimeError(f"Failed to create struct '{self._name}'")

        return result

    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t:
        """
        Build the struct and save it to a type library.

        Args:
            library: Target library (local library if None).

        Returns:
            The constructed and saved tinfo_t.
        """
        result = self.build()
        if library is None:
            library = ida_typeinf.get_idati()
        if result.set_named_type(library, self._name) < 0:
            raise RuntimeError(f"Failed to save struct '{self._name}' to library")
        return result


class UnionBuilder:
    """
    Builder for creating union types.

    Example:
        >>> builder = db.types.create_union("MyUnion")
        >>> builder.add_member("as_int", db.types.create_primitive(4))
        >>> builder.add_member("as_float", db.types.create_primitive(4))
        >>> my_union = builder.build()
    """

    def __init__(self, name: str) -> None:
        """
        Initialize a union builder.

        Args:
            name: Name for the union type.
        """
        self._name = name
        self._members: List[Tuple[str, tinfo_t]] = []

    def add_member(self, name: str, member_type: tinfo_t) -> 'UnionBuilder':
        """
        Add a member to the union.

        Args:
            name: Member name.
            member_type: Member type.

        Returns:
            Self for method chaining.
        """
        self._members.append((name, member_type))
        return self

    def build(self) -> tinfo_t:
        """
        Build and return the union type.

        Returns:
            The constructed tinfo_t.

        Raises:
            RuntimeError: If union creation fails.
        """
        udt = udt_type_data_t()
        udt.is_union = True

        for name, member_type in self._members:
            udt_member = udt.add_member(name, member_type)
            if udt_member is None:
                raise RuntimeError(f"Failed to add member '{name}' to union '{self._name}'")

        result = tinfo_t()
        if not result.create_udt(udt, BTF_UNION):
            raise RuntimeError(f"Failed to create union '{self._name}'")

        return result

    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t:
        """
        Build the union and save it to a type library.

        Args:
            library: Target library (local library if None).

        Returns:
            The constructed and saved tinfo_t.
        """
        result = self.build()
        if library is None:
            library = ida_typeinf.get_idati()
        if result.set_named_type(library, self._name) < 0:
            raise RuntimeError(f"Failed to save union '{self._name}' to library")
        return result


class EnumBuilder:
    """
    Builder for creating enum types.

    Example:
        >>> builder = db.types.create_enum("FileMode", base_size=4)
        >>> builder.add_member("READ", 1)
        >>> builder.add_member("WRITE", 2)
        >>> builder.add_member("EXEC", 4)
        >>> file_mode = builder.build()
    """

    def __init__(self, name: str, base_size: int = 4) -> None:
        """
        Initialize an enum builder.

        Args:
            name: Name for the enum type.
            base_size: Size in bytes (1, 2, 4, or 8).
        """
        self._name = name
        self._base_size = base_size
        self._members: List[Tuple[str, int]] = []
        self._is_bitmask = False

    def add_member(self, name: str, value: int) -> 'EnumBuilder':
        """
        Add a member to the enum.

        Args:
            name: Member name.
            value: Numeric value.

        Returns:
            Self for method chaining.
        """
        self._members.append((name, value))
        return self

    def set_bitmask(self, is_bitmask: bool = True) -> 'EnumBuilder':
        """
        Set whether this is a bitmask enum.
        """
        self._is_bitmask = is_bitmask
        return self

    def build(self) -> tinfo_t:
        """
        Build and return the enum type.

        Returns:
            The constructed tinfo_t.

        Raises:
            RuntimeError: If enum creation fails.
        """
        enum_data = enum_type_data_t()

        for name, value in self._members:
            enum_data.add_constant(name, value)

        if self._is_bitmask:
            enum_data.set_bf(True)

        result = tinfo_t()
        if not result.create_enum(enum_data):
            raise RuntimeError(f"Failed to create enum '{self._name}'")

        return result

    def build_and_save(self, library: Optional[til_t] = None) -> tinfo_t:
        """
        Build the enum and save it to a type library.

        Args:
            library: Target library (local library if None).

        Returns:
            The constructed and saved tinfo_t.
        """
        result = self.build()
        if library is None:
            library = ida_typeinf.get_idati()
        if result.set_named_type(library, self._name) < 0:
            raise RuntimeError(f"Failed to save enum '{self._name}' to library")
        return result


class FuncTypeBuilder:
    """
    Builder for creating function types.

    Example:
        >>> builder = db.types.create_func_type()
        >>> builder.set_return_type(db.types.create_primitive(4))
        >>> builder.add_argument("count", db.types.create_primitive(4))
        >>> builder.add_argument("buffer", db.types.create_pointer(db.types.create_primitive(1)))
        >>> func_type = builder.build()
    """

    def __init__(self) -> None:
        """Initialize a function type builder."""
        self._return_type: Optional[tinfo_t] = None
        self._arguments: List[Tuple[str, tinfo_t]] = []
        self._calling_convention: Optional[CallingConvention] = None
        self._variadic = False

    def set_return_type(self, ret_type: tinfo_t) -> 'FuncTypeBuilder':
        """
        Set the return type.

        Args:
            ret_type: Return type (void if not set).

        Returns:
            Self for method chaining.
        """
        self._return_type = ret_type
        return self

    def add_argument(self, name: str, arg_type: tinfo_t) -> 'FuncTypeBuilder':
        """
        Add an argument to the function type.

        Args:
            name: Argument name.
            arg_type: Argument type.

        Returns:
            Self for method chaining.
        """
        self._arguments.append((name, arg_type))
        return self

    def set_calling_convention(self, cc: CallingConvention) -> 'FuncTypeBuilder':
        """
        Set the calling convention.

        Args:
            cc: Calling convention enum value.

        Returns:
            Self for method chaining.
        """
        self._calling_convention = cc
        return self

    def set_variadic(self, variadic: bool = True) -> 'FuncTypeBuilder':
        """
        Set whether function accepts variable arguments.

        Returns:
            Self for method chaining.
        """
        self._variadic = variadic
        return self

    def build(self) -> tinfo_t:
        """
        Build and return the function type.

        Returns:
            The constructed tinfo_t.

        Raises:
            RuntimeError: If function type creation fails.
        """
        ftd = func_type_data_t()

        # Set return type
        if self._return_type is not None:
            ftd.rettype = self._return_type
        else:
            void_type = tinfo_t()
            void_type.create_simple_type(BT_VOID)
            ftd.rettype = void_type

        # Add arguments
        for name, arg_type in self._arguments:
            fa = funcarg_t()
            fa.name = name
            fa.type = arg_type
            ftd.push_back(fa)

        result = tinfo_t()
        if not result.create_func(ftd):
            raise RuntimeError('Failed to create function type')

        return result


@decorate_all_methods(check_db_open)
class Types(DatabaseEntity):
    """
    Provides access to type information and manipulation in the IDA database.

    Can be used to iterate over all types in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[ida_typeinf.tinfo_t]:
        return self.get_all()

    def load_library(self, file: Path) -> til_t:
        """
        Loads a type library file in memory.

        Args:
            file: The path of the library file to load.
                The library name can be passed with or without extension
                (.til extension will be forced) and as a relative (default ida
                til directory will be used) or absolute path.

        Returns:
            The loaded til_t object.
        """
        return ida_typeinf.load_til(str(file))

    def unload_library(self, library: til_t) -> None:
        """
        Unload library (free underlying object).

        Args:
            library: The library instance to unload.
        """
        ida_typeinf.free_til(library)

    def import_from_library(self, library: til_t) -> None:
        """
        Imports the types from an external library to the local (database) library.

        Args:
            library: The library instance to import from.

        Returns:
            The status of the add library operation.
        """
        for t in self.get_all(library=library):
            self.import_type(library, t.get_type_name())

    def export_to_library(self, library: til_t) -> None:
        """
        Export all types from local library to external library.
        Numbered types will be automatically enabled for the external library.

        Args:
            library: The destination library.
        """
        for t in self.get_all():
            self.export_type(library, t.get_type_name())

    def create_library(self, file: Path, description: str) -> til_t:
        """
        Initializes a new type library.

        Args:
            file: The name of the library.
            description: The description of the library.

        Returns:
            An initialized library.
        """
        return ida_typeinf.new_til(str(file.name), description)

    def save_library(self, library: til_t, file: Path) -> bool:
        """
        Stores the type library to a file.
        If the library contains garbage, it will be collected before storing it.
        Also compacts the library before saving.

        Args:
            library: The type library instance to save to disk.
            file: The path to save the library to.

        Returns:
            True if the operation succeeded, False otherwise.
        """
        ida_typeinf.compact_til(library)
        return ida_typeinf.store_til(library, str(file.parents), str(file))

    def import_type(self, source: til_t, name: str) -> int:
        """
        Imports a type and all dependent types from an external (loaded) library
        into the local (database) library.

        Args:
            source: The loaded type library from where to import the type.
            name: The name of the type.

        Raises:
            RuntimeError: If the import operation failed.

        Returns:
            The ordinal number of the imported type.
        """
        result = ida_typeinf.copy_named_type(ida_typeinf.get_idati(), source, name)
        if result == 0:
            raise RuntimeError(f'error importing type {name}')
        return result

    def export_type(self, destination: til_t, name: str) -> int:
        """
        Exports a type and all dependent types from the local (database) library
        into a loaded (external) library.

        Numbered types will be automatically enabled for the external library.

        Args:
            destination: The loaded type library from where to import the type.
            name: The name of the type.

        Raises:
            RuntimeError: If the export operation failed.

        Returns:
            The ordinal number of the imported type.
        """
        ida_typeinf.enable_numbered_types(destination, True)
        result = ida_typeinf.copy_named_type(destination, ida_typeinf.get_idati(), name)
        if result == 0:
            raise RuntimeError(f'error exporting type {name}')
        return result

    def copy_type(self, source: til_t, destination: til_t, name: str) -> int:
        """
        Copies a type and all dependent types from one library to another.

        Args:
            source: The source library.
            destination: The destination library.
            name: The name of the type.

        Raises:
            RuntimeError: If the copy operation failed.

        Returns:
            The ordinal number of the copied type.
        """
        result = ida_typeinf.copy_named_type(source, destination, name)
        if result == 0:
            raise RuntimeError(f'error exporting type {name}')
        return result

    def parse_header_file(
        self,
        library: til_t,
        header: Path,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_FIL | TypeFormattingFlags.HTI_PAKDEF,
    ) -> int:
        """
        Parse type declarations from file and store created types into a library.

        Args:
            library: The type library into where the parsed types will be stored.
            header: The path to a header file.
            flags: Optional combination of TypeFormattingFlags.

        Returns:
            Number of parse errors.
        """
        return ida_typeinf.parse_decls(library, header, None, flags)

    def parse_declarations(
        self,
        library: til_t,
        decl: str,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_DCL | TypeFormattingFlags.HTI_PAKDEF,
    ) -> int:
        """
        Parse type declarations from string and store created types into a library.

        Args:
            library: The type library into where the parsed types will be stored.
            decl: C type declarations input string.
            flags: Optional combination of TypeFormattingFlags.

        Returns:
            Number of parse errors.
        """
        return ida_typeinf.parse_decls(library, decl, None, flags)

    def parse_one_declaration(
        self,
        library: til_t,
        decl: str,
        name: str,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_DCL | TypeFormattingFlags.HTI_PAKDEF,
    ) -> tinfo_t:
        """
        Parse one declaration from string and create a named type.

        Args:
            library: The type library used for parsing context.
            decl: C type declaration string to parse.
            name: The name to assign to the parsed type.
            flags: Optional combination of TypeFormattingFlags for parsing behavior.

        Returns:
            The tinfo_t instance on success.

        Raises:
            InvalidParameterError: If name/decl is empty, decl cannot be parsed,
                                  or name cannot be used to save the declaration.
        """
        if not name:
            raise InvalidParameterError('name', name, 'cannot be empty')

        if not decl:
            raise InvalidParameterError('decl', decl, 'cannot be empty')

        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, library, decl, flags):
            raise InvalidParameterError('decl', decl, 'cannot be parsed')

        if tif.set_named_type(library, name) < 0:
            raise InvalidParameterError(
                'name', name, f'could not be used to save the parsed declaration {decl}'
            )

        return tif

    def get_by_name(self, name: str, library: til_t = None) -> Optional[tinfo_t]:
        """
        Retrieve a type information object by name.

        Args:
            name: Name of the type to retrieve.
            library: Type library to retrieve from, defaults to local library.

        Returns:
            The named type information object or None if not found.
        """
        if not library:
            library = ida_typeinf.get_idati()
        return library.get_named_type(name)

    def get_at(self, ea: ea_t) -> Optional[tinfo_t]:
        """
        Retrieves the type information of the item at the given address.

        Args:
            ea: The effective address.

        Returns:
            The type information object or None if it does not exist.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        type_info = ida_typeinf.tinfo_t()
        result = ida_nalt.get_tinfo(type_info, ea)
        if result:
            return type_info
        return None

    def apply_at(
        self, type: tinfo_t, ea: ea_t, flags: TypeApplyFlags = TypeApplyFlags.GUESSED
    ) -> bool:
        """
        Applies a named type to the given address.

        Args:
            ea: The effective address.
            type: The name of the type to apply.
            flags: Type apply flags.

        Returns:
            True if the type was applied successfully, false otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_typeinf.apply_tinfo(ea, type, flags)

    def get_all(
        self, library: Optional[til_t] = None, type_kind: TypeKind = TypeKind.NAMED
    ) -> Iterator[ida_typeinf.tinfo_t]:
        """
        Retrieves an iterator over all types in the specified type library.

        Args:
            library: library instance to iterate over (defaults to local library).
            type_kind: type kind to iterate over (defaults to 'NAMED').

        Returns:
            A types iterator.
        """
        til = library
        if not til:
            til = ida_typeinf.get_idati()

        if type_kind == TypeKind.NAMED:
            yield from til.named_types()
        elif type_kind == TypeKind.NUMBERED:
            ida_typeinf.enable_numbered_types(til, True)
            yield from til.numbered_types()

    def traverse(self, type_info: tinfo_t, visitor: ida_typeinf.tinfo_visitor_t) -> None:
        """
        Traverse the given type using the provided visitor class.

        Args:
            type_info: The type information object to visit.
            visitor: A type visitor subclassed object.

        Returns:
            True if traversal was successful, False otherwise.

        """
        return visitor.apply_to(type_info) == 0

    def get_details(self, type_info: tinfo_t) -> TypeDetails:
        """
        Get type details and attributes.

        Args:
            type_info: The type information object for which to gather details.

        Returns:
            Type details object.
        """
        return TypeDetails.from_tinfo_t(type_info)

    def set_comment(self, type_info: tinfo_t, comment: str) -> bool:
        """
        Set comment for type.
        This function works only for non-trivial types

        Args:
            type_info: The type info object to set comment for.
            comment: Comment text to set.

        Returns:
            True if successful, False otherwise.
        """
        return type_info.set_type_cmt(comment) == 0

    def get_comment(self, type_info: tinfo_t) -> str:
        """
        Get comment for type.

        Args:
            type_info: The type info object to get comment from.

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return type_info.get_type_cmt() or ''

    # =========================================================================
    # UDT (Struct/Union) Member Access
    # =========================================================================

    def get_udt_members(self, type_info: tinfo_t) -> Iterator[UdtMemberInfo]:
        """
        Iterate over all members of a struct or union type.

        Args:
            type_info: A UDT (struct or union) type.

        Returns:
            Iterator of UdtMemberInfo for each member.
            Empty iterator if type is not a UDT.

        Example:
            >>> struct_type = db.types.get_by_name("MyStruct")
            >>> for member in db.types.get_udt_members(struct_type):
            ...     print(f"{member.name}: {member.size} bytes at offset {member.offset}")
        """
        if not type_info.is_udt():
            return

        udt_data = udt_type_data_t()
        if not type_info.get_udt_details(udt_data):
            return

        for member in udt_data:
            m: udm_t = member
            byte_offset = int(m.offset) // 8  # Offsets are in bits
            is_bitfield = m.type.is_bitfield()

            bit_offset = None
            bit_size = None
            if is_bitfield:
                bit_offset = int(m.offset) % 8
                bit_size = m.size

            yield UdtMemberInfo(
                name=m.name,
                type=m.type,
                offset=byte_offset,
                size=m.type.get_size(),
                is_bitfield=is_bitfield,
                bit_offset=bit_offset,
                bit_size=bit_size,
            )

    def get_udt_member_by_name(self, type_info: tinfo_t, name: str) -> Optional[UdtMemberInfo]:
        """
        Get a specific UDT member by name.

        Args:
            type_info: A UDT (struct or union) type.
            name: Member name to find.

        Returns:
            UdtMemberInfo if found, None otherwise.
        """
        for member in self.get_udt_members(type_info):
            if member.name == name:
                return member
        return None

    def get_udt_member_by_offset(self, type_info: tinfo_t, offset: int) -> Optional[UdtMemberInfo]:
        """
        Get a UDT member at the specified byte offset.

        Args:
            type_info: A UDT (struct or union) type.
            offset: Byte offset within the structure.

        Returns:
            UdtMemberInfo if found, None otherwise.
        """
        for member in self.get_udt_members(type_info):
            if member.offset == offset:
                return member
        return None

    def get_udt_member_count(self, type_info: tinfo_t) -> int:
        """
        Get the number of members in a UDT.

        Args:
            type_info: A UDT type.

        Returns:
            Member count, or 0 if not a UDT.
        """
        if not type_info.is_udt():
            return 0
        return type_info.get_udt_nmembers()

    # =========================================================================
    # Enum Member Access
    # =========================================================================

    def get_enum_members(self, type_info: tinfo_t) -> Iterator[EnumMemberInfo]:
        """
        Iterate over all members of an enum type.

        Args:
            type_info: An enum type.

        Returns:
            Iterator of EnumMemberInfo for each member.
            Empty iterator if type is not an enum.

        Example:
            >>> enum_type = db.types.get_by_name("FileMode")
            >>> for member in db.types.get_enum_members(enum_type):
            ...     print(f"{member.name} = {member.value}")
        """
        if not type_info.is_enum():
            return

        for e in type_info.iter_enum():
            yield EnumMemberInfo(name=e.name, value=e.value)

    def get_enum_member_by_name(self, type_info: tinfo_t, name: str) -> Optional[EnumMemberInfo]:
        """
        Get a specific enum member by name.

        Args:
            type_info: An enum type.
            name: Member name to find.

        Returns:
            EnumMemberInfo if found, None otherwise.
        """
        for member in self.get_enum_members(type_info):
            if member.name == name:
                return member
        return None

    def get_enum_member_by_value(self, type_info: tinfo_t, value: int) -> Optional[EnumMemberInfo]:
        """
        Get a specific enum member by value.

        Args:
            type_info: An enum type.
            value: Numeric value to find.

        Returns:
            EnumMemberInfo if found, None otherwise.
        """
        for member in self.get_enum_members(type_info):
            if member.value == value:
                return member
        return None

    def get_enum_member_count(self, type_info: tinfo_t) -> int:
        """
        Get the number of members in an enum.

        Args:
            type_info: An enum type.

        Returns:
            Member count, or 0 if not an enum.
        """
        if not type_info.is_enum():
            return 0

        enum_data = enum_type_data_t()
        if type_info.get_enum_details(enum_data):
            return enum_data.size()
        return 0

    # =========================================================================
    # Function Type Access
    # =========================================================================

    def get_func_arguments(self, type_info: tinfo_t) -> Iterator[FuncArgumentInfo]:
        """
        Iterate over all arguments of a function type.

        Args:
            type_info: A function type.

        Returns:
            Iterator of FuncArgumentInfo for each argument.
            Empty iterator if type is not a function.

        Example:
            >>> func_type = db.types.get_at(0x401000)
            >>> for arg in db.types.get_func_arguments(func_type):
            ...     print(f"Arg {arg.index}: {arg.name}")
        """
        if not type_info.is_func():
            return

        for i, arg in enumerate(type_info.iter_func()):
            arg_name = arg.name if arg.name else f'arg{i}'
            yield FuncArgumentInfo(index=i, name=arg_name, type=arg.type)

    def get_func_argument_by_index(
        self, type_info: tinfo_t, index: int
    ) -> Optional[FuncArgumentInfo]:
        """
        Get a specific function argument by index.

        Args:
            type_info: A function type.
            index: Argument index (0-based).

        Returns:
            FuncArgumentInfo if found, None otherwise.
        """
        for arg in self.get_func_arguments(type_info):
            if arg.index == index:
                return arg
        return None

    def get_func_argument_count(self, type_info: tinfo_t) -> int:
        """
        Get the number of arguments in a function type.

        Args:
            type_info: A function type.

        Returns:
            Argument count, or 0 if not a function type.
        """
        if not type_info.is_func():
            return 0

        func_data = func_type_data_t()
        if type_info.get_func_details(func_data):
            return len(func_data)
        return 0

    def get_return_type(self, type_info: tinfo_t) -> Optional[tinfo_t]:
        """
        Get the return type of a function type.

        Args:
            type_info: A function type.

        Returns:
            The return type, or None if not a function type.
        """
        if not type_info.is_func():
            return None
        return type_info.get_rettype()

    # =========================================================================
    # Pointer/Array Type Access
    # =========================================================================

    def get_pointed_type(self, type_info: tinfo_t) -> Optional[tinfo_t]:
        """
        Get the type pointed to by a pointer type.

        Args:
            type_info: A pointer type.

        Returns:
            The pointed-to type, or None if not a pointer.

        Example:
            >>> ptr_type = db.types.get_at(0x401000)  # char*
            >>> base = db.types.get_pointed_type(ptr_type)  # char
        """
        if not type_info.is_ptr() and not type_info.is_funcptr():
            return None
        return type_info.get_pointed_object()

    def get_array_element_type(self, type_info: tinfo_t) -> Optional[tinfo_t]:
        """
        Get the element type of an array type.

        Args:
            type_info: An array type.

        Returns:
            The element type, or None if not an array.
        """
        if not type_info.is_array():
            return None

        array_data = array_type_data_t()
        if type_info.get_array_details(array_data):
            return array_data.elem_type
        return None

    def get_array_length(self, type_info: tinfo_t) -> Optional[int]:
        """
        Get the number of elements in an array type.

        Args:
            type_info: An array type.

        Returns:
            The array length, or None if not an array.
        """
        if not type_info.is_array():
            return None

        array_data = array_type_data_t()
        if type_info.get_array_details(array_data):
            return array_data.nelems
        return None

    # =========================================================================
    # Type Creation Methods
    # =========================================================================

    def create_void(self) -> tinfo_t:
        """
        Create a void type.

        Returns:
            A void tinfo_t.
        """
        result = tinfo_t()
        result.create_simple_type(BT_VOID)
        return result

    def create_primitive(self, size: int, signed: bool = True) -> tinfo_t:
        """
        Create a primitive integer type.

        Args:
            size: Size in bytes (1, 2, 4, or 8).
            signed: True for signed, False for unsigned.

        Returns:
            The primitive type.

        Raises:
            InvalidParameterError: If size is not 1, 2, 4, or 8.

        Example:
            >>> int32 = db.types.create_primitive(4, signed=True)
            >>> uint8 = db.types.create_primitive(1, signed=False)
        """
        size_to_type = {
            1: BT_INT8,
            2: BT_INT16,
            4: BT_INT32,
            8: BT_INT64,
        }

        if size not in size_to_type:
            raise InvalidParameterError('size', size, 'must be 1, 2, 4, or 8')

        result = tinfo_t()
        result.create_simple_type(size_to_type[size])
        return result

    def create_float(self, size: int = 4) -> tinfo_t:
        """
        Create a floating-point type.

        Args:
            size: 4 for float, 8 for double.

        Returns:
            The floating-point type.

        Raises:
            InvalidParameterError: If size is not 4 or 8.
        """
        if size == 4:
            result = tinfo_t()
            result.create_simple_type(BT_FLOAT)
            return result
        elif size == 8:
            result = tinfo_t()
            result.create_simple_type(BT_FLOAT | BTMT_DOUBLE)
            return result
        else:
            raise InvalidParameterError('size', size, 'must be 4 or 8')

    def create_pointer(self, target: tinfo_t) -> tinfo_t:
        """
        Create a pointer type.

        Args:
            target: The type being pointed to.

        Returns:
            A pointer to the target type.

        Example:
            >>> char_type = db.types.create_primitive(1)
            >>> char_ptr = db.types.create_pointer(char_type)
        """
        result = tinfo_t()
        result.create_ptr(target)
        return result

    def create_array(self, element_type: tinfo_t, count: int) -> tinfo_t:
        """
        Create an array type.

        Args:
            element_type: Type of array elements.
            count: Number of elements.

        Returns:
            The array type.

        Example:
            >>> char_type = db.types.create_primitive(1)
            >>> buffer = db.types.create_array(char_type, 256)
        """
        array_data = array_type_data_t()
        array_data.elem_type = element_type
        array_data.nelems = count
        array_data.base = 0

        result = tinfo_t()
        result.create_array(array_data)
        return result

    # =========================================================================
    # Builder Factory Methods
    # =========================================================================

    def create_struct(self, name: str) -> StructBuilder:
        """
        Create a struct builder.

        Args:
            name: Name for the struct.

        Returns:
            A StructBuilder for constructing the type.

        Example:
            >>> point = db.types.create_struct("Point") \\
            ...     .add_member("x", db.types.create_primitive(4)) \\
            ...     .add_member("y", db.types.create_primitive(4)) \\
            ...     .build()
        """
        return StructBuilder(name)

    def create_union(self, name: str) -> UnionBuilder:
        """
        Create a union builder.

        Args:
            name: Name for the union.

        Returns:
            A UnionBuilder for constructing the type.
        """
        return UnionBuilder(name)

    def create_enum(self, name: str, base_size: int = 4) -> EnumBuilder:
        """
        Create an enum builder.

        Args:
            name: Name for the enum.
            base_size: Underlying integer size (1, 2, 4, or 8).

        Returns:
            An EnumBuilder for constructing the type.
        """
        return EnumBuilder(name, base_size)

    def create_func_type(self) -> FuncTypeBuilder:
        """
        Create a function type builder.

        Returns:
            A FuncTypeBuilder for constructing the type.
        """
        return FuncTypeBuilder()

    # =========================================================================
    # Unified LLM-Friendly Interface
    # =========================================================================

    def get_member(
        self,
        type_info: tinfo_t,
        key: Union[str, int],
        by: Union[TypeMemberLookupMode, str] = TypeMemberLookupMode.NAME,
    ) -> Optional[Union[UdtMemberInfo, EnumMemberInfo, FuncArgumentInfo]]:
        """
        Get a type member (LLM-friendly unified interface).

        Works for struct/union members, enum members, and function arguments.

        Args:
            type_info: The type to inspect.
            key: Lookup key (name, offset, index, or value depending on 'by').
            by: Lookup mode:
                - "name": Look up by member/argument name
                - "offset": Look up by byte offset (UDT only)
                - "index": Look up by index (enum, func args)
                - "value": Look up by enum value (enum only)

        Returns:
            The member info if found, None otherwise.

        Example:
            >>> # Get struct member by name
            >>> member = db.types.get_member(struct_type, "x", by="name")
            >>> # Get struct member by offset
            >>> member = db.types.get_member(struct_type, 4, by="offset")
            >>> # Get function argument by index
            >>> arg = db.types.get_member(func_type, 0, by="index")
        """
        # Normalize mode
        if isinstance(by, str):
            by = TypeMemberLookupMode(by)

        if by == TypeMemberLookupMode.NAME:
            if not isinstance(key, str):
                raise InvalidParameterError('key', key, "must be a string when by='name'")
            if type_info.is_udt():
                return self.get_udt_member_by_name(type_info, key)
            elif type_info.is_enum():
                return self.get_enum_member_by_name(type_info, key)
            # Function arguments don't typically have meaningful names to search by
            return None

        elif by == TypeMemberLookupMode.OFFSET:
            if not isinstance(key, int):
                raise InvalidParameterError('key', key, "must be an int when by='offset'")
            if type_info.is_udt():
                return self.get_udt_member_by_offset(type_info, key)
            return None

        elif by == TypeMemberLookupMode.INDEX:
            if not isinstance(key, int):
                raise InvalidParameterError('key', key, "must be an int when by='index'")
            if type_info.is_func():
                return self.get_func_argument_by_index(type_info, key)
            return None

        elif by == TypeMemberLookupMode.VALUE:
            if not isinstance(key, int):
                raise InvalidParameterError('key', key, "must be an int when by='value'")
            if type_info.is_enum():
                return self.get_enum_member_by_value(type_info, key)
            return None

        return None

    def get_members(
        self, type_info: tinfo_t
    ) -> Iterator[Union[UdtMemberInfo, EnumMemberInfo, FuncArgumentInfo]]:
        """
        Get all members of a type (LLM-friendly unified interface).

        Works for struct/union types, enum types, and function types.

        Args:
            type_info: The type to inspect.

        Returns:
            Iterator of member info objects.
            Empty iterator if type has no members.

        Example:
            >>> for member in db.types.get_members(struct_type):
            ...     print(f"{member.name}")
        """
        if type_info.is_udt():
            yield from self.get_udt_members(type_info)
        elif type_info.is_enum():
            yield from self.get_enum_members(type_info)
        elif type_info.is_func():
            yield from self.get_func_arguments(type_info)
