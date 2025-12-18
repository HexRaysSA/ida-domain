from __future__ import annotations

import logging
import warnings
from enum import Enum, EnumMeta, Flag, IntEnum, IntFlag, auto
from pathlib import Path

import ida_nalt
import ida_typeinf
from ida_typeinf import (
    array_type_data_t,
    bitfield_type_data_t,
    enum_type_data_t,
    func_type_data_t,
    ptr_type_data_t,
    til_t,
    tinfo_t,
    udt_type_data_t,
)
from typing_extensions import TYPE_CHECKING, Callable, Dict, Iterator, Optional, Tuple

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

    def get_by_ordinal(self, ordinal: int, library: Optional[til_t] = None) -> Optional[tinfo_t]:
        """
        Retrieve a type information object by its ordinal number.

        Ordinals are numeric identifiers for types in a type library. This method enables
        lookup of types by their numeric ID rather than by name.

        Args:
            ordinal: The ordinal number of the type to retrieve. Must be positive.
            library: Type library to retrieve from. If None, uses the local (database) library.

        Returns:
            The type information object if found, None if the ordinal doesn't exist.

        Example:
            >>> db = Database.open_current()
            >>> # Get type at ordinal 5
            >>> type_info = db.types.get_by_ordinal(5)
            >>> if type_info:
            ...     print(f"Type name: {type_info.get_type_name()}")
        """
        if not library:
            library = ida_typeinf.get_idati()

        # Enable numbered types for this library
        ida_typeinf.enable_numbered_types(library, True)

        # Try to get the type using set_numbered_type
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(library, ordinal):
            return tif

        return None

    def get_ordinal(self, name: str, library: Optional[til_t] = None) -> Optional[int]:
        """
        Get the ordinal number of a named type.

        Each named type in a library can be referenced by both its name and a numeric ordinal.
        This method maps from name to ordinal.

        Args:
            name: The name of the type to look up.
            library: Type library to search. If None, uses the local (database) library.

        Returns:
            The ordinal number of the named type, or None if not found.

        Example:
            >>> db = Database.open_current()
            >>> ordinal = db.types.get_ordinal("size_t")
            >>> if ordinal:
            ...     print(f"size_t has ordinal {ordinal}")
        """
        if not library:
            library = ida_typeinf.get_idati()

        ordinal = ida_typeinf.get_type_ordinal(library, name)
        if ordinal == 0:  # 0 means not found
            return None

        return ordinal

    def apply_by_name(
        self,
        ea: ea_t,
        name: str,
        flags: TypeApplyFlags = TypeApplyFlags.DEFINITE
    ) -> bool:
        """
        Apply a named type to the given address.

        This is a convenience method that looks up a type by name and applies it to an
        address in a single operation.

        Args:
            ea: The effective address where the type should be applied.
            name: The name of the type to apply (e.g., "size_t", "HWND").
            flags: Type apply flags controlling how the type is applied.

        Returns:
            True if the type was applied successfully, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Apply HWND type to a global variable
            >>> success = db.types.apply_by_name(0x401000, "HWND")
            >>> if success:
            ...     print("Type applied successfully")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return ida_typeinf.apply_named_type(ea, name)

    def apply_declaration(
        self,
        ea: ea_t,
        decl: str,
        flags: TypeFormattingFlags = TypeFormattingFlags.HTI_DCL
    ) -> bool:
        """
        Parse a C declaration and apply it directly to an address.

        This method parses a C-style type declaration string and applies the parsed type
        to the specified address in a single operation.

        Args:
            ea: The effective address where the type should be applied.
            decl: The C declaration string (e.g., "int *", "struct foo", "void (__cdecl *)(int)").
            flags: Type formatting flags for parsing the declaration.

        Returns:
            True if the declaration was parsed and applied successfully, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If the declaration string is empty.

        Example:
            >>> db = Database.open_current()
            >>> # Apply a function pointer type
            >>> success = db.types.apply_declaration(0x401000, "void (__cdecl *)(int, char*)")
            >>> if success:
            ...     print("Function type applied")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if not decl:
            raise InvalidParameterError('decl', decl, 'cannot be empty')

        # Get local library for parsing context
        til = ida_typeinf.get_idati()

        # Apply C declaration directly
        return ida_typeinf.apply_cdecl(til, ea, decl, flags)

    def guess_at(self, ea: ea_t) -> Optional[tinfo_t]:
        """
        Leverage IDA's type inference to guess the type at an address.

        IDA Pro has sophisticated type inference capabilities that can deduce types from
        usage patterns, cross-references, and context. This method invokes IDA's type
        guessing engine for a specific address.

        Args:
            ea: The effective address for which to infer the type.

        Returns:
            The inferred type information if successful, None if type cannot be guessed.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Let IDA guess the type of a function
            >>> guessed_type = db.types.guess_at(0x401000)
            >>> if guessed_type:
            ...     print(f"Guessed type: {db.types.format_type(guessed_type)}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        tif = ida_typeinf.tinfo_t()
        result = ida_typeinf.guess_tinfo(tif, ea)

        # guess_tinfo returns GUESS_FUNC_* codes
        # Non-zero means successful guess
        if result != 0:
            return tif

        return None

    def format_type(
        self,
        type_info: tinfo_t,
        flags: TypeFormattingFlags = TypeFormattingFlags(0)
    ) -> str:
        """
        Format a type as a C declaration string.

        Converts a type information object into a human-readable C-style declaration string.
        The formatting can be customized with flags to control aspects like typedef expansion,
        spacing, and comment inclusion.

        Args:
            type_info: The type information object to format.
            flags: Formatting flags controlling the output style.

        Returns:
            A C-style declaration string representing the type.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("size_t")
            >>> if type_info:
            ...     decl = db.types.format_type(type_info)
            ...     print(f"Declaration: {decl}")
        """
        return type_info.dstr()

    def format_type_at(
        self,
        ea: ea_t,
        flags: TypeFormattingFlags = TypeFormattingFlags(0)
    ) -> Optional[str]:
        """
        Format the type at an address as a C declaration string.

        This is a convenience method that retrieves the type at an address and formats it
        as a C declaration in a single operation.

        Args:
            ea: The effective address of the item to format.
            flags: Formatting flags controlling the output style.

        Returns:
            A C-style declaration string, or None if no type exists at the address.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Format the type of a global variable
            >>> decl = db.types.format_type_at(0x401000)
            >>> if decl:
            ...     print(f"Type: {decl}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Use print_type to format the type at an address
        result = ida_typeinf.print_type(ea, False)  # False = don't force one line
        if result:
            return result

        return None

    def compare_types(self, type1: tinfo_t, type2: tinfo_t) -> bool:
        """
        Check if two types are structurally equivalent.

        Performs a structural comparison of two type information objects to determine if
        they represent the same type, even if they have different names or come from
        different libraries.

        Args:
            type1: The first type to compare.
            type2: The second type to compare.

        Returns:
            True if the types are equivalent, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> type1 = db.types.get_by_name("size_t")
            >>> type2 = db.types.get_by_name("unsigned long")
            >>> if type1 and type2:
            ...     if db.types.compare_types(type1, type2):
            ...         print("Types are equivalent")
        """
        # compare_tinfo returns 0 if types are equal
        result = ida_typeinf.compare_tinfo(type1, type2, 0)
        return result == 0

    def validate_type(self, type_info: tinfo_t) -> bool:
        """
        Validate that a type is well-formed and correct.

        Checks whether a type information object is valid according to IDA's type system
        rules. This includes verifying that the type is properly constructed, all
        references are resolved, and the type conforms to language semantics.

        Args:
            type_info: The type information object to validate.

        Returns:
            True if the type is valid, False if it contains errors.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("MyStruct")
            >>> if type_info and db.types.validate_type(type_info):
            ...     print("Type is well-formed")
        """
        return ida_typeinf.verify_tinfo(type_info)

    def resolve_typedef(self, type_info: tinfo_t) -> tinfo_t:
        """
        Follow typedef chains to get the underlying concrete type.

        When a type is a typedef (type alias), this method resolves it to the actual
        underlying type. If the type is not a typedef, returns an equivalent type.

        Args:
            type_info: The type information object to resolve.

        Returns:
            A new type information object with typedefs resolved.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("DWORD")  # Often typedef to unsigned long
            >>> resolved = db.types.resolve_typedef(type_info)
            >>> print(f"DWORD resolves to: {db.types.format_type(resolved)}")
        """
        # Create a copy to avoid modifying original
        result = ida_typeinf.tinfo_t()
        ida_typeinf.copy_tinfo_t(result, type_info)

        # Resolve typedef chain in-place
        ida_typeinf.resolve_typedef(result)

        return result

    def remove_pointer(self, type_info: tinfo_t) -> Optional[tinfo_t]:
        """
        Strip pointer/reference from a type to get the pointed-to type.

        If the given type is a pointer or reference, returns the type being pointed to.
        For example, "int *" would return "int".

        Args:
            type_info: The type information object to dereference.

        Returns:
            The pointed-to type if the input is a pointer, None otherwise.

        Example:
            >>> db = Database.open_current()
            >>> ptr_type = db.types.get_at(0x401000)  # Assume this is "char *"
            >>> if ptr_type:
            ...     base_type = db.types.remove_pointer(ptr_type)
            ...     if base_type:
            ...         print(f"Points to: {db.types.format_type(base_type)}")
        """
        # Check if it's actually a pointer
        if not type_info.is_ptr():
            return None

        # Create a copy to modify
        result = ida_typeinf.tinfo_t()
        ida_typeinf.copy_tinfo_t(result, type_info)

        # Remove pointer modifier
        if ida_typeinf.remove_pointer(result):
            return result

        return None

    def is_enum(self, type_info: tinfo_t) -> bool:
        """
        Check if a type is an enumeration.

        Args:
            type_info: The type information object to test.

        Returns:
            True if the type is an enum, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("MyEnum")
            >>> if type_info and db.types.is_enum(type_info):
            ...     print("Type is an enumeration")
        """
        return type_info.is_enum()

    def is_struct(self, type_info: tinfo_t) -> bool:
        """
        Check if a type is a structure.

        Args:
            type_info: The type information object to test.

        Returns:
            True if the type is a struct, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("MyStruct")
            >>> if type_info and db.types.is_struct(type_info):
            ...     print("Type is a structure")
        """
        return type_info.is_struct()

    def is_union(self, type_info: tinfo_t) -> bool:
        """
        Check if a type is a union.

        Args:
            type_info: The type information object to test.

        Returns:
            True if the type is a union, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("MyUnion")
            >>> if type_info and db.types.is_union(type_info):
            ...     print("Type is a union")
        """
        return type_info.is_union()

    def is_udt(self, type_info: tinfo_t) -> bool:
        """
        Check if a type is a user-defined type (structure or union).

        A UDT (User-Defined Type) is either a struct or a union. This method is equivalent
        to `is_struct(type_info) or is_union(type_info)`.

        Args:
            type_info: The type information object to test.

        Returns:
            True if the type is a UDT (struct or union), False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> type_info = db.types.get_by_name("SomeType")
            >>> if type_info and db.types.is_udt(type_info):
            ...     print("Type is a user-defined type")
        """
        return type_info.is_udt()
