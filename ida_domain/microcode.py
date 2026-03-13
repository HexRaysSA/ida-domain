from __future__ import annotations

import logging
from enum import IntEnum, IntFlag

import ida_hexrays
import ida_idaapi
import ida_lines
import ida_range
from ida_funcs import func_t
from ida_hexrays import (
    lvar_t,
    lvars_t,
    mba_t,
    mblock_t,
    mcallarg_t,
    mcallinfo_t,
    minsn_t,
    mlist_t,
    mop_t,
)
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional, Tuple

from .base import DatabaseEntity, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from ida_hexrays import ivlset_t, valrng_t, vdloc_t, vivl_t
    from ida_idaapi import ea_t
    from ida_typeinf import argloc_t, tinfo_t

    from .database import Database

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class MicroMaturity(IntEnum):
    """Microcode maturity levels corresponding to MMAT_* constants."""

    ZERO = ida_hexrays.MMAT_ZERO
    GENERATED = ida_hexrays.MMAT_GENERATED
    PREOPTIMIZED = ida_hexrays.MMAT_PREOPTIMIZED
    LOCOPT = ida_hexrays.MMAT_LOCOPT
    CALLS = ida_hexrays.MMAT_CALLS
    GLBOPT1 = ida_hexrays.MMAT_GLBOPT1
    GLBOPT2 = ida_hexrays.MMAT_GLBOPT2
    GLBOPT3 = ida_hexrays.MMAT_GLBOPT3
    LVARS = ida_hexrays.MMAT_LVARS


class MicroOpcode(IntEnum):
    """Microcode instruction opcodes corresponding to m_* constants."""

    # No-operation / data movement
    NOP = ida_hexrays.m_nop
    STX = ida_hexrays.m_stx
    LDX = ida_hexrays.m_ldx
    LDC = ida_hexrays.m_ldc
    MOV = ida_hexrays.m_mov
    NEG = ida_hexrays.m_neg
    LNOT = ida_hexrays.m_lnot
    BNOT = ida_hexrays.m_bnot
    XDS = ida_hexrays.m_xds
    XDU = ida_hexrays.m_xdu
    LOW = ida_hexrays.m_low
    HIGH = ida_hexrays.m_high

    # Arithmetic
    ADD = ida_hexrays.m_add
    SUB = ida_hexrays.m_sub
    MUL = ida_hexrays.m_mul
    UDIV = ida_hexrays.m_udiv
    SDIV = ida_hexrays.m_sdiv
    UMOD = ida_hexrays.m_umod
    SMOD = ida_hexrays.m_smod

    # Bitwise
    OR = ida_hexrays.m_or
    AND = ida_hexrays.m_and
    XOR = ida_hexrays.m_xor
    SHL = ida_hexrays.m_shl
    SHR = ida_hexrays.m_shr
    SAR = ida_hexrays.m_sar

    # Comparison / set
    SETNZ = ida_hexrays.m_setnz
    SETZ = ida_hexrays.m_setz
    SETAE = ida_hexrays.m_setae
    SETB = ida_hexrays.m_setb
    SETA = ida_hexrays.m_seta
    SETBE = ida_hexrays.m_setbe
    SETP = ida_hexrays.m_setp
    SETS = ida_hexrays.m_sets
    SETO = ida_hexrays.m_seto
    CFADD = ida_hexrays.m_cfadd
    OFADD = ida_hexrays.m_ofadd
    CFSHL = ida_hexrays.m_cfshl
    CFSHR = ida_hexrays.m_cfshr

    # Signed comparison / set
    SETG = ida_hexrays.m_setg
    SETGE = ida_hexrays.m_setge
    SETL = ida_hexrays.m_setl
    SETLE = ida_hexrays.m_setle

    # Control flow
    GOTO = ida_hexrays.m_goto
    JNZ = ida_hexrays.m_jnz
    JZ = ida_hexrays.m_jz
    JAE = ida_hexrays.m_jae
    JB = ida_hexrays.m_jb
    JA = ida_hexrays.m_ja
    JBE = ida_hexrays.m_jbe
    JG = ida_hexrays.m_jg
    JGE = ida_hexrays.m_jge
    JL = ida_hexrays.m_jl
    JLE = ida_hexrays.m_jle
    JTBL = ida_hexrays.m_jtbl
    IJMP = ida_hexrays.m_ijmp
    JCND = ida_hexrays.m_jcnd

    # Calls / returns
    CALL = ida_hexrays.m_call
    ICALL = ida_hexrays.m_icall
    RET = ida_hexrays.m_ret

    # Floating-point
    F2I = ida_hexrays.m_f2i
    F2U = ida_hexrays.m_f2u
    I2F = ida_hexrays.m_i2f
    U2F = ida_hexrays.m_u2f
    F2F = ida_hexrays.m_f2f
    FNEG = ida_hexrays.m_fneg
    FADD = ida_hexrays.m_fadd
    FSUB = ida_hexrays.m_fsub
    FMUL = ida_hexrays.m_fmul
    FDIV = ida_hexrays.m_fdiv

    # Miscellaneous
    PUSH = ida_hexrays.m_push
    POP = ida_hexrays.m_pop
    UND = ida_hexrays.m_und
    EXT = ida_hexrays.m_ext

    # -- category queries --------------------------------------------------

    @property
    def is_conditional_jump(self) -> bool:
        """True for conditional jump opcodes (``jnz`` through ``jle``, plus ``jcnd``)."""
        return ida_hexrays.is_mcode_jcond(self.value)

    @property
    def is_jump(self) -> bool:
        """True for any jump/branch opcode including ``goto``, ``jtbl``, and ``ijmp``."""
        return self.is_conditional_jump or self.value in (
            ida_hexrays.m_goto,
            ida_hexrays.m_jtbl,
            ida_hexrays.m_ijmp,
        )

    @property
    def is_call(self) -> bool:
        """True for call opcodes (``call``, ``icall``)."""
        return ida_hexrays.is_mcode_call(self.value)

    @property
    def is_flow(self) -> bool:
        """True for any control-flow opcode (jumps, calls, ``ret``)."""
        return self.is_jump or self.is_call or self.value == ida_hexrays.m_ret

    @property
    def is_set(self) -> bool:
        """True for set-condition opcodes (``setnz`` through ``setle``)."""
        return ida_hexrays.is_mcode_set(self.value)

    @property
    def is_commutative(self) -> bool:
        """True for commutative opcodes.

        Includes ``add``, ``mul``, ``or``, ``and``, ``xor``,
        ``setz``, ``setnz``, ``cfadd``, ``ofadd``.
        """
        return ida_hexrays.is_mcode_commutative(self.value)

    @property
    def is_fpu(self) -> bool:
        """True for floating-point opcodes (``f2i`` through ``fdiv``)."""
        return ida_hexrays.is_mcode_fpu(self.value)

    @property
    def is_propagatable(self) -> bool:
        """True if this opcode may appear in a sub-instruction (nested ``mop_d``).

        Non-propagatable opcodes include jumps, ``ret``, ``nop``, etc.
        """
        return ida_hexrays.is_mcode_propagatable(self.value)

    @property
    def is_unary(self) -> bool:
        """True for unary opcodes (``neg``, ``lnot``, ``bnot``, ``fneg``)."""
        return self.value in (
            ida_hexrays.m_neg,
            ida_hexrays.m_lnot,
            ida_hexrays.m_bnot,
            ida_hexrays.m_fneg,
        )

    @property
    def is_shift(self) -> bool:
        """True for shift opcodes (``shl``, ``shr``, ``sar``)."""
        return ida_hexrays.is_mcode_shift(self.value)

    @property
    def is_arithmetic(self) -> bool:
        """True for integer arithmetic opcodes.

        Includes ``add``, ``sub``, ``mul``, ``udiv``, ``sdiv``,
        ``umod``, ``smod``.
        """
        return self.value in (
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_mul,
            ida_hexrays.m_udiv,
            ida_hexrays.m_sdiv,
            ida_hexrays.m_umod,
            ida_hexrays.m_smod,
        )

    @property
    def is_bitwise(self) -> bool:
        """True for bitwise opcodes (``or``, ``and``, ``xor``, ``shl``, ``shr``, ``sar``)."""
        return self.value in (
            ida_hexrays.m_or,
            ida_hexrays.m_and,
            ida_hexrays.m_xor,
            ida_hexrays.m_shl,
            ida_hexrays.m_shr,
            ida_hexrays.m_sar,
        )

    @property
    def is_addsub(self) -> bool:
        """True for addition/subtraction opcodes (``add``, ``sub``)."""
        return ida_hexrays.is_mcode_addsub(self.value)

    @property
    def is_xdsu(self) -> bool:
        """True for sign/zero extension opcodes (``xds``, ``xdu``)."""
        return ida_hexrays.is_mcode_xdsu(self.value)

    @property
    def is_convertible_to_jump(self) -> bool:
        """True if this set-condition opcode has a corresponding jump opcode."""
        return ida_hexrays.is_mcode_convertible_to_jmp(self.value)

    @property
    def is_convertible_to_set(self) -> bool:
        """True if this jump opcode has a corresponding set-condition opcode."""
        return ida_hexrays.is_mcode_convertible_to_set(self.value)


class MicroOperandType(IntEnum):
    """Microcode operand types corresponding to mop_* constants."""

    EMPTY = ida_hexrays.mop_z
    REGISTER = ida_hexrays.mop_r
    NUMBER = ida_hexrays.mop_n
    STRING = ida_hexrays.mop_str
    SUB_INSN = ida_hexrays.mop_d
    STACK_VAR = ida_hexrays.mop_S
    GLOBAL_ADDR = ida_hexrays.mop_v
    BLOCK_REF = ida_hexrays.mop_b
    CALL_INFO = ida_hexrays.mop_f
    LOCAL_VAR = ida_hexrays.mop_l
    ADDR_OF = ida_hexrays.mop_a
    HELPER = ida_hexrays.mop_h
    CASE = ida_hexrays.mop_c
    FP_CONST = ida_hexrays.mop_fn
    PAIR = ida_hexrays.mop_p
    SCATTERED = ida_hexrays.mop_sc


class MicroBlockType(IntEnum):
    """Basic block types corresponding to BLT_* constants."""

    NONE = ida_hexrays.BLT_NONE
    STOP = ida_hexrays.BLT_STOP
    ZERO_WAY = ida_hexrays.BLT_0WAY
    ONE_WAY = ida_hexrays.BLT_1WAY
    TWO_WAY = ida_hexrays.BLT_2WAY
    N_WAY = ida_hexrays.BLT_NWAY
    EXTERNAL = ida_hexrays.BLT_XTRN


class MicroBlockFlags(IntFlag):
    """Block flags corresponding to MBL_* constants."""

    PRIV = ida_hexrays.MBL_PRIV
    NONFAKE = ida_hexrays.MBL_NONFAKE
    FAKE = ida_hexrays.MBL_FAKE
    GOTO = ida_hexrays.MBL_GOTO
    TCAL = ida_hexrays.MBL_TCAL
    PUSH = ida_hexrays.MBL_PUSH
    DMT64 = ida_hexrays.MBL_DMT64
    COMB = ida_hexrays.MBL_COMB
    PROP = ida_hexrays.MBL_PROP
    DEAD = ida_hexrays.MBL_DEAD
    LIST = ida_hexrays.MBL_LIST
    INCONST = ida_hexrays.MBL_INCONST
    CALL = ida_hexrays.MBL_CALL
    BACKPROP = ida_hexrays.MBL_BACKPROP
    NORET = ida_hexrays.MBL_NORET
    DSLOT = ida_hexrays.MBL_DSLOT
    VALRANGES = ida_hexrays.MBL_VALRANGES


class MicroError(IntEnum):
    """Microcode error/return codes corresponding to MERR_* constants."""

    # Success / control flow
    OK = ida_hexrays.MERR_OK
    BLOCK = ida_hexrays.MERR_BLOCK

    # Fatal errors (negative values)
    INTERR = ida_hexrays.MERR_INTERR
    INSN = ida_hexrays.MERR_INSN
    MEM = ida_hexrays.MERR_MEM
    BADBLK = ida_hexrays.MERR_BADBLK
    BADSP = ida_hexrays.MERR_BADSP
    PROLOG = ida_hexrays.MERR_PROLOG
    SWITCH = ida_hexrays.MERR_SWITCH
    EXCEPTION = ida_hexrays.MERR_EXCEPTION
    HUGESTACK = ida_hexrays.MERR_HUGESTACK
    LVARS = ida_hexrays.MERR_LVARS
    BITNESS = ida_hexrays.MERR_BITNESS
    BADCALL = ida_hexrays.MERR_BADCALL
    BADFRAME = ida_hexrays.MERR_BADFRAME
    UNKTYPE = ida_hexrays.MERR_UNKTYPE
    BADIDB = ida_hexrays.MERR_BADIDB
    SIZEOF = ida_hexrays.MERR_SIZEOF
    REDO = ida_hexrays.MERR_REDO
    CANCELED = ida_hexrays.MERR_CANCELED
    RECDEPTH = ida_hexrays.MERR_RECDEPTH
    OVERLAP = ida_hexrays.MERR_OVERLAP
    PARTINIT = ida_hexrays.MERR_PARTINIT
    COMPLEX = ida_hexrays.MERR_COMPLEX
    LICENSE = ida_hexrays.MERR_LICENSE
    ONLY32 = ida_hexrays.MERR_ONLY32
    ONLY64 = ida_hexrays.MERR_ONLY64
    BUSY = ida_hexrays.MERR_BUSY
    FARPTR = ida_hexrays.MERR_FARPTR
    EXTERN = ida_hexrays.MERR_EXTERN
    FUNCSIZE = ida_hexrays.MERR_FUNCSIZE
    BADRANGES = ida_hexrays.MERR_BADRANGES
    BADARCH = ida_hexrays.MERR_BADARCH
    DSLOT = ida_hexrays.MERR_DSLOT
    STOP = ida_hexrays.MERR_STOP
    CLOUD = ida_hexrays.MERR_CLOUD
    EMULATOR = ida_hexrays.MERR_EMULATOR
    LOOP = ida_hexrays.MERR_LOOP


class MicrocodeError(Exception):
    """Raised when microcode generation or decompilation fails.

    Attributes:
        code: The :class:`MicroError` code (``None`` if not available).
        errea: The address where the error occurred (``None`` if not available).
    """

    def __init__(
        self,
        message: str,
        code: Optional[MicroError] = None,
        errea: Optional[int] = None,
    ):
        self.code = code
        self.errea = errea
        super().__init__(message)


class DecompilationFlags(IntFlag):
    """Decompilation flags passed to microcode generation (``DECOMP_*``)."""

    NO_WAIT = ida_hexrays.DECOMP_NO_WAIT
    NO_CACHE = ida_hexrays.DECOMP_NO_CACHE
    NO_FRAME = ida_hexrays.DECOMP_NO_FRAME
    WARNINGS = ida_hexrays.DECOMP_WARNINGS
    ALL_BLKS = ida_hexrays.DECOMP_ALL_BLKS
    NO_HIDE = ida_hexrays.DECOMP_NO_HIDE
    GXREFS_DEFLT = ida_hexrays.DECOMP_GXREFS_DEFLT
    GXREFS_NOUPD = ida_hexrays.DECOMP_GXREFS_NOUPD
    GXREFS_FORCE = ida_hexrays.DECOMP_GXREFS_FORCE
    VOID_MBA = ida_hexrays.DECOMP_VOID_MBA


class AnalyzeCallsFlags(IntFlag):
    """Flags for :meth:`MicroBlockArray.analyze_calls` (``ACFL_*``)."""

    LOCOPT = ida_hexrays.ACFL_LOCOPT
    BLKOPT = ida_hexrays.ACFL_BLKOPT
    GLBPROP = ida_hexrays.ACFL_GLBPROP
    GLBDEL = ida_hexrays.ACFL_GLBDEL
    GUESS = ida_hexrays.ACFL_GUESS


class MbaFlags(IntFlag):
    """Microcode block-array flags (``MBA_*``).

    These control display options, optimization requests, and
    internal state of the :class:`MicroBlockArray`.
    """

    # Display / output
    SHORT = ida_hexrays.MBA_SHORT
    COLGDL = ida_hexrays.MBA_COLGDL
    INSGDL = ida_hexrays.MBA_INSGDL
    NICE = ida_hexrays.MBA_NICE
    NUMADDR = ida_hexrays.MBA_NUMADDR
    VALNUM = ida_hexrays.MBA_VALNUM

    # Optimization requests
    CMBBLK = ida_hexrays.MBA_CMBBLK
    PREOPT = ida_hexrays.MBA_PREOPT
    GLBOPT = ida_hexrays.MBA_GLBOPT
    REFINE = ida_hexrays.MBA_REFINE

    # Function properties
    PRCDEFS = ida_hexrays.MBA_PRCDEFS
    NOFUNC = ida_hexrays.MBA_NOFUNC
    PATTERN = ida_hexrays.MBA_PATTERN
    LOADED = ida_hexrays.MBA_LOADED
    RETFP = ida_hexrays.MBA_RETFP
    SPLINFO = ida_hexrays.MBA_SPLINFO
    PASSREGS = ida_hexrays.MBA_PASSREGS
    THUNK = ida_hexrays.MBA_THUNK
    CMNSTK = ida_hexrays.MBA_CMNSTK

    # Internal state
    ASRTOK = ida_hexrays.MBA_ASRTOK
    CALLS = ida_hexrays.MBA_CALLS
    ASRPROP = ida_hexrays.MBA_ASRPROP
    SAVRST = ida_hexrays.MBA_SAVRST
    RETREF = ida_hexrays.MBA_RETREF
    LVARS0 = ida_hexrays.MBA_LVARS0
    LVARS1 = ida_hexrays.MBA_LVARS1
    DELPAIRS = ida_hexrays.MBA_DELPAIRS
    CHVARS = ida_hexrays.MBA_CHVARS


class CopyBlockFlags(IntFlag):
    """Flags for :meth:`MicroBlockArray.copy_block` (``CPBLK_*``)."""

    FAST = ida_hexrays.CPBLK_FAST
    MINREF = ida_hexrays.CPBLK_MINREF
    OPTJMP = ida_hexrays.CPBLK_OPTJMP


class AccessType(IntEnum):
    """Access type for use-def list building (``MUST_ACCESS`` / ``MAY_ACCESS``)."""

    MAY = ida_hexrays.MAY_ACCESS
    MUST = ida_hexrays.MUST_ACCESS


class CallInfoFlags(IntFlag):
    """Call information flags (``FCI_*``)."""

    PROP = ida_hexrays.FCI_PROP
    DEAD = ida_hexrays.FCI_DEAD
    FINAL = ida_hexrays.FCI_FINAL
    NORET = ida_hexrays.FCI_NORET
    PURE = ida_hexrays.FCI_PURE
    NOSIDE = ida_hexrays.FCI_NOSIDE
    SPLOK = ida_hexrays.FCI_SPLOK
    HASCALL = ida_hexrays.FCI_HASCALL
    HASFMT = ida_hexrays.FCI_HASFMT
    EXPLOCS = ida_hexrays.FCI_EXPLOCS


class FunctionRole(IntEnum):
    """Function role constants (``ROLE_*``)."""

    UNK = ida_hexrays.ROLE_UNK
    EMPTY = ida_hexrays.ROLE_EMPTY
    MEMSET = ida_hexrays.ROLE_MEMSET
    MEMSET32 = ida_hexrays.ROLE_MEMSET32
    MEMSET64 = ida_hexrays.ROLE_MEMSET64
    MEMCPY = ida_hexrays.ROLE_MEMCPY
    STRCPY = ida_hexrays.ROLE_STRCPY
    STRLEN = ida_hexrays.ROLE_STRLEN
    STRCAT = ida_hexrays.ROLE_STRCAT
    TAIL = ida_hexrays.ROLE_TAIL
    BUG = ida_hexrays.ROLE_BUG
    ALLOCA = ida_hexrays.ROLE_ALLOCA
    BSWAP = ida_hexrays.ROLE_BSWAP
    PRESENT = ida_hexrays.ROLE_PRESENT
    CONTAINING_RECORD = ida_hexrays.ROLE_CONTAINING_RECORD
    FASTFAIL = ida_hexrays.ROLE_FASTFAIL
    READFLAGS = ida_hexrays.ROLE_READFLAGS
    IS_MUL_OK = ida_hexrays.ROLE_IS_MUL_OK
    SATURATED_MUL = ida_hexrays.ROLE_SATURATED_MUL
    BITTEST = ida_hexrays.ROLE_BITTEST
    BITTESTANDSET = ida_hexrays.ROLE_BITTESTANDSET
    BITTESTANDRESET = ida_hexrays.ROLE_BITTESTANDRESET
    BITTESTANDCOMPLEMENT = ida_hexrays.ROLE_BITTESTANDCOMPLEMENT
    VA_ARG = ida_hexrays.ROLE_VA_ARG
    VA_COPY = ida_hexrays.ROLE_VA_COPY
    VA_START = ida_hexrays.ROLE_VA_START
    VA_END = ida_hexrays.ROLE_VA_END
    ROL = ida_hexrays.ROLE_ROL
    ROR = ida_hexrays.ROLE_ROR
    CFSUB3 = ida_hexrays.ROLE_CFSUB3
    OFSUB3 = ida_hexrays.ROLE_OFSUB3
    ABS = ida_hexrays.ROLE_ABS
    THREE_WAY_CMP0 = ida_hexrays.ROLE_3WAYCMP0
    THREE_WAY_CMP1 = ida_hexrays.ROLE_3WAYCMP1
    WMEMCPY = ida_hexrays.ROLE_WMEMCPY
    WMEMSET = ida_hexrays.ROLE_WMEMSET
    WCSCPY = ida_hexrays.ROLE_WCSCPY
    WCSLEN = ida_hexrays.ROLE_WCSLEN
    WCSCAT = ida_hexrays.ROLE_WCSCAT
    SSE_CMP4 = ida_hexrays.ROLE_SSE_CMP4
    SSE_CMP8 = ida_hexrays.ROLE_SSE_CMP8


# ---------------------------------------------------------------------------
# MicroCallArg / MicroCallInfo — wraps mcallarg_t / mcallinfo_t
# ---------------------------------------------------------------------------


class MicroCallArg:
    """Wrapper around an IDA ``mcallarg_t`` call argument.

    Each argument has a type, a location (argloc), an optional name,
    and inherits all ``mop_t`` fields (the argument value as a
    micro-operand).
    """

    def __init__(
        self, raw: mcallarg_t, _parent_call: Optional[MicroCallInfo] = None
    ):
        self._raw = raw
        self._parent_call = _parent_call

    @property
    def raw_arg(self) -> mcallarg_t:
        """Get the underlying ``mcallarg_t`` object."""
        return self._raw

    @property
    def type(self) -> tinfo_t:
        """Argument type."""
        return self._raw.type

    @property
    def argloc(self) -> argloc_t:
        """Argument location."""
        return self._raw.argloc

    @property
    def name(self) -> str:
        """Argument name (may be empty)."""
        return self._raw.name

    @property
    def flags(self) -> int:
        """Argument flags."""
        return self._raw.flags

    @property
    def size(self) -> int:
        """Argument size in bytes."""
        return self._raw.size

    @property
    def ea(self) -> ea_t:
        """Source address of the argument."""
        return self._raw.ea

    @property
    def operand(self) -> MicroOperand:
        """The argument value as a :class:`MicroOperand`.

        ``mcallarg_t`` inherits from ``mop_t``, so the argument
        itself is a micro-operand.
        """
        return MicroOperand(self._raw)

    def to_text(self) -> str:
        """Get text representation of this argument."""
        return self._raw.dstr()

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        name = self._raw.name or '?'
        return f'MicroCallArg(name={name!r}, size={self._raw.size})'


class MicroCallInfo:
    """Wrapper around an IDA ``mcallinfo_t`` call information structure.

    Provides access to the callee, arguments, calling convention,
    return type, and spoiled/dead registers.
    """

    def __init__(
        self, raw: mcallinfo_t, _parent_op: Optional[MicroOperand] = None
    ):
        self._raw = raw
        self._parent_op = _parent_op

    @property
    def raw_call_info(self) -> mcallinfo_t:
        """Get the underlying ``mcallinfo_t`` object."""
        return self._raw

    @property
    def callee(self) -> ea_t:
        """Callee address (``BADADDR`` if indirect/unknown)."""
        return self._raw.callee

    @property
    def fixed_arg_count(self) -> int:
        """Number of solid (non-variadic) arguments."""
        return self._raw.solid_args

    @property
    def calling_convention(self) -> int:
        """Calling convention (``CM_CC_*`` constant)."""
        return self._raw.cc

    @property
    def return_type(self) -> tinfo_t:
        """Return type."""
        return self._raw.return_type

    @property
    def return_argloc(self) -> argloc_t:
        """Return value location."""
        return self._raw.return_argloc

    @property
    def flags(self) -> CallInfoFlags:
        """Call flags as a :class:`CallInfoFlags` bit-field."""
        return CallInfoFlags(self._raw.flags)

    @property
    def role(self) -> FunctionRole:
        """Function role as a :class:`FunctionRole` enum."""
        return FunctionRole(self._raw.role)

    @property
    def is_vararg(self) -> bool:
        """True if this is a variadic call."""
        return self._raw.is_vararg()

    @property
    def is_noret(self) -> bool:
        """True if the ``FCI_NORET`` flag is set."""
        return bool(self._raw.flags & ida_hexrays.FCI_NORET)

    @property
    def is_pure(self) -> bool:
        """True if the ``FCI_PURE`` flag is set (no side effects)."""
        return bool(self._raw.flags & ida_hexrays.FCI_PURE)

    @property
    def spoiled(self) -> MicroLocationSet:
        """Spoiled register set."""
        return MicroLocationSet(self._raw.spoiled)

    @property
    def dead_regs(self) -> MicroLocationSet:
        """Dead registers set."""
        return MicroLocationSet(self._raw.dead_regs)

    @property
    def return_regs(self) -> MicroLocationSet:
        """Return registers set."""
        return MicroLocationSet(self._raw.return_regs)

    @property
    def pass_regs(self) -> MicroLocationSet:
        """Pass-through registers set."""
        return MicroLocationSet(self._raw.pass_regs)

    @property
    def visible_memory(self) -> ivlset_t:
        """Memory visible to the call (``ivlset_t``)."""
        return self._raw.visible_memory

    @property
    def call_stack_pointer_delta(self) -> int:
        """Stack pointer delta at the call point."""
        return self._raw.call_spd

    @property
    def stack_args_top(self) -> int:
        """Top of stack arguments area."""
        return self._raw.stkargs_top

    @property
    def args(self) -> List[MicroCallArg]:
        """List of call arguments as :class:`MicroCallArg` wrappers."""
        raw_args = self._raw.args
        return [MicroCallArg(raw_args.at(i), self) for i in range(raw_args.size())]

    @property
    def arg_count(self) -> int:
        """Number of arguments."""
        return self._raw.args.size()

    def get_type(self) -> tinfo_t:
        """Get the full function type."""
        return self._raw.get_type()

    def to_text(self) -> str:
        """Get text representation of this call info."""
        return self._raw.dstr()

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        return (
            f'MicroCallInfo(callee=0x{self._raw.callee:x}, '
            f'args={self._raw.args.size()})'
        )


# ---------------------------------------------------------------------------
# MicroLocalVar / MicroLocalVars — wraps lvar_t / lvars_t
# ---------------------------------------------------------------------------


class MicroLocalVar:
    """Wrapper around an IDA ``lvar_t`` local variable.

    Provides access to the variable's name, type, location, and flags.
    """

    def __init__(
        self, raw: lvar_t, _parent_vars: Optional[MicroLocalVars] = None
    ):
        self._raw = raw
        self._parent_vars = _parent_vars

    @property
    def raw_var(self) -> lvar_t:
        """Get the underlying ``lvar_t`` object."""
        return self._raw

    # -- identity ----------------------------------------------------------

    @property
    def name(self) -> str:
        """Variable name."""
        return self._raw.name

    @property
    def comment(self) -> str:
        """Variable comment (may be empty)."""
        return self._raw.cmt

    @property
    def type_info(self) -> tinfo_t:
        """Variable type information."""
        return self._raw.tif

    @property
    def location(self) -> vdloc_t:
        """Variable location (register, stack, or scattered)."""
        return self._raw.location

    @property
    def width(self) -> int:
        """Variable width in bytes."""
        return self._raw.width

    @property
    def definition_address(self) -> ea_t:
        """Address where this variable is first defined."""
        return self._raw.defea

    @property
    def def_block(self) -> int:
        """Block index where this variable is first defined."""
        return self._raw.defblk

    @property
    def divisor(self) -> int:
        """Variable divisor (for division optimization)."""
        return self._raw.divisor

    # -- boolean flags (properties for no-arg, methods for parameterized) --

    @property
    def is_arg(self) -> bool:
        """True if this is a function argument."""
        return self._raw.is_arg_var

    @property
    def is_result(self) -> bool:
        """True if this is the function return variable."""
        return self._raw.is_result_var

    @property
    def is_used(self) -> bool:
        """True if this variable is used in the function."""
        return self._raw.used

    @property
    def is_typed(self) -> bool:
        """True if this variable has a type assigned."""
        return self._raw.typed

    @property
    def has_nice_name(self) -> bool:
        """True if the variable has a meaningful name."""
        return self._raw.has_nice_name

    @property
    def has_user_name(self) -> bool:
        """True if the user has set a custom name."""
        return self._raw.has_user_name

    @property
    def has_user_type(self) -> bool:
        """True if the user has set a custom type."""
        return self._raw.has_user_type

    @property
    def has_user_info(self) -> bool:
        """True if the user has set any custom info."""
        return self._raw.has_user_info

    @property
    def is_fake(self) -> bool:
        """True if this is a fake variable."""
        return self._raw.is_fake_var

    @property
    def is_overlapped(self) -> bool:
        """True if this variable overlaps with another."""
        return self._raw.is_overlapped_var

    @property
    def is_floating(self) -> bool:
        """True if this is a floating-point variable."""
        return self._raw.is_floating_var

    @property
    def is_spoiled(self) -> bool:
        """True if this variable is spoiled."""
        return self._raw.is_spoiled_var

    def is_stack_variable(self) -> bool:
        """True if this variable is on the stack."""
        return self._raw.is_stk_var()

    def is_register_variable(self) -> bool:
        """True if this variable is in a register."""
        return self._raw.is_reg_var()

    def is_scattered(self) -> bool:
        """True if this variable is scattered across locations."""
        return self._raw.is_scattered()

    def is_thisarg(self) -> bool:
        """True if this is the ``this`` pointer argument."""
        return self._raw.is_thisarg()

    def is_dummy_arg(self) -> bool:
        """True if this is a dummy argument."""
        return self._raw.is_dummy_arg()

    # -- mutation ----------------------------------------------------------

    def set_type(self, tif: tinfo_t) -> bool:
        """Set the variable type.

        Args:
            tif: The new type to assign.

        Returns:
            True if the type was accepted.
        """
        return self._raw.set_lvar_type(tif)

    def set_final_type(self, tif: tinfo_t) -> bool:
        """Set the final variable type (no further propagation).

        Args:
            tif: The new type to assign.

        Returns:
            True if the type was accepted.
        """
        return self._raw.set_final_lvar_type(tif)

    def accepts_type(self, tif: tinfo_t) -> bool:
        """Check if the variable accepts the given type.

        Args:
            tif: The type to check.

        Returns:
            True if the type is compatible.
        """
        return self._raw.accepts_type(tif)

    def set_user_name(self, name: str) -> None:
        """Set a user-defined name for this variable."""
        self._raw.name = name
        self._raw.set_user_name()

    # -- text --------------------------------------------------------------

    def __str__(self) -> str:
        tif_str = str(self._raw.tif) if self._raw.tif else '?'
        return f'{tif_str} {self._raw.name}'

    def __repr__(self) -> str:
        return (
            f'MicroLocalVar(name={self._raw.name!r}, '
            f'width={self._raw.width})'
        )


class MicroLocalVars:
    """Wrapper around an IDA ``lvars_t`` local variable list.

    Supports iteration, indexing, and lookup by name or location.
    """

    def __init__(self, raw: lvars_t, mba: MicroBlockArray):
        self._raw = raw
        self._mba = mba

    @property
    def raw_lvars(self) -> lvars_t:
        """Get the underlying ``lvars_t`` object."""
        return self._raw

    def __len__(self) -> int:
        return self._raw.size()

    def __getitem__(self, i: int) -> MicroLocalVar:
        if i < 0:
            i += self._raw.size()
        if i < 0 or i >= self._raw.size():
            raise IndexError(
                f'Variable index out of range (0..{self._raw.size() - 1})'
            )
        return MicroLocalVar(self._raw.at(i), self)

    def __iter__(self) -> Iterator[MicroLocalVar]:
        for i in range(self._raw.size()):
            yield MicroLocalVar(self._raw.at(i), self)

    def find_by_name(self, name: str) -> Optional[MicroLocalVar]:
        """Find a variable by name.

        Note: IDAPython ``lvars_t`` has no name-based lookup, so this
        performs a linear scan.

        Args:
            name: Variable name to search for.

        Returns:
            The :class:`MicroLocalVar`, or *None* if not found.
        """
        for i in range(self._raw.size()):
            v = self._raw.at(i)
            if v.name == name:
                return MicroLocalVar(v, self)
        return None

    def find_lvar(self, location: vdloc_t, width: int) -> Optional[MicroLocalVar]:
        """Find a variable by its location and width.

        Args:
            location: Variable location (``vdloc_t``).
            width: Variable width in bytes.

        Returns:
            The :class:`MicroLocalVar`, or *None* if not found.
        """
        idx = self._raw.find_lvar(location, width)
        if idx < 0:
            return None
        return MicroLocalVar(self._raw.at(idx), self)

    def find_stkvar(self, spoff: int, width: int) -> Optional[MicroLocalVar]:
        """Find a stack variable by its stack offset and width.

        Args:
            spoff: Stack offset.
            width: Variable width in bytes.

        Returns:
            The :class:`MicroLocalVar`, or *None* if not found.
        """
        idx = self._raw.find_stkvar(spoff, width)
        if idx < 0:
            return None
        return MicroLocalVar(self._raw.at(idx), self)

    @property
    def arguments(self) -> List[MicroLocalVar]:
        """List of variables that are function arguments."""
        return [MicroLocalVar(self._raw.at(i), self)
                for i in range(self._raw.size())
                if self._raw.at(i).is_arg_var]

    def __repr__(self) -> str:
        return f'MicroLocalVars(count={self._raw.size()})'


# ---------------------------------------------------------------------------
# MicroOperand — wraps mop_t
# ---------------------------------------------------------------------------


class MicroOperand:
    """Wrapper around an IDA ``mop_t`` microcode operand.

    Provides Pythonic access to operand type, value, and type-specific
    accessors.  The underlying raw object is always available via
    :pyattr:`raw_operand`.

    Use the static factory methods to create new operands::

        num = MicroOperand.number(42, size=4)
        reg = MicroOperand.reg(mreg, size=8)
        blk = MicroOperand.new_block_ref(3)
    """

    _T = MicroOperandType  # shorthand for type checks

    def __init__(
        self, raw: mop_t, _parent_insn: Optional[MicroInstruction] = None
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    # -- factories ---------------------------------------------------------

    @staticmethod
    def number(value: int, size: int, ea: int = ida_idaapi.BADADDR) -> MicroOperand:
        """Create a numeric constant operand.

        Args:
            value: The integer constant value.
            size: Operand size in bytes (1, 2, 4, 8).
            ea: Optional source address (default ``BADADDR``).
        """
        raw = mop_t()
        raw.make_number(value, size, ea)
        return MicroOperand(raw)

    @staticmethod
    def reg(mreg: int, size: int) -> MicroOperand:
        """Create a micro-register operand.

        Args:
            mreg: Micro-register number (from ``ida_hexrays.reg2mreg()``
                or ``ida_hexrays.mr_*`` constants).
            size: Operand size in bytes.
        """
        raw = mop_t()
        raw._make_reg(mreg, size)
        return MicroOperand(raw)

    @staticmethod
    def helper(name: str) -> MicroOperand:
        """Create a helper function name operand.

        Args:
            name: Helper function name (e.g. ``"memcpy"``).
        """
        raw = mop_t()
        raw.make_helper(name)
        return MicroOperand(raw)

    @staticmethod
    def new_block_ref(serial: int) -> MicroOperand:
        """Create a block-reference operand.

        Args:
            serial: Target block serial number.
        """
        raw = mop_t()
        raw._make_blkref(serial)
        return MicroOperand(raw)

    @staticmethod
    def global_addr(ea: int, size: int) -> MicroOperand:
        """Create a global address operand.

        Args:
            ea: Global address.
            size: Operand size in bytes.
        """
        raw = mop_t()
        raw._make_gvar(ea)
        raw.size = size
        return MicroOperand(raw)

    @staticmethod
    def from_insn(insn: MicroInstruction) -> MicroOperand:
        """Create an operand wrapping a sub-instruction (``mop_d``).

        The instruction becomes a nested expression operand.

        Args:
            insn: The :class:`MicroInstruction` to wrap.
        """
        raw = mop_t()
        raw.create_from_insn(insn._raw)
        return MicroOperand(raw)

    @staticmethod
    def stack_var(mba: MicroBlockArray, offset: int) -> MicroOperand:
        """Create a stack variable operand.

        Args:
            mba: The parent :class:`MicroBlockArray`.
            offset: Stack offset.
        """
        raw = mop_t()
        raw._make_stkvar(mba._raw, offset)
        return MicroOperand(raw)

    @staticmethod
    def local_var(mba: MicroBlockArray, idx: int, off: int = 0) -> MicroOperand:
        """Create a local variable operand.

        Args:
            mba: The parent :class:`MicroBlockArray`.
            idx: Index into the local variable list (``mba.vars``).
            off: Offset from the beginning of the variable.
        """
        raw = mop_t()
        raw._make_lvar(mba._raw, idx, off)
        return MicroOperand(raw)

    @staticmethod
    def reg_pair(loreg: int, hireg: int, halfsize: int) -> MicroOperand:
        """Create a register-pair operand.

        Args:
            loreg: Micro-register holding the low part.
            hireg: Micro-register holding the high part.
            halfsize: Size of each half-register in bytes.
        """
        raw = mop_t()
        raw.make_reg_pair(loreg, hireg, halfsize)
        return MicroOperand(raw)

    @staticmethod
    def fpnum(data: bytes) -> MicroOperand:
        """Create a floating-point constant operand.

        Args:
            data: Raw floating-point bytes in the processor's native
                format (e.g. IEEE 754 for x86).
        """
        raw = mop_t()
        raw.make_fpnum(data)
        return MicroOperand(raw)

    @staticmethod
    def empty() -> MicroOperand:
        """Create an empty operand (``mop_z``)."""
        return MicroOperand(mop_t())

    # -- raw access --------------------------------------------------------

    @property
    def raw_operand(self) -> mop_t:
        """Get the underlying ``mop_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def type(self) -> MicroOperandType:
        """Operand type as a :class:`MicroOperandType` enum."""
        return MicroOperandType(self._raw.t)

    @property
    def size(self) -> int:
        """Operand size in bytes."""
        return self._raw.size

    @property
    def is_empty(self) -> bool:
        """True if this is an empty operand (``mop_z``)."""
        return not self

    # -- type-specific accessors (return None if wrong type) ---------------

    @property
    def register(self) -> Optional[int]:
        """Micro-register number, or *None* if not a register operand."""
        if self._raw.t == self._T.REGISTER:
            return self._raw.r
        return None

    @property
    def register_name(self) -> Optional[str]:
        """Human-readable micro-register name, or *None*."""
        if self._raw.t == self._T.REGISTER:
            return ida_hexrays.get_mreg_name(self._raw.r, self._raw.size)
        return None

    @property
    def value(self) -> Optional[int]:
        """Numeric value for number operands, or *None*."""
        if self._raw.t == self._T.NUMBER:
            return self._raw.nnn.value
        return None

    @property
    def signed_value(self) -> Optional[int]:
        """Signed interpretation of a number operand, or *None*."""
        if self._raw.t == self._T.NUMBER:
            return self._raw.signed_value()
        return None

    @property
    def unsigned_value(self) -> Optional[int]:
        """Unsigned interpretation of a number operand, or *None*."""
        if self._raw.t == self._T.NUMBER:
            return self._raw.unsigned_value()
        return None

    @property
    def global_address(self) -> Optional[int]:
        """Global address for ``mop_v`` operands, or *None*."""
        if self._raw.t == self._T.GLOBAL_ADDR:
            return self._raw.g
        return None

    @property
    def stack_offset(self) -> Optional[int]:
        """Stack variable offset for ``mop_S`` operands, or *None*."""
        if self._raw.t == self._T.STACK_VAR:
            return self._raw.s.off
        return None

    def get_stack_variable(self) -> Optional[Tuple[int, int]]:
        """Resolve a stack variable operand to its frame index and IDA offset.

        Returns:
            A tuple ``(frame_index, ida_offset)`` or *None* if this is not
            a stack variable operand or the variable cannot be resolved.
            *frame_index* is the index of the struct member in the frame,
            *ida_offset* is the IDA-style stack offset.
        """
        if self._raw.t != self._T.STACK_VAR:
            return None
        idx = self._raw.get_stkvar()
        if idx < 0:
            return None
        return (idx, self._raw.s.off)

    @property
    def sub_instruction(self) -> Optional[MicroInstruction]:
        """Nested :class:`MicroInstruction` for ``mop_d`` operands, or *None*."""
        if self._raw.t == self._T.SUB_INSN:
            parent_block = (
                self._parent_insn._parent_block
                if self._parent_insn is not None
                else None
            )
            return MicroInstruction(self._raw.d, parent_block)
        return None

    @property
    def helper_name(self) -> Optional[str]:
        """Helper function name for ``mop_h`` operands, or *None*."""
        if self._raw.t == self._T.HELPER:
            return self._raw.helper
        return None

    @property
    def block_ref(self) -> Optional[int]:
        """Target block serial number for ``mop_b`` operands, or *None*."""
        if self._raw.t == self._T.BLOCK_REF:
            return self._raw.b
        return None

    @property
    def call_info(self) -> Optional[MicroCallInfo]:
        """Call information for ``mop_f`` operands, or *None*."""
        if self._raw.t == self._T.CALL_INFO:
            return MicroCallInfo(self._raw.f, self)
        return None

    @property
    def string_value(self) -> Optional[str]:
        """String value for ``mop_str`` operands, or *None*."""
        if self._raw.t == self._T.STRING:
            return self._raw.cstr
        return None

    @property
    def address_target(self) -> Optional[MicroOperand]:
        """Inner operand of an address-of (``mop_a``) operand, or *None*."""
        if self._raw.t == self._T.ADDR_OF:
            return MicroOperand(self._raw.a, self._parent_insn)
        return None

    @property
    def pair(self) -> Optional[Tuple[MicroOperand, MicroOperand]]:
        """(low, high) operand pair for ``mop_p`` operands, or *None*."""
        if self._raw.t == self._T.PAIR:
            return (
                MicroOperand(self._raw.pair.lop, self._parent_insn),
                MicroOperand(self._raw.pair.hop, self._parent_insn),
            )
        return None

    # -- type-check shortcuts ----------------------------------------------

    @property
    def is_register(self) -> bool:
        return self._raw.is_reg()

    @property
    def is_number(self) -> bool:
        return self._raw.t == self._T.NUMBER

    @property
    def is_stack_var(self) -> bool:
        return self._raw.is_stkvar()

    @property
    def is_global_address(self) -> bool:
        return self._raw.is_glbvar()

    @property
    def is_helper(self) -> bool:
        return self._raw.t == self._T.HELPER

    @property
    def is_string(self) -> bool:
        return self._raw.t == self._T.STRING

    @property
    def is_pair(self) -> bool:
        return self._raw.t == self._T.PAIR

    # -- constant predicates -----------------------------------------------

    def is_constant(self, is_signed: bool = True) -> Optional[int]:
        """Retrieve the value of a constant integer operand.

        Args:
            is_signed: Interpret the value as signed.

        Returns:
            The integer value if the operand is a numeric constant
            (``mop_n``), or *None* otherwise.
        """
        return self._raw.is_constant(is_signed)

    @property
    def is_zero(self) -> bool:
        """True if this is a numeric zero constant."""
        return self._raw.is_zero()

    @property
    def is_one(self) -> bool:
        """True if this is a numeric constant equal to 1."""
        return self._raw.is_one()

    @property
    def is_positive_constant(self) -> bool:
        """True if this is a positive numeric constant."""
        return self._raw.is_positive_constant()

    @property
    def is_negative_constant(self) -> bool:
        """True if this is a negative numeric constant (signed)."""
        return self._raw.is_negative_constant()

    def is_equal_to(self, n: int, is_signed: bool = True) -> bool:
        """True if this is a numeric constant equal to *n*.

        Args:
            n: The value to compare against.
            is_signed: Interpret the comparison as signed.
        """
        return self._raw.is_equal_to(n, is_signed)

    # -- extended type checks ----------------------------------------------

    @property
    def is_kernel_register(self) -> bool:
        """True if this is a kernel register."""
        return self._raw.is_kreg()

    @property
    def is_condition_code(self) -> bool:
        """True if this is a condition code register."""
        return self._raw.is_cc()

    @property
    def is_bit_reg(self) -> bool:
        """True if this is a bit register (including condition codes)."""
        return self._raw.is_bit_reg()

    @property
    def is_scattered(self) -> bool:
        """True if this is a scattered operand."""
        return self._raw.is_scattered()

    @property
    def is_boolean(self) -> bool:
        """True if the operand can only be 0 or 1 (bit register, set result, etc.)."""
        return self._raw.is01()

    def is_sign_extended_from(self, nbytes: int) -> bool:
        """True if the high bytes are sign-extended from *nbytes*.

        Args:
            nbytes: Number of low bytes that were sign-extended.
        """
        return self._raw.is_sign_extended_from(nbytes)

    def is_zero_extended_from(self, nbytes: int) -> bool:
        """True if the high bytes are zero-extended from *nbytes*.

        Args:
            nbytes: Number of low bytes that were zero-extended.
        """
        return self._raw.is_zero_extended_from(nbytes)

    # -- query methods -----------------------------------------------------

    def is_sub_instruction(self, opcode: Optional[MicroOpcode] = None) -> bool:
        """Check if this operand is a nested sub-instruction.

        Args:
            opcode: If given, also checks that the nested instruction has
                this specific opcode.
        """
        if opcode is not None:
            return self._raw.is_insn(int(opcode))
        return self._raw.is_insn()

    def has_side_effects(
        self, include_ldx_and_divs: bool = False
    ) -> bool:
        """True if evaluating this operand may cause side effects.

        Args:
            include_ldx_and_divs: Also treat ``ldx``/``div``/``mod``
                as having side effects.
        """
        return self._raw.has_side_effects(include_ldx_and_divs)

    @property
    def may_use_aliased_memory(self) -> bool:
        """True if this operand may access aliased memory."""
        return self._raw.may_use_aliased_memory()

    # -- mutation ----------------------------------------------------------

    def clear(self) -> None:
        """Reset this operand to empty (``mop_z``)."""
        self._raw.erase()

    def erase_but_keep_size(self) -> None:
        """Reset this operand to empty but preserve the size field."""
        self._raw.erase_but_keep_size()

    # -- transformations ---------------------------------------------------

    def make_low_half(self, width: int) -> bool:
        """Extract the low half of this operand.

        Args:
            width: Desired size in bytes (must be smaller than current size).

        Returns:
            True on success.
        """
        return self._raw.make_low_half(width)

    def make_high_half(self, width: int) -> bool:
        """Extract the high half of this operand.

        Args:
            width: Desired size in bytes (must be smaller than current size).

        Returns:
            True on success.
        """
        return self._raw.make_high_half(width)

    def make_first_half(self, width: int) -> bool:
        """Extract the first part (endianness-independent).

        Args:
            width: Desired size in bytes.

        Returns:
            True on success.
        """
        return self._raw.make_first_half(width)

    def make_second_half(self, width: int) -> bool:
        """Extract the second part (endianness-independent).

        Args:
            width: Desired size in bytes.

        Returns:
            True on success.
        """
        return self._raw.make_second_half(width)

    def change_size(self, new_size: int) -> bool:
        """Change operand size, discarding extra high bytes or zero-extending.

        Args:
            new_size: New size in bytes.

        Returns:
            True on success.
        """
        return self._raw.change_size(new_size)

    def double_size(self) -> bool:
        """Double the operand size (e.g. 4 -> 8), zero-extending.

        Returns:
            True on success.
        """
        return self._raw.double_size()

    def apply_zero_extension(self, new_size: int, ea: int = ida_idaapi.BADADDR) -> None:
        """Apply zero-extension to *new_size* bytes.

        Args:
            new_size: Target size in bytes.
            ea: Source address for the extending instruction.
        """
        self._raw.apply_xdu(ea, new_size)

    def apply_sign_extension(self, new_size: int, ea: int = ida_idaapi.BADADDR) -> None:
        """Apply sign-extension to *new_size* bytes.

        Args:
            new_size: Target size in bytes.
            ea: Source address for the extending instruction.
        """
        self._raw.apply_xds(ea, new_size)

    def shift_operand(self, offset: int) -> bool:
        """Shift the operand start by *offset* bytes.

        Positive offsets move toward higher bytes (shrink from the low end),
        negative offsets move toward lower bytes (grow from the high end).

        Examples::

            AH.1  shift_operand(-1) → AX.2
            #0x12345678.4  shift_operand(3) → #0x12.1

        Args:
            offset: Number of bytes to shift.

        Returns:
            True on success.
        """
        return self._raw.shift_mop(offset)

    # -- text / display ----------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> str:
        """Get text representation of this operand."""
        text = self._raw.dstr()
        if remove_tags:
            text = ida_lines.tag_remove(text)
        return text

    # -- dunder protocols --------------------------------------------------

    def __bool__(self) -> bool:
        """True if this operand is non-empty (not ``mop_z``)."""
        return self._raw.t != self._T.EMPTY

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MicroOperand):
            return self._raw == other._raw
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, MicroOperand):
            return self._raw != other._raw
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, MicroOperand):
            return self._raw < other._raw
        return NotImplemented

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        try:
            type_name = MicroOperandType(self._raw.t).name
        except ValueError:
            type_name = str(self._raw.t)
        return f'MicroOperand(type={type_name}, size={self._raw.size})'


# ---------------------------------------------------------------------------
# MicroInstruction — wraps minsn_t
# ---------------------------------------------------------------------------


class MicroInstruction:
    """Wrapper around an IDA ``minsn_t`` microcode instruction.

    Provides Pythonic access to opcode, operands, and traversal.

    Use :meth:`create` to build new instructions::

        insn = MicroInstruction.create(
            ea=0x401000,
            opcode=MicroOpcode.MOV,
            left=MicroOperand.reg(mreg, 4),
            dest=MicroOperand.number(0, 4),
        )
    """

    def __init__(self, raw: minsn_t, parent_block: Optional[MicroBlock] = None):
        self._raw = raw
        self._parent_block = parent_block

    # -- factory -----------------------------------------------------------

    @staticmethod
    def create(
        ea: int,
        opcode: MicroOpcode,
        left: Optional[MicroOperand] = None,
        right: Optional[MicroOperand] = None,
        dest: Optional[MicroOperand] = None,
    ) -> MicroInstruction:
        """Create a new microcode instruction from scratch.

        Args:
            ea: Effective address for the instruction.
            opcode: The microcode opcode.
            left: Left operand (``l``).
            right: Right operand (``r``).
            dest: Destination operand (``d``).

        Returns:
            A new :class:`MicroInstruction`.
        """
        raw = minsn_t(ea)
        raw.opcode = int(opcode)
        if left is not None:
            raw.l.swap(left._raw)
        if right is not None:
            raw.r.swap(right._raw)
        if dest is not None:
            raw.d.swap(dest._raw)
        return MicroInstruction(raw)

    # -- raw access --------------------------------------------------------

    @property
    def raw_instruction(self) -> minsn_t:
        """Get the underlying ``minsn_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def opcode(self) -> MicroOpcode:
        """Instruction opcode as a :class:`MicroOpcode` enum."""
        return MicroOpcode(self._raw.opcode)

    @opcode.setter
    def opcode(self, value: MicroOpcode) -> None:
        self._raw.opcode = int(value)

    @property
    def ea(self) -> int:
        """Effective address of this instruction."""
        return self._raw.ea

    # Operand access — short names (l, r, d) and descriptive aliases
    @property
    def l(self) -> MicroOperand:
        """Left operand."""
        return MicroOperand(self._raw.l, self)

    @l.setter
    def l(self, operand: MicroOperand) -> None:
        self._raw.l.swap(operand._raw)

    @property
    def r(self) -> MicroOperand:
        """Right operand."""
        return MicroOperand(self._raw.r, self)

    @r.setter
    def r(self, operand: MicroOperand) -> None:
        self._raw.r.swap(operand._raw)

    @property
    def d(self) -> MicroOperand:
        """Destination operand."""
        return MicroOperand(self._raw.d, self)

    @d.setter
    def d(self, operand: MicroOperand) -> None:
        self._raw.d.swap(operand._raw)

    @property
    def left(self) -> MicroOperand:
        """Left operand (alias for ``l``)."""
        return self.l

    @left.setter
    def left(self, operand: MicroOperand) -> None:
        self.l = operand

    @property
    def right(self) -> MicroOperand:
        """Right operand (alias for ``r``)."""
        return self.r

    @right.setter
    def right(self, operand: MicroOperand) -> None:
        self.r = operand

    @property
    def dest(self) -> MicroOperand:
        """Destination operand (alias for ``d``)."""
        return self.d

    @dest.setter
    def dest(self, operand: MicroOperand) -> None:
        self.d = operand

    @property
    def next(self) -> Optional[MicroInstruction]:
        """Next instruction in the block, or *None*."""
        n = self._raw.next
        if n:
            return MicroInstruction(n, self._parent_block)
        return None

    @property
    def prev(self) -> Optional[MicroInstruction]:
        """Previous instruction in the block, or *None*."""
        p = self._raw.prev
        if p:
            return MicroInstruction(p, self._parent_block)
        return None

    @property
    def block(self) -> Optional[MicroBlock]:
        """Parent block, if known."""
        return self._parent_block

    @property
    def is_top_level(self) -> bool:
        """True if this instruction lives directly in a block's list.

        False for sub-instructions nested inside an operand (``mop_d``).
        """
        if self._parent_block is None:
            return False
        return self._parent_block.contains_instruction(self)

    # -- iteration ---------------------------------------------------------

    def operands(self) -> Iterator[MicroOperand]:
        """Iterate over non-empty operands (l, r, d)."""
        for op in (self.l, self.r, self.d):
            if op:
                yield op

    # -- query methods -----------------------------------------------------

    def is_call(self) -> bool:
        """True if this is a call instruction (``m_call`` or ``m_icall``)."""
        return self.opcode.is_call

    def is_mov(self) -> bool:
        """True if this is a ``m_mov`` instruction."""
        return self.opcode == MicroOpcode.MOV

    def is_conditional_jump(self) -> bool:
        """True if this is a conditional jump (``jnz``..``jle``, ``jcnd``)."""
        return self.opcode.is_conditional_jump

    def is_jump(self) -> bool:
        """True if this is any jump/branch (including ``goto``, ``jtbl``, ``ijmp``)."""
        return self.opcode.is_jump

    def is_flow(self) -> bool:
        """True if this is any control-flow instruction (jump, call, ``ret``)."""
        return self.opcode.is_flow

    def is_set(self) -> bool:
        """True if this is a set-condition instruction (``setnz``..``setle``)."""
        return self.opcode.is_set

    def is_fpu(self) -> bool:
        """True if this is a floating-point instruction."""
        return self.opcode.is_fpu

    def is_commutative(self) -> bool:
        """True if this instruction's opcode is commutative."""
        return self.opcode.is_commutative

    def has_side_effects(
        self, include_ldx_and_divs: bool = False
    ) -> bool:
        """True if this instruction (or any nested sub-instruction) may cause side effects.

        Args:
            include_ldx_and_divs: Also treat ``ldx``/``div``/``mod``
                as having side effects.
        """
        return self._raw.has_side_effects(include_ldx_and_divs)

    def is_helper(self, name: str) -> bool:
        """True if this is a helper call with the specified name.

        Args:
            name: Helper function name to check (e.g. ``"memcpy"``).
        """
        return self._raw.is_helper(name)

    def contains_call(self, with_helpers: bool = False) -> bool:
        """True if this instruction (or any sub-instruction) contains a call.

        Args:
            with_helpers: Also consider helper calls.
        """
        return self._raw.contains_call(with_helpers)

    def is_noret_call(self, flags: int = 0) -> bool:
        """True if this is a non-returning call.

        Args:
            flags: Combination of ``NORET_*`` bits.
        """
        return self._raw.is_noret_call(flags)

    def find_numeric_operand(
        self,
    ) -> Optional[Tuple[MicroOperand, MicroOperand]]:
        """Find the numeric operand (``l`` or ``r``) of this instruction.

        Returns:
            A tuple ``(num_operand, other_operand)`` where *num_operand*
            is the numeric one and *other_operand* is the remaining one,
            or *None* if neither operand is a number.
        """
        result = self._raw.find_num_op()
        if result is None:
            return None
        num_op, other_op = result
        if num_op is None:
            return None
        return MicroOperand(num_op, self), MicroOperand(other_op, self)

    def find_sub_instruction_operand(
        self, opcode: MicroOpcode = MicroOpcode.NOP
    ) -> Optional[Tuple[MicroInstruction, MicroOperand]]:
        """Find a sub-instruction operand (``l`` or ``r``) with the given opcode.

        Args:
            opcode: Opcode to search for. ``NOP`` (default) matches any.

        Returns:
            A tuple ``(sub_insn, other_operand)`` where *sub_insn* is
            the nested instruction and *other_operand* is the remaining
            operand, or *None* if no matching sub-instruction is found.
        """
        result = self._raw.find_ins_op(int(opcode))
        if result is None:
            return None
        insn, other_op = result
        if insn is None:
            return None
        return (
            MicroInstruction(insn, self._parent_block),
            MicroOperand(other_op, self),
        )

    @property
    def modifies_dest(self) -> bool:
        """True if this instruction writes to its ``d`` operand.

        Some instructions (e.g. ``stx``) do not modify ``d``.
        """
        return self._raw.modifies_d()

    def find_call(self, with_helpers: bool = False) -> Optional[MicroInstruction]:
        """Find the first call in this instruction tree."""
        result = self._raw.find_call(with_helpers)
        if result:
            parent = self._parent_block if result.obj_id == self._raw.obj_id else None
            return MicroInstruction(result, parent)
        return None

    def find_opcode(self, mcode: MicroOpcode) -> Optional[MicroInstruction]:
        """Find the first sub-instruction with the given opcode."""
        result = self._raw.find_opcode(int(mcode))
        if result:
            parent = self._parent_block if result.obj_id == self._raw.obj_id else None
            return MicroInstruction(result, parent)
        return None

    # -- recursive visitors ------------------------------------------------

    def for_all_instructions(self, visitor: MicroInstructionVisitor) -> int:
        """Recursively visit all sub-instructions in this instruction tree.

        Args:
            visitor: A :class:`MicroInstructionVisitor` whose ``visit`` method
                will be called for each nested instruction.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_insns(visitor)

    def for_all_operands(self, visitor: MicroOperandVisitor) -> int:
        """Recursively visit all operands in this instruction tree.

        Args:
            visitor: A :class:`MicroOperandVisitor` whose ``visit`` method
                will be called for each operand.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_ops(visitor)

    # -- instruction flags -------------------------------------------------

    @property
    def is_combined(self) -> bool:
        """True if this instruction was combined from several."""
        return self._raw.is_combined()

    @property
    def is_assert(self) -> bool:
        """True if this is an assertion instruction."""
        return self._raw.is_assert()

    @property
    def is_floating_point_insn(self) -> bool:
        """True if this is a floating-point instruction (flag-based)."""
        return self._raw.is_fpinsn()

    @property
    def is_persistent(self) -> bool:
        """True if this instruction must not be deleted."""
        return self._raw.is_persistent()

    @property
    def is_propagatable(self) -> bool:
        """True if this instruction is propagatable."""
        return self._raw.is_propagatable()

    @property
    def is_combinable(self) -> bool:
        """True if this instruction is combinable."""
        return self._raw.is_combinable()

    @property
    def is_optional(self) -> bool:
        """True if this instruction is optional (may be dropped)."""
        return self._raw.is_optional()

    @property
    def is_tailcall(self) -> bool:
        """True if this call has been recognized as a tail call."""
        return self._raw.is_tailcall()

    @property
    def is_farcall(self) -> bool:
        """True if this is a far call."""
        return self._raw.is_farcall()

    @property
    def is_cleaning_pop(self) -> bool:
        """True if this pop instruction cleans up the stack."""
        return self._raw.is_cleaning_pop()

    @property
    def is_multimov(self) -> bool:
        """True if this is a multi-move (struct/memcpy)."""
        return self._raw.is_multimov()

    @property
    def is_ignore_low_source(self) -> bool:
        """True if low part of the source operand should be ignored."""
        return self._raw.is_ignlowsrc()

    @property
    def is_extended_store(self) -> bool:
        """True if this stx uses a sign-extended offset."""
        return self._raw.is_extstx()

    @property
    def is_alloca(self) -> bool:
        """True if this is an ``alloca`` call."""
        return self._raw.is_alloca()

    @property
    def is_like_move(self) -> bool:
        """True if this is structurally similar to a ``mov`` instruction."""
        return self._raw.is_like_move()

    @property
    def is_memory_barrier(self) -> bool:
        """True if this is a memory barrier instruction."""
        return self._raw.is_mbarrier()

    @property
    def is_bswap(self) -> bool:
        """True if this is a byte-swap instruction."""
        return self._raw.is_bswap()

    @property
    def is_memcpy(self) -> bool:
        """True if this is a memcpy operation."""
        return self._raw.is_memcpy()

    @property
    def is_memset(self) -> bool:
        """True if this is a memset operation."""
        return self._raw.is_memset()

    @property
    def is_readflags(self) -> bool:
        """True if this instruction reads flags."""
        return self._raw.is_readflags()

    @property
    def is_inverted_jump(self) -> bool:
        """True if this conditional jump has been inverted."""
        return self._raw.is_inverted_jx()

    @property
    def is_wild_match(self) -> bool:
        """True if wild-matching is enabled for this instruction."""
        return self._raw.is_wild_match()

    @property
    def is_unknown_call(self) -> bool:
        """True if this is a call to an unknown target."""
        return self._raw.is_unknown_call()

    def set_combined(self) -> None:
        """Mark this instruction as combined."""
        self._raw.set_combined()

    def clr_combined(self) -> None:
        """Clear the combined flag."""
        self._raw.clr_combined()

    def set_assert(self) -> None:
        """Mark this instruction as an assertion."""
        self._raw.set_assert()

    def clr_assert(self) -> None:
        """Clear the assertion flag."""
        self._raw.clr_assert()

    def set_floating_point_insn(self) -> None:
        """Mark this as a floating-point instruction."""
        self._raw.set_fpinsn()

    def clr_floating_point_insn(self) -> None:
        """Clear the floating-point instruction flag."""
        self._raw.clr_fpinsn()

    def set_persistent(self) -> None:
        """Mark this instruction as persistent (must not be deleted)."""
        self._raw.set_persistent()

    def set_combinable(self) -> None:
        """Mark this instruction as combinable."""
        self._raw.set_combinable()

    def clr_combinable(self) -> None:
        """Clear the combinable flag."""
        self._raw.clr_combinable()

    def set_optional(self) -> None:
        """Mark this instruction as optional."""
        self._raw.set_optional()

    def set_tailcall(self) -> None:
        """Mark this call as a tail call."""
        self._raw.set_tailcall()

    def clr_tailcall(self) -> None:
        """Clear the tail call flag."""
        self._raw.clr_tailcall()

    def set_farcall(self) -> None:
        """Mark this as a far call."""
        self._raw.set_farcall()

    def set_cleaning_pop(self) -> None:
        """Mark this pop as a cleaning pop."""
        self._raw.set_cleaning_pop()

    def set_multimov(self) -> None:
        """Mark this as a multi-move instruction."""
        self._raw.set_multimov()

    def clr_multimov(self) -> None:
        """Clear the multi-move flag."""
        self._raw.clr_multimov()

    def set_ignore_low_source(self) -> None:
        """Set the ignore-low-source flag."""
        self._raw.set_ignlowsrc()

    def clr_ignore_low_source(self) -> None:
        """Clear the ignore-low-source flag."""
        self._raw.clr_ignlowsrc()

    def set_extended_store(self) -> None:
        """Mark stx as using sign-extended offset."""
        self._raw.set_extstx()

    def set_memory_barrier(self) -> None:
        """Mark this as a memory barrier."""
        self._raw.set_mbarrier()

    def set_inverted_jump(self) -> None:
        """Mark this conditional jump as inverted."""
        self._raw.set_inverted_jx()

    def set_wild_match(self) -> None:
        """Enable wild-matching for this instruction."""
        self._raw.set_wild_match()

    def set_noret_icall(self) -> None:
        """Mark this indirect call as non-returning."""
        self._raw.set_noret_icall()

    def clr_noret_icall(self) -> None:
        """Clear the non-returning indirect call flag."""
        self._raw.clr_noret_icall()

    def clr_propagatable(self) -> None:
        """Clear the propagatable flag."""
        self._raw.clr_propagatable()

    # -- mutation ----------------------------------------------------------

    def make_nop(self) -> None:
        """Convert this instruction to a NOP.

        Erases all data except the prev/next links.  In most cases
        prefer :meth:`MicroBlock.make_nop` which also marks the
        block's use-def lists as dirty.
        """
        self._raw._make_nop()

    def swap(self, other: MicroInstruction) -> None:
        """Swap this instruction with another."""
        self._raw.swap(other._raw)

    def optimize_solo(self) -> int:
        """Run single-instruction optimization on this instruction.

        Returns:
            Number of changes made (non-zero means the instruction was optimized).
        """
        return self._raw.optimize_solo(0)

    def replace_with(self, new_insn: MicroInstruction) -> None:
        """Replace this instruction with *new_insn*, performing cleanup.

        Equivalent to the common deobfuscation idiom::

            insn.swap(new_insn)
            insn.optimize_solo()
            block.mark_lists_dirty()

        The parent block must be known (i.e. this instruction must have been
        obtained from a :class:`MicroBlock`).

        Raises:
            RuntimeError: If the parent block is not known.
        """
        if self._parent_block is None:
            raise RuntimeError(
                "Cannot mark lists dirty: parent block unknown. "
                "Use block.replace_instruction() or ensure the instruction "
                "was obtained from a block."
            )
        self.swap(new_insn)
        self.optimize_solo()
        self._parent_block.mark_lists_dirty()

    def set_address(self, ea: int) -> None:
        """Change the effective address of this instruction and all sub-instructions."""
        self._raw.setaddr(ea)

    # -- text / display ----------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> str:
        """Get text representation of this instruction."""
        text = self._raw.dstr()
        if remove_tags:
            text = ida_lines.tag_remove(text)
        return text

    # -- comparison --------------------------------------------------------

    def equals(self, other: MicroInstruction, eqflags: int = 0) -> bool:
        """Structural comparison with fine-grained control.

        Args:
            other: Instruction to compare with.
            eqflags: Combination of ``EQ_*`` flags from ``ida_hexrays``:
                ``EQ_IGNSIZE`` (1) — ignore operand sizes,
                ``EQ_IGNCODE`` (2) — ignore opcode,
                ``EQ_CMPDEST`` (4) — compare destination operand,
                ``EQ_OPTINSN`` (8) — optimizer comparison mode.
        """
        return self._raw.equal_insns(other._raw, eqflags)

    # -- dunder protocols --------------------------------------------------

    def __iter__(self) -> Iterator[MicroOperand]:
        return self.operands()

    def __len__(self) -> int:
        return sum(1 for _ in self.operands())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MicroInstruction):
            return self._raw == other._raw
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, MicroInstruction):
            return self._raw != other._raw
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, MicroInstruction):
            return self._raw < other._raw
        return NotImplemented

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        try:
            opname = MicroOpcode(self._raw.opcode).name
        except ValueError:
            opname = str(self._raw.opcode)
        return f'MicroInstruction(opcode={opname}, ea=0x{self._raw.ea:x})'


# ---------------------------------------------------------------------------
# MicroBlock — wraps mblock_t
# ---------------------------------------------------------------------------


class MicroBlock:
    """Wrapper around an IDA ``mblock_t`` microcode basic block.

    Supports iteration over instructions and navigation to
    successors/predecessors.
    """

    def __init__(self, raw: mblock_t, parent_mf: Optional[MicroBlockArray] = None):
        self._raw = raw
        self._parent_mf = parent_mf
        self._cached_mba: Optional[MicroBlockArray] = None

    # -- raw access --------------------------------------------------------

    @property
    def raw_block(self) -> mblock_t:
        """Get the underlying ``mblock_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def index(self) -> int:
        """Block index (same as serial)."""
        return self._raw.serial

    @property
    def block_type(self) -> MicroBlockType:
        """Block type as a :class:`MicroBlockType` enum."""
        return MicroBlockType(self._raw.type)

    @block_type.setter
    def block_type(self, value: MicroBlockType) -> None:
        self._raw.type = int(value)

    @property
    def block_flags(self) -> MicroBlockFlags:
        """Current block flags as a :class:`MicroBlockFlags` bit-field."""
        return MicroBlockFlags(self._raw.flags)

    @block_flags.setter
    def block_flags(self, value: MicroBlockFlags) -> None:
        self._raw.flags = int(value)

    def set_block_flag(self, flag: MicroBlockFlags) -> None:
        """Set (OR) one or more block flags."""
        self._raw.flags |= int(flag)

    def clear_block_flag(self, flag: MicroBlockFlags) -> None:
        """Clear one or more block flags."""
        self._raw.flags &= ~int(flag)

    @property
    def start_ea(self) -> int:
        """Start effective address of this block."""
        return self._raw.start

    @property
    def end_ea(self) -> int:
        """End effective address of this block."""
        return self._raw.end

    @property
    def serial(self) -> int:
        """Block serial number."""
        return self._raw.serial

    @property
    def head(self) -> Optional[MicroInstruction]:
        """First instruction in the block, or *None* if empty."""
        h = self._raw.head
        if h:
            return MicroInstruction(h, self)
        return None

    @property
    def tail(self) -> Optional[MicroInstruction]:
        """Last instruction in the block, or *None* if empty."""
        t = self._raw.tail
        if t:
            return MicroInstruction(t, self)
        return None

    @property
    def first_regular_insn(self) -> Optional[MicroInstruction]:
        """First non-assertion instruction (wraps ``getf_reginsn()``)."""
        h = self._raw.head
        if not h:
            return None
        reg = ida_hexrays.getf_reginsn(h)
        if reg:
            return MicroInstruction(reg, self)
        return None

    @property
    def mba(self) -> MicroBlockArray:
        """Parent :class:`MicroBlockArray`."""
        if self._parent_mf is not None:
            return self._parent_mf
        # Lazily wrap the raw mba_t and cache to prevent GC
        if self._cached_mba is None:
            self._cached_mba = MicroBlockArray(self._raw.mba)
        return self._cached_mba

    # -- query properties --------------------------------------------------

    @property
    def is_empty(self) -> bool:
        """True if this block has no instructions."""
        return self._raw.head is None

    @property
    def is_branch(self) -> bool:
        """True if this block ends with a conditional branch."""
        return self._raw.is_branch()

    @property
    def is_simple_goto(self) -> bool:
        """True if this block contains only a ``goto`` instruction.

        Commonly used by deobfuscators to detect and simplify goto chains.
        """
        return self._raw.is_simple_goto_block()

    @property
    def is_call_block(self) -> bool:
        """True if this block contains a call instruction."""
        return self._raw.is_call_block()

    @property
    def jump_target(self) -> Optional[int]:
        """Target block serial of the tail jump, or *None*.

        - ``TWO_WAY``: the taken-branch target from the conditional
          jump's ``d`` operand.
        - ``ONE_WAY`` with ``goto``: the goto target from ``l``.
        - ``ONE_WAY`` without ``goto``: implicit fallthrough
          (``serial + 1``).
        - Other block types: *None*.
        """
        tail = self.tail
        if tail is None:
            return None
        if tail.is_conditional_jump():
            return tail.d.block_ref
        if tail.opcode == MicroOpcode.GOTO:
            return tail.l.block_ref
        if self.block_type == MicroBlockType.ONE_WAY:
            return self._raw.serial + 1
        return None

    @property
    def fall_through(self) -> Optional[int]:
        """Fall-through (not-taken) block serial, or *None*.

        Only meaningful for ``TWO_WAY`` blocks.  In IDA's microcode the
        fall-through successor of a conditional branch is always the
        sequentially-next block (``serial + 1``).
        """
        if self.block_type != MicroBlockType.TWO_WAY:
            return None
        return self._raw.serial + 1

    @property
    def predecessor_count(self) -> int:
        """Number of predecessor blocks."""
        return self._raw.npred()

    @property
    def successor_count(self) -> int:
        """Number of successor blocks."""
        return self._raw.nsucc()

    @property
    def instruction_count(self) -> int:
        """Number of real (non-NOP/non-assertion) instructions."""
        return self._raw.get_reginsn_qty()

    # -- iteration ---------------------------------------------------------

    def instructions(self) -> Iterator[MicroInstruction]:
        """Iterate over all instructions in this block."""
        insn = self._raw.head
        while insn:
            yield MicroInstruction(insn, self)
            insn = insn.next

    def __iter__(self) -> Iterator[MicroInstruction]:
        return self.instructions()

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def for_all_instructions(self, visitor: MicroInstructionVisitor) -> int:
        """Visit all instructions in this block (including sub-instructions).

        Args:
            visitor: A :class:`MicroInstructionVisitor`.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_insns(visitor)

    def for_all_operands(self, visitor: MicroOperandVisitor) -> int:
        """Visit all operands in this block (including sub-instruction operands).

        Args:
            visitor: A :class:`MicroOperandVisitor`.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_ops(visitor)

    def successors(self) -> Iterator[MicroBlock]:
        """Iterate over successor blocks."""
        mba_raw = self._raw.mba
        for j in range(self._raw.nsucc()):
            serial = self._raw.succ(j)
            yield MicroBlock(mba_raw.get_mblock(serial), self._parent_mf)

    def predecessors(self) -> Iterator[MicroBlock]:
        """Iterate over predecessor blocks."""
        mba_raw = self._raw.mba
        for j in range(self._raw.npred()):
            serial = self._raw.pred(j)
            yield MicroBlock(mba_raw.get_mblock(serial), self._parent_mf)

    @property
    def successor_serials(self) -> List[int]:
        """List of successor block serial numbers."""
        return [self._raw.succ(j) for j in range(self._raw.nsucc())]

    @property
    def predecessor_serials(self) -> List[int]:
        """List of predecessor block serial numbers."""
        return [self._raw.pred(j) for j in range(self._raw.npred())]

    # -- edge manipulation -------------------------------------------------

    def _resolve_serial(self, block_or_serial: Any) -> int:
        if isinstance(block_or_serial, MicroBlock):
            return block_or_serial.serial
        return int(block_or_serial)

    def add_successor(self, target: Any) -> None:
        """Add a successor edge from this block to *target*.

        Also adds this block to *target*'s predecessor set.

        Args:
            target: A :class:`MicroBlock` or a block serial number.
        """
        serial = self._resolve_serial(target)
        self._raw.succset.push_back(serial)
        self._raw.mba.get_mblock(serial).predset.push_back(self._raw.serial)

    def remove_successor(self, target: Any) -> None:
        """Remove a successor edge from this block to *target*.

        Also removes this block from *target*'s predecessor set.

        Args:
            target: A :class:`MicroBlock` or a block serial number.
        """
        serial = self._resolve_serial(target)
        self._raw.succset._del(serial)
        self._raw.mba.get_mblock(serial).predset._del(self._raw.serial)

    def clear_successors(self) -> None:
        """Remove all successor edges.

        Also removes this block from each successor's predecessor set.
        """
        for serial in self.successor_serials:
            self._raw.mba.get_mblock(serial).predset._del(self._raw.serial)
        self._raw.succset.clear()

    def clear_predecessors(self) -> None:
        """Remove all predecessor edges.

        Also removes this block from each predecessor's successor set.
        """
        for serial in self.predecessor_serials:
            self._raw.mba.get_mblock(serial).succset._del(self._raw.serial)
        self._raw.predset.clear()

    def replace_successor(self, old_target: Any, new_target: Any) -> None:
        """Replace a successor edge: remove *old_target*, add *new_target*.

        Also updates predecessor sets of both target blocks.

        Args:
            old_target: A :class:`MicroBlock` or serial to disconnect.
            new_target: A :class:`MicroBlock` or serial to connect.
        """
        self.remove_successor(old_target)
        self.add_successor(new_target)

    # -- use-def (intra-block) ---------------------------------------------

    def build_use_list(self, insn: MicroInstruction, maymust: int = 0) -> MicroLocationSet:
        """Build the use-list for an instruction in this block.

        Args:
            insn: The instruction to analyze.
            maymust: ``MUST_ACCESS`` or ``MAY_ACCESS`` from ``ida_hexrays``.
        """
        return MicroLocationSet(self._raw.build_use_list(insn._raw, maymust))

    def build_def_list(self, insn: MicroInstruction, maymust: int = 0) -> MicroLocationSet:
        """Build the def-list for an instruction in this block.

        Args:
            insn: The instruction to analyze.
            maymust: ``MUST_ACCESS`` or ``MAY_ACCESS`` from ``ida_hexrays``.
        """
        return MicroLocationSet(self._raw.build_def_list(insn._raw, maymust))

    def append_use_list(
        self,
        target: MicroLocationSet,
        operand: MicroOperand,
        maymust: int = 0,
    ) -> None:
        """Append operand use-locations to an existing set.

        Unlike :meth:`build_use_list` which returns a fresh set, this
        appends to *target*, allowing incremental construction.

        Args:
            target: Location set to append to.
            operand: The operand to analyze.
            maymust: ``MUST_ACCESS`` (0) or ``MAY_ACCESS`` (1).
        """
        self._raw.append_use_list(target._raw, operand._raw, maymust)

    def append_def_list(
        self,
        target: MicroLocationSet,
        operand: MicroOperand,
        maymust: int = 0,
    ) -> None:
        """Append operand def-locations to an existing set.

        Args:
            target: Location set to append to.
            operand: The operand to analyze.
            maymust: ``MUST_ACCESS`` (0) or ``MAY_ACCESS`` (1).
        """
        self._raw.append_def_list(target._raw, operand._raw, maymust)

    def build_lists(self, kill_deads: bool = False) -> int:
        """Build def-use lists and optionally eliminate dead instructions.

        Args:
            kill_deads: If True, delete dead instructions.

        Returns:
            Number of eliminated instructions.
        """
        return self._raw.build_lists(kill_deads)

    def optimize_insn(self, insn: MicroInstruction, optflags: int = 0) -> int:
        """Optimize a single instruction in the context of this block.

        May modify other instructions in the block but will not destroy
        top-level instructions (converts them to NOPs instead).

        Args:
            insn: A top-level instruction in this block.
            optflags: Optimization flag bits.

        Returns:
            Number of changes made.
        """
        return self._raw.optimize_insn(insn._raw, optflags)

    def is_rhs_redefined(
        self,
        insn: MicroInstruction,
        start: MicroInstruction,
        end: Optional[MicroInstruction] = None,
    ) -> bool:
        """Check if the right-hand side of *insn* is redefined in a range.

        Args:
            insn: Instruction whose source operands to check.
            start: Start of the range (top-level instruction).
            end: End of the range (exclusive, top-level instruction).
                If *None*, checks to the end of the block.
        """
        end_raw = end._raw if end is not None else None
        return self._raw.is_rhs_redefined(insn._raw, start._raw, end_raw)

    def get_valranges(
        self,
        operand: MicroOperand,
        vrflags: int = 0,
        insn: Optional[MicroInstruction] = None,
    ) -> Optional[valrng_t]:
        """Compute the possible value range for an operand.

        When *insn* is ``None``, computes ranges at the block level.
        When *insn* is given, computes ranges at that specific instruction.

        Requires that value-range analysis has been performed (maturity
        ``GLBOPT1`` or higher).

        Args:
            operand: The operand to query (typically a register or stack
                variable).  A ``vivl_t`` is constructed from its underlying
                ``mop_t`` automatically.
            vrflags: Flags controlling the analysis (default 0).
            insn: If given, compute the range at this instruction.

        Returns:
            A ``valrng_t`` with the result, or *None* if the range
            could not be determined.
        """
        vivl = ida_hexrays.vivl_t(operand._raw)
        res = ida_hexrays.valrng_t()
        if insn is not None:
            ok = self._raw.get_valranges(res, vivl, insn._raw, vrflags)
        else:
            ok = self._raw.get_valranges(res, vivl, vrflags)
        return res if ok else None

    def request_propagation(self) -> None:
        """Request value propagation for this block."""
        self._raw.request_propagation()

    def find_first_use(
        self,
        locations: MicroLocationSet,
        start: MicroInstruction,
        end: Optional[MicroInstruction] = None,
    ) -> Optional[MicroInstruction]:
        """Find the first instruction after *start* that uses *locations*.

        .. warning::
            *locations* is **modified** during the search: redefined
            locations are removed from the set.  Pass a :meth:`copy`
            if you need to preserve the original.

        Args:
            locations: The set of locations to search for.
            start: Start searching from this instruction.
            end: Stop searching at this instruction (exclusive). If *None*,
                searches to the end of the block.
        """
        end_raw = end._raw if end is not None else None
        result = self._raw.find_first_use(locations._raw, start._raw, end_raw)
        if result:
            return MicroInstruction(result, self)
        return None

    def find_redefinition(
        self,
        locations: MicroLocationSet,
        start: MicroInstruction,
        end: Optional[MicroInstruction] = None,
    ) -> Optional[MicroInstruction]:
        """Find the first instruction after *start* that redefines *locations*.

        Args:
            locations: The set of locations to search for.
            start: Start searching from this instruction.
            end: Stop searching at this instruction (exclusive). If *None*,
                searches to the end of the block.
        """
        end_raw = end._raw if end is not None else None
        result = self._raw.find_redefinition(locations._raw, start._raw, end_raw)
        if result:
            return MicroInstruction(result, self)
        return None

    def build_operand_locations(self, operand: MicroOperand) -> MicroLocationSet:
        """Build the location set for a single operand in this block's context.

        Supports registers (``mop_r``), stack variables (``mop_S``),
        and local variables (``mop_l``).  Returns an empty set for
        other operand types.
        """
        ml = mlist_t()
        self._raw.append_use_list(ml, operand.raw_operand, AccessType.MUST)
        return MicroLocationSet(ml)

    def find_def_backward(
        self,
        operand: MicroOperand,
        start: Optional[MicroInstruction] = None,
    ) -> Optional[MicroInstruction]:
        """Find the nearest instruction that defines *operand*, searching backward.

        Scans from the instruction *before* ``start`` toward the head of the
        block.  If ``start`` is *None*, scanning begins at the tail.

        Only register (``mop_r``), stack variable (``mop_S``), and local
        variable (``mop_l``) operands can be tracked.

        Args:
            operand: The operand whose definition to search for.
            start: Reference instruction (excluded from search).
                If *None*, the entire block is searched from the tail.

        Returns:
            The defining :class:`MicroInstruction`, or *None* if no
            definition is found within this block.
        """
        locations = self.build_operand_locations(operand)
        if not locations:
            return None

        insn = start.prev if start is not None else self.tail
        while insn is not None:
            def_set = self.build_def_list(insn, AccessType.MAY)
            if locations.has_common(def_set):
                return insn
            insn = insn.prev
        return None

    def trace_def_backward(
        self,
        operand: MicroOperand,
        start: Optional[MicroInstruction] = None,
        max_blocks: int = 64,
    ) -> List[MicroInstruction]:
        """Trace the definition chain of *operand* backward through ``mov`` instructions.

        Starting from *start* (or the tail), this method:

        1. Searches backward for the instruction that defines *operand*.
        2. If the defining instruction is a ``mov``, records it and
           continues searching for the definition of the ``mov``'s source.
        3. Follows single-predecessor paths across block boundaries.
        4. Stops when a non-``mov`` definition is found, the source is
           a constant or non-trackable operand, or the search is
           exhausted.

        Only register (``mop_r``) and stack variable (``mop_S``)
        operands are followed through ``mov`` chains.  Local variables
        (``mop_l``) are not typically present at the maturity levels
        where this method is most useful.

        Args:
            operand: The operand to trace.
            start: Reference instruction (excluded from search).
                If *None*, the entire block is searched from the tail.
            max_blocks: Maximum number of predecessor blocks to follow
                (default 64).

        Returns:
            A list of :class:`MicroInstruction` forming the definition
            chain, ordered from nearest to earliest.  The last entry is
            the ultimate defining instruction.  Returns an empty list
            if no definition is found.

        Example::

            # Find what value is ultimately moved into rax
            for block in mf.blocks(skip_sentinels=True):
                for insn in block:
                    if insn.l.is_register:
                        chain = block.trace_def_backward(insn.l, start=insn)
                        if chain:
                            ultimate = chain[-1]
                            print(f"{insn.l} defined by: {ultimate}")
        """
        chain: List[MicroInstruction] = []
        block: MicroBlock = self
        cur_start: Optional[MicroInstruction] = start
        cur_operand: MicroOperand = operand
        blocks_traversed = 0

        while True:
            found = block.find_def_backward(cur_operand, cur_start)

            if found is not None:
                chain.append(found)

                # If it's a mov with a trackable source, follow the chain.
                if found.opcode == MicroOpcode.MOV:
                    src = found.l
                    if src.is_register or src.is_stack_var:
                        cur_operand = src
                        cur_start = found
                        continue
                # Non-mov or non-variable source — chain ends here.
                break

            # Not found in this block — try the sole predecessor.
            blocks_traversed += 1
            if blocks_traversed > max_blocks:
                break
            if block.predecessor_count != 1:
                break
            block = next(block.predecessors())
            cur_start = None  # search from tail of predecessor

        return chain

    # -- mutation ----------------------------------------------------------

    def insert_instruction(
        self, new_minsn: MicroInstruction, after: Optional[MicroInstruction] = None
    ) -> None:
        """Insert a new instruction into this block.

        Args:
            new_minsn: The instruction to insert.
            after: Insert after this instruction. If *None*, insert at head.
        """
        if after is None:
            self._raw.insert_into_block(new_minsn._raw, None)
        else:
            self._raw.insert_into_block(new_minsn._raw, after._raw)

    def remove_instruction(self, insn: MicroInstruction) -> None:
        """Remove an instruction from this block."""
        self._raw.remove_from_block(insn._raw)

    def make_nop(self, insn: MicroInstruction) -> None:
        """Convert an instruction to a NOP within this block."""
        self._raw.make_nop(insn._raw)

    def contains_instruction(self, insn: MicroInstruction) -> bool:
        """True if *insn* belongs to this block's instruction list."""
        cur = self._raw.head
        target_id = insn._raw.obj_id
        while cur:
            if cur.obj_id == target_id:
                return True
            cur = cur.next
        return False

    def mark_lists_dirty(self) -> None:
        """Invalidate the use-def lists for this block.

        Must be called after modifying instructions to keep the
        analysis state consistent.
        """
        self._raw.mark_lists_dirty()

    def optimize_block(self) -> int:
        """Optimize this basic block.

        Usually there is no need to call this explicitly because the
        decompiler will call it itself if an optimizer callback returns
        non-zero.

        Returns:
            Number of changes made.
        """
        return self._raw.optimize_block()

    def optimize_useless_jump(self) -> int:
        """Remove a useless jump at the end of this block.

        Both conditional and unconditional jumps (and jtbl) are
        handled.  Side effects are preserved when removing the jump.

        Returns:
            Number of changes made.
        """
        return self._raw.optimize_useless_jump()

    def replace_instruction(
        self, old_insn: MicroInstruction, new_insn: MicroInstruction
    ) -> None:
        """Replace *old_insn* with *new_insn*, performing cleanup.

        Equivalent to the common deobfuscation idiom::

            old.swap(new)
            old.optimize_solo()
            block.mark_lists_dirty()

        Args:
            old_insn: The instruction to replace (must be in this block).
            new_insn: The replacement instruction.

        Raises:
            ValueError: If *old_insn* is not found in this block.
        """
        if not self.contains_instruction(old_insn):
            raise ValueError("old_insn is not in this block")
        old_insn.swap(new_insn)
        old_insn.optimize_solo()
        self.mark_lists_dirty()

    def __str__(self) -> str:
        return '\n'.join(str(insn) for insn in self)

    def __repr__(self) -> str:
        try:
            type_name = MicroBlockType(self._raw.type).name
        except ValueError:
            type_name = str(self._raw.type)
        return (
            f'MicroBlock(serial={self._raw.serial}, type={type_name}, '
            f'start=0x{self._raw.start:x}, end=0x{self._raw.end:x})'
        )


# ---------------------------------------------------------------------------
# MicroBlockArray — wraps mba_t
# ---------------------------------------------------------------------------


class MicroBlockArray:
    """Wrapper around an IDA ``mba_t`` (micro block array).

    An ``mba_t`` can represent a single function or an arbitrary address
    range.  Supports iteration over blocks, traversal, and access to
    analysis primitives.
    """

    def __init__(self, raw: mba_t, _owner: Any = None):
        self._raw = raw
        self._owner = _owner  # prevent GC of parent (e.g. cfunc_t)

    # -- raw access --------------------------------------------------------

    @property
    def raw_mba(self) -> mba_t:
        """Get the underlying ``mba_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def maturity(self) -> MicroMaturity:
        """Current maturity level."""
        return MicroMaturity(self._raw.maturity)

    @property
    def mba_flags(self) -> MbaFlags:
        """Current MBA flags as a :class:`MbaFlags` bit-field."""
        return MbaFlags(self._raw.get_mba_flags())

    def set_mba_flag(self, flag: MbaFlags) -> None:
        """Set (OR) one or more MBA flags, leaving others unchanged."""
        self._raw.set_mba_flags(int(flag))

    def clear_mba_flag(self, flag: MbaFlags) -> None:
        """Clear one or more MBA flags, leaving others unchanged."""
        self._raw.clr_mba_flags(int(flag))

    @property
    def block_count(self) -> int:
        """Total number of blocks (including sentinels)."""
        return self._raw.qty

    @property
    def entry_ea(self) -> int:
        """Entry effective address of the function."""
        return self._raw.entry_ea

    @property
    def entry_block(self) -> MicroBlock:
        """First block (index 0)."""
        return MicroBlock(self._raw.get_mblock(0), self)

    # -- state queries -----------------------------------------------------

    @property
    def has_over_chains(self) -> bool:
        """True if overlapped-variable chains have been computed."""
        return self._raw.has_over_chains()

    @property
    def final_type(self) -> tinfo_t:
        """Return type of the function."""
        return self._raw.final_type

    @property
    def vars(self) -> MicroLocalVars:
        """Local variables (available after ``MMAT_LVARS`` maturity)."""
        return MicroLocalVars(self._raw.vars, self)

    @property
    def argument_indices(self) -> List[int]:
        """Indices of function arguments in the local variable list."""
        raw = self._raw.argidx
        return [raw.at(i) for i in range(raw.size())]

    @property
    def return_variable_index(self) -> int:
        """Index of the return variable in the local variable list, or -1."""
        return self._raw.retvaridx

    # -- iteration ---------------------------------------------------------

    def __iter__(self) -> Iterator[MicroBlock]:
        """Iterate over all blocks."""
        for i in range(self._raw.qty):
            yield MicroBlock(self._raw.get_mblock(i), self)

    def __getitem__(self, i: int) -> MicroBlock:
        """Get block by index (supports negative indexing)."""
        if i < 0:
            i += self._raw.qty
        if i < 0 or i >= self._raw.qty:
            raise IndexError(f'Block index out of range (0..{self._raw.qty - 1})')
        return MicroBlock(self._raw.get_mblock(i), self)

    def __len__(self) -> int:
        return self._raw.qty

    def blocks(self, skip_sentinels: bool = False) -> Iterator[MicroBlock]:
        """Iterate over blocks.

        Args:
            skip_sentinels: If True, skip the entry block (index 0)
                and BLT_STOP blocks.
        """
        for block in self:
            if skip_sentinels:
                if block.index == 0:
                    continue
                if block.block_type == MicroBlockType.STOP:
                    continue
            yield block

    def instructions(self, skip_sentinels: bool = False) -> Iterator[MicroInstruction]:
        """Flat walk over all instructions.

        Args:
            skip_sentinels: If True, skip sentinel blocks.
        """
        for block in self.blocks(skip_sentinels=skip_sentinels):
            yield from block

    def find_instructions(
        self,
        opcode: Optional[MicroOpcode] = None,
        operand_type: Optional[MicroOperandType] = None,
    ) -> Iterator[MicroInstruction]:
        """Find instructions matching the given criteria.

        Args:
            opcode: Filter by opcode.
            operand_type: Filter by operand type (any of l, r, d).
        """
        for insn in self.instructions():
            if opcode is not None and insn.opcode != opcode:
                continue
            if operand_type is not None:
                has_type = any(op.type == operand_type for op in insn)
                if not has_type:
                    continue
            yield insn

    # -- graph & analysis --------------------------------------------------

    def analyze_calls(self, flags: AnalyzeCallsFlags = AnalyzeCallsFlags(0)) -> int:
        """Analyze call instructions and determine calling conventions.

        Args:
            flags: Analysis flags (e.g. ``AnalyzeCallsFlags.GUESS``).

        Returns:
            Number of calls analyzed, or negative on failure.
        """
        return self._raw.analyze_calls(int(flags))

    def get_graph(self) -> MicroGraph:
        """Get the wrapped :class:`MicroGraph`."""
        return MicroGraph(self._raw.get_graph(), _parent_mf=self)

    def find_mop(
        self, ctx: Any, ea: int, is_dest: bool, locations: MicroLocationSet
    ) -> Optional[MicroOperand]:
        """Find a micro-operand by context, address, and location set.

        Note: The returned operand does not carry a parent instruction
        reference because ``find_mop`` does not expose which instruction
        the operand belongs to.  The caller must hold a reference to this
        :class:`MicroBlockArray` while using the result.
        """
        result = self._raw.find_mop(ctx, ea, is_dest, locations._raw)
        if result:
            return MicroOperand(result)
        return None

    # -- visitor dispatch --------------------------------------------------

    def for_all_top_instructions(self, visitor: MicroInstructionVisitor) -> int:
        """Visit all top-level instructions across all blocks.

        Args:
            visitor: A :class:`MicroInstructionVisitor`.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_topinsns(visitor)

    def for_all_instructions(self, visitor: MicroInstructionVisitor) -> int:
        """Visit all instructions (including sub-instructions) across all blocks.

        Args:
            visitor: A :class:`MicroInstructionVisitor`.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_insns(visitor)

    def for_all_operands(self, visitor: MicroOperandVisitor) -> int:
        """Visit all operands across all blocks and sub-instructions.

        Args:
            visitor: A :class:`MicroOperandVisitor`.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_ops(visitor)

    # -- mutation ----------------------------------------------------------

    def alloc_kernel_register(self, size: int, check_size: bool = True) -> int:
        """Allocate a kernel register.

        Kernel registers are temporary registers that do not interfere
        with the processor's own registers.

        Args:
            size: Size of the register in bytes.
            check_size: If True, only sizes matching a basic type are
                accepted.

        Returns:
            Allocated micro-register number, or ``mr_none`` on failure.
        """
        return self._raw.alloc_kreg(size, check_size)

    def free_kernel_register(self, reg: int, size: int) -> None:
        """Free a previously allocated kernel register.

        Args:
            reg: The micro-register number returned by :meth:`alloc_kernel_register`.
            size: Size of the register in bytes (must match allocation).
        """
        self._raw.free_kreg(reg, size)

    def alloc_fictional_address(self, real_ea: int = ida_idaapi.BADADDR) -> int:
        """Allocate a fictional address for new instructions or variables.

        Fictional addresses are unique addresses from an unallocated
        range, useful when creating new instructions where reusing an
        existing address would cause conflicts.

        Args:
            real_ea: A real instruction address to associate with,
                or ``BADADDR``.

        Returns:
            A unique fictional address.
        """
        return self._raw.alloc_fict_ea(real_ea)

    def insert_block(self, index: int) -> MicroBlock:
        """Insert a new block at the given index."""
        blk = self._raw.insert_block(index)
        return MicroBlock(blk, self)

    def remove_block(self, block: MicroBlock) -> bool:
        """Remove a block.

        Returns:
            True if at least one other block became empty or unreachable.
        """
        return self._raw.remove_block(block._raw)

    def remove_blocks(self, start: int, end: int) -> bool:
        """Remove a range of blocks by serial number.

        Args:
            start: First block serial to remove (inclusive).
            end: Last block serial to remove (exclusive).

        Returns:
            True if at least one other block became empty or unreachable.
        """
        return self._raw.remove_blocks(start, end)

    def split_block(
        self, block: MicroBlock, start_insn: MicroInstruction
    ) -> MicroBlock:
        """Split a block at the given instruction.

        A new block is inserted after *block*, and all instructions from
        *start_insn* to the end of *block* are moved to the new block.

        Args:
            block: Block to split.
            start_insn: First instruction to move to the new block.

        Returns:
            The newly created :class:`MicroBlock`.
        """
        raw = self._raw.split_block(block._raw, start_insn._raw)
        return MicroBlock(raw, self)

    def copy_block(
        self,
        source: MicroBlock,
        new_serial: int,
        flags: CopyBlockFlags = CopyBlockFlags.FAST | CopyBlockFlags.MINREF,
    ) -> MicroBlock:
        """Make a copy of a block and insert it at *new_serial*.

        Args:
            source: The block to copy.
            new_serial: Serial number where the copy will be inserted.
                Existing blocks at this index and above are shifted.
            flags: Copy flags controlling reference updates and
                jump optimization.  The default
                (``FAST | MINREF``) matches the IDA SDK default.

        Returns:
            The newly created :class:`MicroBlock`.
        """
        raw = self._raw.copy_block(source._raw, new_serial, int(flags))
        return MicroBlock(raw, self)

    def set_maturity(self, maturity: MicroMaturity) -> None:
        """Set the microcode maturity level."""
        self._raw.set_maturity(int(maturity))

    def create_helper_call(self, ea: int, helper_name: str) -> MicroInstruction:
        """Create a call to a helper function.

        The returned instruction is detached (not yet in any block).
        The caller must hold a reference to this :class:`MicroBlockArray`
        while using the result.
        """
        insn = self._raw.create_helper_call(ea, helper_name)
        return MicroInstruction(insn)

    def verify(self, always: bool = False) -> None:
        """Verify the microcode structure for consistency.

        If any inconsistency is discovered, an internal error will be
        generated.  It is strongly recommended to call this before
        returning control to the decompiler from callbacks that modify
        the microcode.

        Args:
            always: If False, the check is only performed when IDA runs
                under a debugger.  If True, always verify.
        """
        self._raw.verify(always)

    def mark_chains_dirty(self) -> None:
        """Invalidate the use-def chains for the entire function.

        Call after structural changes (block insertion/removal, edge
        changes) that affect global data-flow.
        """
        self._raw.mark_chains_dirty()

    def remove_empty_and_unreachable_blocks(self) -> bool:
        """Delete all empty and unreachable blocks.

        Blocks may become empty or unreachable after control-flow
        modifications (e.g. deobfuscation, unflattening).  This method
        cleans them up in a single pass.

        Returns:
            True if any blocks were removed.
        """
        return self._raw.remove_empty_and_unreachable_blocks()

    def merge_blocks(self) -> bool:
        """Merge blocks that form a linear flow.

        Combines consecutive blocks where one falls through to the next
        with no other predecessors.  Also calls
        :meth:`remove_empty_and_unreachable_blocks` internally.

        Returns:
            True if any blocks were merged.
        """
        return self._raw.merge_blocks()

    def optimize_local(self, locopt_level: int = 0) -> int:
        """Run local optimization on all blocks.

        This triggers a local optimization pass (constant folding,
        dead-code elimination, etc.) and is typically called after
        structural modifications.

        Args:
            locopt_level: Optimization level (0 is standard).

        Returns:
            Number of changes made.
        """
        return self._raw.optimize_local(locopt_level)

    def optimize_global(self) -> MicroError:
        """Optimize microcode globally.

        Applies various optimization methods until a fixed point is
        reached, then preallocates local variables unless the
        requested maturity forbids it.

        Returns:
            Error code (:attr:`MicroError.OK` on success).
        """
        return MicroError(self._raw.optimize_global())

    def alloc_local_variables(self) -> None:
        """Allocate local variables.

        Must be called only immediately after :meth:`optimize_global`,
        with no modifications to the microcode.  Converts registers,
        stack variables, and similar operands into ``mop_l``.  After
        this call the microcode reaches its final state.
        """
        self._raw.alloc_lvars()

    def build_graph(self) -> None:
        """Build (or rebuild) the block-level control flow graph.

        Must be called after heavy structural modifications (block
        insertion/removal, edge changes) before the microcode can
        be further analyzed or verified.
        """
        self._raw.build_graph()

    # -- stack offset conversion -------------------------------------------

    def stack_offset_decompiler_to_ida(self, vd_offset: int) -> int:
        """Convert a decompiler stack offset to an IDA stack offset.

        Args:
            vd_offset: Decompiler-style stack offset.

        Returns:
            IDA-style stack offset.
        """
        return self._raw.stkoff_vd2ida(vd_offset)

    def stack_offset_ida_to_decompiler(self, ida_offset: int) -> int:
        """Convert an IDA stack offset to a decompiler stack offset.

        Args:
            ida_offset: IDA-style stack offset.

        Returns:
            Decompiler-style stack offset.
        """
        return self._raw.stkoff_ida2vd(ida_offset)

    def location_ida_to_decompiler(self, loc: Any, width: int) -> Any:
        """Convert an IDA ``argloc_t`` to a decompiler ``vdloc_t``.

        Args:
            loc: An ``argloc_t`` location.
            width: Size in bytes.

        Returns:
            A ``vdloc_t`` location.
        """
        return self._raw.idaloc2vd(loc, width)

    def location_decompiler_to_ida(self, loc: Any, width: int, spd: Optional[int] = None) -> Any:
        """Convert a decompiler ``vdloc_t`` to an IDA ``argloc_t``.

        Args:
            loc: A ``vdloc_t`` location.
            width: Size in bytes.
            spd: Optional stack pointer delta.

        Returns:
            An ``argloc_t`` location.
        """
        if spd is not None:
            return self._raw.vd2idaloc(loc, width, spd)
        return self._raw.vd2idaloc(loc, width)

    # -- frame/stack properties --------------------------------------------

    @property
    def temp_stack_size(self) -> int:
        """Size of the temporary stack area in bytes."""
        return self._raw.tmpstk_size

    @property
    def frame_size(self) -> int:
        """Size of the local variables area in bytes."""
        return self._raw.frsize

    @property
    def stacksize(self) -> int:
        """Total stack size used by the function in bytes."""
        return self._raw.stacksize

    @property
    def incoming_args_offset(self) -> int:
        """Offset of the incoming arguments area."""
        return self._raw.inargoff

    @property
    def retsize(self) -> int:
        """Size of the return address on the stack."""
        return self._raw.retsize

    # -- serialization -----------------------------------------------------

    def serialize(self) -> bytes:
        """Serialize the microcode to bytes."""
        return self._raw.serialize()

    @staticmethod
    def deserialize(data: bytes) -> MicroBlockArray:
        """Deserialize a microcode function from bytes."""
        raw = mba_t.deserialize(data)
        return MicroBlockArray(raw)

    # -- debugging ---------------------------------------------------------

    def dump(self) -> None:
        """Dump microcode to a file for debugging.

        The file is created in the directory pointed to by the ``IDA_DUMPDIR``
        environment variable. Dump is only created when IDA is run under a
        debugger.
        """
        self._raw.dump()

    def dump_with_title(self, title: str, verify: bool = True) -> None:
        """Dump microcode with a title and optional verification.

        Args:
            title: Title/header for the dump output.
            verify: If True, verify microcode consistency before dumping.
        """
        self._raw.dump_mba(verify, title)

    # -- text / display ----------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> List[str]:
        """Get text representation of the microcode.

        Prints each non-sentinel block individually.  When *remove_tags*
        is True (default), IDA color tags are stripped and empty lines
        and whitespace are removed.  When False, raw block output
        (including color tags and blank lines) is returned as-is.
        """
        lines: List[str] = []
        for block in self.blocks(skip_sentinels=True):
            vp = ida_hexrays.qstring_printer_t(None, True)
            block.raw_block._print(vp)
            block_lines = vp.get_s().split('\n')

            if not remove_tags:
                lines.extend(block_lines)
                continue

            for line in block_lines:
                line = ida_lines.tag_remove(line)
                if line:
                    lines.append(line.strip())
        return lines

    def __str__(self) -> str:
        return '\n'.join(self.to_text())

    def __repr__(self) -> str:
        try:
            mat_name = MicroMaturity(self._raw.maturity).name
        except ValueError:
            mat_name = str(self._raw.maturity)
        return (
            f'MicroBlockArray(entry=0x{self._raw.entry_ea:x}, '
            f'maturity={mat_name}, blocks={self._raw.qty})'
        )


# ---------------------------------------------------------------------------
# MicroGraph — wraps mbl_graph_t
# ---------------------------------------------------------------------------


class MicroGraph:
    """Wrapper around an IDA ``mbl_graph_t`` block-level control flow graph.

    Provides iteration and use-def chain access.
    """

    def __init__(self, raw: Any, _parent_mf: Optional[MicroBlockArray] = None) -> None:
        self._raw = raw
        self._parent_mf = _parent_mf  # prevent GC of parent mba_t

    @property
    def raw_graph(self) -> Any:
        """Get the underlying ``mbl_graph_t`` object."""
        return self._raw

    def __len__(self) -> int:
        return self._raw.node_qty()

    def __getitem__(self, i: int) -> MicroBlock:
        qty = self._raw.node_qty()
        if i < 0:
            i += qty
        if i < 0 or i >= qty:
            raise IndexError(f'Graph node index out of range (0..{qty - 1})')
        return MicroBlock(self._raw.get_mblock(i), self._parent_mf)

    def __iter__(self) -> Iterator[MicroBlock]:
        for i in range(self._raw.node_qty()):
            yield MicroBlock(self._raw.get_mblock(i), self._parent_mf)

    def get_use_def_chains(self, gctype: int) -> Any:
        """Get use-def chains (returns raw ``graph_chains_t``).

        Args:
            gctype: Chain type, e.g. ``ida_hexrays.GC_REGS_AND_STKVARS``.
        """
        return self._raw.get_ud(gctype)

    def get_def_use_chains(self, gctype: int) -> Any:
        """Get def-use chains (returns raw ``graph_chains_t``).

        Args:
            gctype: Chain type, e.g. ``ida_hexrays.GC_REGS_AND_STKVARS``.
        """
        return self._raw.get_du(gctype)

    def is_redefined_globally(
        self,
        locations: MicroLocationSet,
        block1: int,
        block2: int,
        insn1: MicroInstruction,
        insn2: MicroInstruction,
        maymust: int = 0,
    ) -> bool:
        """Check if locations are redefined globally between two points.

        Args:
            locations: Location set to check.
            block1: First block serial.
            block2: Second block serial.
            insn1: First instruction.
            insn2: Second instruction.
            maymust: ``MUST_ACCESS`` (0) or ``MAY_ACCESS`` (1).
        """
        return self._raw.is_redefined_globally(
            locations._raw, block1, block2, insn1._raw, insn2._raw, maymust
        )

    def is_used_globally(
        self,
        locations: MicroLocationSet,
        block1: int,
        block2: int,
        insn1: MicroInstruction,
        insn2: MicroInstruction,
        maymust: int = 0,
    ) -> bool:
        """Check if locations are used globally between two points.

        Args:
            locations: Location set to check.
            block1: First block serial.
            block2: Second block serial.
            insn1: First instruction.
            insn2: Second instruction.
            maymust: ``MUST_ACCESS`` (0) or ``MAY_ACCESS`` (1).
        """
        return self._raw.is_used_globally(
            locations._raw, block1, block2, insn1._raw, insn2._raw, maymust
        )

    def __repr__(self) -> str:
        return f'MicroGraph(blocks={self._raw.node_qty()})'


# ---------------------------------------------------------------------------
# MicroLocationSet — wraps mlist_t
# ---------------------------------------------------------------------------


class MicroLocationSet:
    """Wrapper around an IDA ``mlist_t`` set of memory/register locations.

    Supports Pythonic set operations for use-def analysis::

        use_set = block.build_use_list(insn)
        def_set = block.build_def_list(insn)
        if search_set.has_common(use_set):  # any overlap?
            results.append(insn.ea)
        search_set -= def_set          # subtract
    """

    def __init__(self, raw: Optional[mlist_t] = None):
        self._raw = raw if raw is not None else ida_hexrays.mlist_t()

    @property
    def raw_mlist(self) -> mlist_t:
        """Get the underlying ``mlist_t`` object."""
        return self._raw

    def copy(self) -> MicroLocationSet:
        """Return a shallow copy of this location set."""
        new = MicroLocationSet()
        new._raw.add(self._raw)
        return new

    def add(self, other: MicroLocationSet) -> None:
        """Union this set with *other* in-place."""
        self._raw.add(other._raw)

    def add_register(self, mreg: int, size: int) -> bool:
        """Add a micro-register range to the set.

        Args:
            mreg: Micro-register number.
            size: Size in bytes.

        Returns:
            True if the set changed.
        """
        return self._raw.add(mreg, size)

    def add_memory(self, ea: int, size: int) -> bool:
        """Add a memory range to the set.

        Args:
            ea: Memory address.
            size: Size in bytes.

        Returns:
            True if the set changed.
        """
        return self._raw.addmem(ea, size)

    def subtract(self, other: MicroLocationSet) -> None:
        """Subtract *other* from this set in-place."""
        self._raw.sub(other._raw)

    def subtract_register(self, mreg: int, size: int) -> bool:
        """Remove a micro-register range from the set.

        Args:
            mreg: Micro-register number.
            size: Size in bytes.

        Returns:
            True if the set changed.
        """
        return self._raw.sub(mreg, size)

    def has_common(self, other: MicroLocationSet) -> bool:
        """True if this set has any locations in common with *other*."""
        return self._raw.has_common(other._raw)

    def has_register(self, mreg: int) -> bool:
        """True if the given micro-register is in the set.

        Args:
            mreg: Micro-register number.
        """
        return self._raw.has(mreg)

    def has_all_register(self, mreg: int, size: int) -> bool:
        """True if the *entire* register range is in the set.

        Args:
            mreg: Micro-register number.
            size: Size in bytes.
        """
        return self._raw.has_all(mreg, size)

    def has_any_register(self, mreg: int, size: int) -> bool:
        """True if *any* part of the register range is in the set.

        Args:
            mreg: Micro-register number.
            size: Size in bytes.
        """
        return self._raw.has_any(mreg, size)

    @property
    def has_memory(self) -> bool:
        """True if the set contains any memory locations."""
        return self._raw.has_memory()

    @property
    def count(self) -> int:
        """Number of individual locations in the set."""
        return self._raw.count()

    def clear(self) -> None:
        """Remove all locations from this set."""
        self._raw.clear()

    def to_text(self) -> str:
        """Get text representation of this location set."""
        return self._raw.dstr()

    def __bool__(self) -> bool:
        return not self._raw.empty()

    def __and__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Return the intersection of this set and *other*."""
        result = self.copy()
        result._raw.intersect(other._raw)
        return result

    def __or__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Return the union of this set and *other*."""
        result = self.copy()
        result.add(other)
        return result

    def __ior__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Union in-place."""
        self.add(other)
        return self

    def __sub__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Return this set minus *other*."""
        result = self.copy()
        result.subtract(other)
        return result

    def __isub__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Subtract in-place."""
        self.subtract(other)
        return self

    def issuperset(self, other: MicroLocationSet) -> bool:
        """True if this set contains all locations from *other*."""
        return self._raw.includes(other._raw)

    def issubset(self, other: MicroLocationSet) -> bool:
        """True if all locations in this set are also in *other*."""
        return other._raw.includes(self._raw)

    def __contains__(self, other: MicroLocationSet) -> bool:
        """True if *other* is a subset of this set.

        Note: Unlike Python's built-in ``set`` where ``x in s`` tests
        membership of a single element, ``MicroLocationSet`` elements
        are not individually addressable.  This operator tests whether
        all locations in *other* are present in this set (superset check),
        matching the semantics of ``mlist_t::includes``.
        """
        return self._raw.includes(other._raw)

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        return f'MicroLocationSet(count={self._raw.count()}, empty={self._raw.empty()})'


# ---------------------------------------------------------------------------
# Visitor base classes
# ---------------------------------------------------------------------------


class MicroInstructionVisitor(ida_hexrays.minsn_visitor_t):
    """Visitor that delivers :class:`MicroInstruction` wrappers.

    Override :meth:`visit` instead of ``visit_minsn()``.
    """

    def __init__(self) -> None:
        super().__init__()

    def visit_minsn(self) -> int:
        is_top = self.curins.obj_id == self.topins.obj_id
        mba = MicroBlockArray(self.blk.mba)
        parent = MicroBlock(self.blk, mba) if is_top else None
        return self.visit(MicroInstruction(self.curins, parent))

    def visit(self, insn: MicroInstruction) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0


class MicroOperandVisitor(ida_hexrays.mop_visitor_t):
    """Visitor that delivers :class:`MicroOperand` wrappers.

    Override :meth:`visit` instead of ``visit_mop()``.
    """

    def visit_mop(self, op: Any, type_: Any, is_target: bool) -> int:
        mba = MicroBlockArray(self.mba)
        blk = MicroBlock(self.blk, mba)
        insn = MicroInstruction(self.curins, blk)
        return self.visit(MicroOperand(op, insn), type_, is_target)

    def visit(self, operand: MicroOperand, type_info: Any, is_target: bool) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0


# ---------------------------------------------------------------------------
# Optimizer & filter base classes
# ---------------------------------------------------------------------------


class MicroInstructionOptimizer(ida_hexrays.optinsn_t):
    """Per-instruction optimizer. Override :meth:`optimize`.

    Use :meth:`install` to register and :meth:`uninstall` to remove::

        class MyOpt(MicroInstructionOptimizer):
            def optimize(self, block, insn, optflags):
                ...
                return 1  # number of changes

        opt = MyOpt()
        opt.install()
    """

    def func(self, blk: Any, ins: Any, optflags: int = 0) -> int:
        mba = MicroBlockArray(blk.mba)
        mb = MicroBlock(blk, mba)
        mi = MicroInstruction(ins, mb)
        return self.optimize(mb, mi, optflags)

    def optimize(self, block: MicroBlock, insn: MicroInstruction, optflags: int) -> int:
        """Override this. Return number of changes made."""
        return 0

    def install(self) -> None:
        """Register this optimizer with the decompiler."""
        ida_hexrays.optinsn_t.install(self)

    def uninstall(self) -> None:
        """Unregister this optimizer from the decompiler."""
        ida_hexrays.optinsn_t.remove(self)


class MicroBlockOptimizer(ida_hexrays.optblock_t):
    """Per-block optimizer. Override :meth:`optimize`.

    Use :meth:`install` to register and :meth:`uninstall` to remove::

        class MyOpt(MicroBlockOptimizer):
            def optimize(self, block):
                ...
                return 1  # modified

        opt = MyOpt()
        opt.install()
    """

    def func(self, blk: Any) -> int:
        mba = MicroBlockArray(blk.mba)
        mb = MicroBlock(blk, mba)
        return self.optimize(mb)

    def optimize(self, block: MicroBlock) -> int:
        """Override this. Return 1 if modified, 0 otherwise."""
        return 0

    def install(self) -> None:
        """Register this optimizer with the decompiler."""
        ida_hexrays.optblock_t.install(self)

    def uninstall(self) -> None:
        """Unregister this optimizer from the decompiler."""
        ida_hexrays.optblock_t.remove(self)


class MicrocodeFilter(ida_hexrays.udc_filter_t):
    """User-defined call filter.

    Turns instruction patterns into function calls via a declared
    signature.
    """

    def install(self) -> None:
        """Install this filter."""
        ida_hexrays.udc_filter_t.install(self)

    def uninstall(self) -> None:
        """Uninstall this filter."""
        ida_hexrays.udc_filter_t.remove(self)


class MicrocodeLifter(ida_hexrays.microcode_filter_t):
    """Custom instruction lifter. Override ``match()`` and ``apply()``.

    Generates custom microcode for unsupported processor instructions
    (e.g., AVX, SIMD, custom ISA extensions).

    The ``cdg`` parameter in ``match()``/``apply()`` is a raw
    ``codegen_t`` providing:

    - ``cdg.insn`` — current ida instruction (``insn_t``)
    - ``cdg.emit(op, sz, l, r, d, off)`` — emit a micro-instruction
    - ``cdg.load_operand(n)`` — load operand *n* into a micro-register
    """

    def install(self) -> None:
        """Install this lifter."""
        ida_hexrays.install_microcode_filter(self, True)

    def uninstall(self) -> None:
        """Uninstall this lifter."""
        ida_hexrays.install_microcode_filter(self, False)


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _microcode_error_from(hf: Any, location: str) -> MicrocodeError:
    """Build a :class:`MicrocodeError` from a ``hexrays_failure_t``."""
    try:
        code = MicroError(hf.code)
        code_label = code.name
    except ValueError:
        code = None
        code_label = str(hf.code)
    errea = hf.errea if hf.errea != ida_idaapi.BADADDR else None
    parts = [f'Microcode generation failed for {location}']
    parts.append(f'{code_label}: {hf.str}' if hf.str else code_label)
    if errea is not None:
        parts.append(f'at 0x{errea:x}')
    return MicrocodeError(' — '.join(parts), code=code, errea=errea)


# ---------------------------------------------------------------------------
# Free functions
# ---------------------------------------------------------------------------


def reg2mreg(processor_reg: int) -> int:
    """Map a processor register number to a micro-register number.

    Args:
        processor_reg: Processor register number (e.g. from ``ida_idp``).

    Returns:
        Micro-register id, or ``mr_none`` if the register has no mapping.
    """
    return ida_hexrays.reg2mreg(processor_reg)


def mreg2reg(mreg: int, width: int) -> int:
    """Map a micro-register number to a processor register number.

    Args:
        mreg: Micro-register number.
        width: Size of the micro-register in bytes.

    Returns:
        Processor register id, or -1 if no mapping exists.
    """
    return ida_hexrays.mreg2reg(mreg, width)


def get_hexrays_version() -> str:
    """Get the Hex-Rays decompiler version string.

    Returns:
        Version in the form ``"major.minor.revision.build-date"``.
    """
    return ida_hexrays.get_hexrays_version()


# ---------------------------------------------------------------------------
# Microcode entry point — DatabaseEntity
# ---------------------------------------------------------------------------


@decorate_all_methods(check_db_open)
class Microcode(DatabaseEntity):
    """Provides structured access to IDA's Hex-Rays microcode.

    Access via ``db.microcode``.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def generate(
        self,
        func: func_t,
        maturity: MicroMaturity = MicroMaturity.GENERATED,
        flags: DecompilationFlags = DecompilationFlags.WARNINGS,
        build_graph: bool = True,
    ) -> MicroBlockArray:
        """Generate microcode for a function.

        Args:
            func: An IDA ``func_t`` object (e.g. from ``db.functions.get_at()``).
            maturity: The desired maturity level.
            flags: Decompilation flags (default: ``DecompilationFlags.WARNINGS``).
            build_graph: Whether to build the CFG graph after generation.

        Returns:
            A :class:`MicroBlockArray` wrapping the generated ``mba_t``.

        Raises:
            MicrocodeError: If microcode generation fails.
        """
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, ml, int(flags), int(maturity))

        if not mba:
            raise _microcode_error_from(hf, f'0x{func.start_ea:x}')

        if build_graph:
            mba.build_graph()

        return MicroBlockArray(mba)

    def generate_for_range(
        self,
        start_ea: int,
        end_ea: int,
        maturity: MicroMaturity = MicroMaturity.GENERATED,
        flags: DecompilationFlags = DecompilationFlags.WARNINGS,
        build_graph: bool = True,
    ) -> MicroBlockArray:
        """Generate microcode for an address range.

        Args:
            start_ea: Range start address.
            end_ea: Range end address.
            maturity: The desired maturity level.
            flags: Decompilation flags (default: ``DecompilationFlags.WARNINGS``).
            build_graph: Whether to build the CFG graph after generation.

        Returns:
            A :class:`MicroBlockArray` wrapping the generated ``mba_t``.

        Raises:
            MicrocodeError: If microcode generation fails.
        """
        mbr = ida_hexrays.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(start_ea, end_ea))
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, ml, int(flags), int(maturity))

        if not mba:
            raise _microcode_error_from(hf, f'range 0x{start_ea:x}:0x{end_ea:x}')

        if build_graph:
            mba.build_graph()

        return MicroBlockArray(mba)

    def from_decompilation(self, func: func_t) -> MicroBlockArray:
        """Get microcode from a full decompilation (maturity LVARS).

        Uses ``ida_hexrays.decompile()`` and returns the ``mba_t``
        from the resulting ``cfunc_t``.

        Args:
            func: An IDA ``func_t`` object.

        Returns:
            A :class:`MicroBlockArray` at LVARS maturity.

        Raises:
            MicrocodeError: If decompilation fails.
        """
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise MicrocodeError(f'Failed to decompile function at 0x{func.start_ea:x}')
        return MicroBlockArray(cfunc.mba, _owner=cfunc)

    def get_text(
        self,
        func: func_t,
        maturity: MicroMaturity = MicroMaturity.GENERATED,
        remove_tags: bool = True,
    ) -> List[str]:
        """Generate microcode and return it as text lines.

        This is a convenience method equivalent to::

            mf = db.microcode.generate(func, maturity)
            lines = mf.to_text(remove_tags)

        Args:
            func: An IDA ``func_t`` object.
            maturity: The desired maturity level.
            remove_tags: Whether to strip IDA color tags.

        Returns:
            A list of strings, each a line of microcode text.
        """
        mf = self.generate(func, maturity=maturity)
        return mf.to_text(remove_tags=remove_tags)
