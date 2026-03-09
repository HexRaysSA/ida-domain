from __future__ import annotations

import logging
from enum import IntEnum, IntFlag

import ida_hexrays
import ida_idaapi
import ida_lines
import ida_range
from ida_funcs import func_t
from ida_hexrays import mba_t, mblock_t, minsn_t, mlist_t, mop_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional, Tuple

from .base import DatabaseEntity, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from ida_idaapi import ea_t

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
        """True for commutative opcodes (``add``, ``mul``, ``or``, ``and``, ``xor``, ``setz``, ``setnz``, ``cfadd``, ``ofadd``)."""
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
        """True for unary opcodes (single source operand: ``neg``, ``lnot``, ``bnot``, ``fneg``)."""
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
        """True for integer arithmetic opcodes (``add``, ``sub``, ``mul``, ``udiv``, ``sdiv``, ``umod``, ``smod``)."""
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

    def __init__(self, raw: mop_t):
        self._raw = raw

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

    @property
    def sub_instruction(self) -> Optional[MicroInstruction]:
        """Nested :class:`MicroInstruction` for ``mop_d`` operands, or *None*."""
        if self._raw.t == self._T.SUB_INSN:
            return MicroInstruction(self._raw.d)
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
    def call_info(self) -> Any:
        """Raw ``mcallinfo_t`` for ``mop_f`` operands, or *None*."""
        if self._raw.t == self._T.CALL_INFO:
            return self._raw.f
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
            return MicroOperand(self._raw.a)
        return None

    @property
    def pair(self) -> Optional[Tuple[MicroOperand, MicroOperand]]:
        """(low, high) operand pair for ``mop_p`` operands, or *None*."""
        if self._raw.t == self._T.PAIR:
            return (
                MicroOperand(self._raw.pair.lop),
                MicroOperand(self._raw.pair.hop),
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

    def has_side_effects(self) -> bool:
        """True if evaluating this operand may cause side effects."""
        return self._raw.has_side_effects()

    def clear(self) -> None:
        """Reset this operand to empty (``mop_z``)."""
        self._raw.erase()

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
        return MicroOperand(self._raw.l)

    @l.setter
    def l(self, operand: MicroOperand) -> None:
        self._raw.l.swap(operand._raw)

    @property
    def r(self) -> MicroOperand:
        """Right operand."""
        return MicroOperand(self._raw.r)

    @r.setter
    def r(self, operand: MicroOperand) -> None:
        self._raw.r.swap(operand._raw)

    @property
    def d(self) -> MicroOperand:
        """Destination operand."""
        return MicroOperand(self._raw.d)

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
        return self._parent_block is not None

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

    def has_side_effects(self) -> bool:
        """True if this instruction (or any nested sub-instruction) may cause side effects."""
        return self._raw.has_side_effects()

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

    def for_all_insns(self, visitor: MicroInstructionVisitor) -> int:
        """Recursively visit all sub-instructions in this instruction tree.

        Args:
            visitor: A :class:`MicroInstructionVisitor` whose ``visit`` method
                will be called for each nested instruction.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_insns(visitor)

    def for_all_ops(self, visitor: MicroOperandVisitor) -> int:
        """Recursively visit all operands in this instruction tree.

        Args:
            visitor: A :class:`MicroOperandVisitor` whose ``visit`` method
                will be called for each operand.

        Returns:
            Non-zero if the visitor stopped early.
        """
        return self._raw.for_all_ops(visitor)

    # -- mutation ----------------------------------------------------------

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
        self.swap(new_insn)
        self.optimize_solo()
        if self._parent_block is not None:
            self._parent_block.mark_lists_dirty()
        else:
            raise RuntimeError(
                "Cannot mark lists dirty: parent block unknown. "
                "Use block.replace_instruction() or ensure the instruction "
                "was obtained from a block."
            )

    def set_ea(self, ea: int) -> None:
        """Change the effective address of this instruction."""
        self._raw.setaddr(ea)

    # -- text / display ----------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> str:
        """Get text representation of this instruction."""
        text = self._raw.dstr()
        if remove_tags:
            text = ida_lines.tag_remove(text)
        return text

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
    def npred(self) -> int:
        """Number of predecessor blocks."""
        return self._raw.npred()

    @property
    def nsucc(self) -> int:
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

    def find_first_use(
        self,
        locations: MicroLocationSet,
        start: MicroInstruction,
        end: Optional[MicroInstruction] = None,
    ) -> Optional[MicroInstruction]:
        """Find the first instruction after *start* that uses *locations*.

        Args:
            locations: The set of locations to search for.
            start: Start searching from this instruction.
            end: Stop searching at this instruction (exclusive). If *None*,
                searches to the end of the block.
        """
        end_raw = end._raw if end is not None else self._raw.tail
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
        end_raw = end._raw if end is not None else self._raw.tail
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
           a constant or non-variable, or the search is exhausted.

        Only register (``mop_r``), stack variable (``mop_S``), and local
        variable (``mop_l``) operands can be tracked.

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
            if block.npred != 1:
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
    def final_type(self) -> Any:
        """Return type of the function (raw ``tinfo_t``)."""
        return self._raw.final_type

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
        """Find a micro-operand by context, address, and location set."""
        result = self._raw.find_mop(ctx, ea, is_dest, locations._raw)
        if result:
            return MicroOperand(result)
        return None

    # -- mutation ----------------------------------------------------------

    def insert_block(self, index: int) -> MicroBlock:
        """Insert a new block at the given index."""
        blk = self._raw.insert_block(index)
        return MicroBlock(blk, self)

    def remove_block(self, block: MicroBlock) -> None:
        """Remove a block."""
        self._raw.remove_block(block._raw)

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
        """Create a call to a helper function."""
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

    def build_graph(self) -> None:
        """Build (or rebuild) the block-level control flow graph.

        Must be called after heavy structural modifications (block
        insertion/removal, edge changes) before the microcode can
        be further analyzed or verified.
        """
        self._raw.build_graph()

    # -- serialization -----------------------------------------------------

    def serialize(self) -> bytes:
        """Serialize the microcode to bytes."""
        return self._raw.serialize()

    @staticmethod
    def deserialize(data: bytes) -> MicroBlockArray:
        """Deserialize a microcode function from bytes."""
        raw = mba_t.deserialize(data)
        return MicroBlockArray(raw)

    # -- text / display ----------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> List[str]:
        """Get text representation of the microcode.

        Prints each non-sentinel block individually, stripping empty lines
        and whitespace.  Color tags are stripped by default.
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
        self, locations: MicroLocationSet, block: int, insn: MicroInstruction
    ) -> bool:
        """Check if locations are redefined globally from the given point."""
        return self._raw.is_redefined_globally(locations._raw, block, insn._raw)

    def is_used_globally(
        self, locations: MicroLocationSet, block: int, insn: MicroInstruction
    ) -> bool:
        """Check if locations are used globally from the given point."""
        return self._raw.is_used_globally(locations._raw, block, insn._raw)

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

    def subtract(self, other: MicroLocationSet) -> None:
        """Subtract *other* from this set in-place."""
        self._raw.sub(other._raw)

    def has_common(self, other: MicroLocationSet) -> bool:
        """True if this set has any locations in common with *other*."""
        return self._raw.has_common(other._raw)

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

    def __repr__(self) -> str:
        return f'MicroLocationSet(empty={self._raw.empty()})'


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
        parent = MicroBlock(self.blk) if is_top else None
        return self.visit(MicroInstruction(self.curins, parent))

    def visit(self, insn: MicroInstruction) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0


class MicroOperandVisitor(ida_hexrays.mop_visitor_t):
    """Visitor that delivers :class:`MicroOperand` wrappers.

    Override :meth:`visit` instead of ``visit_mop()``.
    """

    def visit_mop(self, op: Any, type_: Any, is_target: bool) -> int:
        return self.visit(MicroOperand(op), type_, is_target)

    def visit(self, operand: MicroOperand, type_info: Any, is_target: bool) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0


# ---------------------------------------------------------------------------
# Optimizer & filter base classes
# ---------------------------------------------------------------------------


class MicroInstructionOptimizer(ida_hexrays.optinsn_t):
    """Per-instruction optimizer. Override :meth:`optimize`."""

    def func(self, blk: Any, ins: Any, optflags: int = 0) -> int:
        mb = MicroBlock(blk)
        mi = MicroInstruction(ins, mb)
        return self.optimize(mb, mi, optflags)

    def optimize(self, block: MicroBlock, insn: MicroInstruction, optflags: int) -> int:
        """Override this. Return number of changes made."""
        return 0


class MicroBlockOptimizer(ida_hexrays.optblock_t):
    """Per-block optimizer. Override :meth:`optimize`."""

    def func(self, blk: Any) -> int:
        mb = MicroBlock(blk)
        return self.optimize(mb)

    def optimize(self, block: MicroBlock) -> int:
        """Override this. Return 1 if modified, 0 otherwise."""
        return 0


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
