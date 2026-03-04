from __future__ import annotations

import logging
import warnings
from enum import IntEnum

import ida_funcs
import ida_hexrays
import ida_lines
import ida_range
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
        self, message: str, code: Optional[MicroError] = None, errea: Optional[int] = None,
    ):
        self.code = code
        self.errea = errea
        super().__init__(message)


# ---------------------------------------------------------------------------
# MicroOperand — wraps mop_t
# ---------------------------------------------------------------------------

class MicroOperand:
    """Wrapper around an IDA ``mop_t`` microcode operand.

    Provides Pythonic access to operand type, value, and type-specific
    accessors.  The underlying raw object is always available via
    :pyattr:`raw_operand`.
    """

    _T = MicroOperandType  # shorthand for type checks

    def __init__(self, raw: mop_t, parent_insn: Optional[MicroInstruction] = None):
        self._raw = raw
        self._parent_insn = parent_insn

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
            v = self._raw.nnn.value
            bits = self._raw.size * 8
            if v >= (1 << (bits - 1)):
                v -= 1 << bits
            return v
        return None

    @property
    def unsigned_value(self) -> Optional[int]:
        """Unsigned interpretation of a number operand, or *None*."""
        if self._raw.t == self._T.NUMBER:
            return self._raw.nnn.value
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
        return self._raw.t == self._T.REGISTER

    @property
    def is_number(self) -> bool:
        return self._raw.t == self._T.NUMBER

    @property
    def is_stack_var(self) -> bool:
        return self._raw.t == self._T.STACK_VAR

    @property
    def is_global_address(self) -> bool:
        return self._raw.t == self._T.GLOBAL_ADDR

    @property
    def is_helper(self) -> bool:
        return self._raw.t == self._T.HELPER

    @property
    def is_string(self) -> bool:
        return self._raw.t == self._T.STRING

    @property
    def is_pair(self) -> bool:
        return self._raw.t == self._T.PAIR

    @property
    def is_zero(self) -> bool:
        """True if this is a number operand with value 0."""
        return self.value == 0

    @property
    def is_one(self) -> bool:
        """True if this is a number operand with value 1."""
        return self.value == 1

    # -- query methods -----------------------------------------------------

    def is_sub_instruction(self, opcode: Optional[MicroOpcode] = None) -> bool:
        """Check if this operand is a nested sub-instruction.

        Args:
            opcode: If given, also checks that the nested instruction has
                this specific opcode.
        """
        if self._raw.t != self._T.SUB_INSN:
            return False
        if opcode is not None:
            return self._raw.d.opcode == int(opcode)
        return True

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

    def __lt__(self, other: MicroOperand) -> bool:
        return self._raw < other._raw

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
    """

    def __init__(self, raw: minsn_t, parent_block: Optional[MicroBlock] = None):
        self._raw = raw
        self._parent_block = parent_block

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

    @property
    def r(self) -> MicroOperand:
        """Right operand."""
        return MicroOperand(self._raw.r, self)

    @property
    def d(self) -> MicroOperand:
        """Destination operand."""
        return MicroOperand(self._raw.d, self)

    @property
    def left(self) -> MicroOperand:
        """Left operand (alias for ``l``)."""
        return self.l

    @property
    def right(self) -> MicroOperand:
        """Right operand (alias for ``r``)."""
        return self.r

    @property
    def dest(self) -> MicroOperand:
        """Destination operand (alias for ``d``)."""
        return self.d

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
        return self.opcode in (MicroOpcode.CALL, MicroOpcode.ICALL)

    def is_mov(self) -> bool:
        """True if this is a ``m_mov`` instruction."""
        return self.opcode == MicroOpcode.MOV

    def find_call(self, with_helpers: bool = False) -> Optional[MicroInstruction]:
        """Find the first call in this instruction tree."""
        result = self._raw.find_call(with_helpers)
        if result:
            return MicroInstruction(result, self._parent_block)
        return None

    def find_opcode(self, mcode: MicroOpcode) -> Optional[MicroInstruction]:
        """Find the first sub-instruction with the given opcode."""
        result = self._raw.find_opcode(int(mcode))
        if result:
            return MicroInstruction(result, self._parent_block)
        return None

    # -- mutation ----------------------------------------------------------

    def swap(self, other: MicroInstruction) -> None:
        """Swap this instruction with another."""
        self._raw.swap(other._raw)

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

    def __lt__(self, other: MicroInstruction) -> bool:
        return self._raw < other._raw

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

    def __init__(
        self, raw: mblock_t, serial: int = 0, parent_mf: Optional[MicroBlockArray] = None
    ):
        self._raw = raw
        self._serial = serial
        self._parent_mf = parent_mf

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
        # Lazily wrap the raw mba_t from the block
        return MicroBlockArray(self._raw.mba)

    # -- query properties --------------------------------------------------

    @property
    def is_empty(self) -> bool:
        """True if this block has no instructions."""
        return self._raw.head is None

    @property
    def is_branch(self) -> bool:
        """True if this block ends with a conditional branch."""
        return self.block_type == MicroBlockType.TWO_WAY

    @property
    def is_call_block(self) -> bool:
        """True if this block contains a call instruction."""
        return any(insn.is_call() for insn in self)

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
            yield MicroBlock(mba_raw.get_mblock(serial), serial, self._parent_mf)

    def predecessors(self) -> Iterator[MicroBlock]:
        """Iterate over predecessor blocks."""
        mba_raw = self._raw.mba
        for j in range(self._raw.npred()):
            serial = self._raw.pred(j)
            yield MicroBlock(mba_raw.get_mblock(serial), serial, self._parent_mf)

    @property
    def successor_serials(self) -> List[int]:
        """List of successor block serial numbers."""
        return [self._raw.succ(j) for j in range(self._raw.nsucc())]

    @property
    def predecessor_serials(self) -> List[int]:
        """List of predecessor block serial numbers."""
        return [self._raw.pred(j) for j in range(self._raw.npred())]

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

    def __init__(self, raw: mba_t):
        self._raw = raw

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
        return MicroBlock(self._raw.get_mblock(0), 0, self)

    @property
    def natural_block_count(self) -> int:
        """Number of blocks excluding entry/exit sentinels."""
        return max(0, self._raw.qty - 2)

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
            yield MicroBlock(self._raw.get_mblock(i), i, self)

    def __getitem__(self, i: int) -> MicroBlock:
        """Get block by index."""
        if i < 0 or i >= self._raw.qty:
            raise IndexError(f'Block index {i} out of range (0..{self._raw.qty - 1})')
        return MicroBlock(self._raw.get_mblock(i), i, self)

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

    def get_graph(self) -> MicroGraph:
        """Get the wrapped :class:`MicroGraph`."""
        return MicroGraph(self._raw.get_graph())

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
        return MicroBlock(blk, index, self)

    def remove_block(self, block: MicroBlock) -> None:
        """Remove a block."""
        self._raw.remove_block(block._raw)

    def set_maturity(self, maturity: MicroMaturity) -> None:
        """Set the microcode maturity level."""
        self._raw.set_maturity(int(maturity))

    def create_helper_call(self, ea: int, helper_name: str) -> MicroInstruction:
        """Create a call to a helper function."""
        insn = self._raw.create_helper_call(ea, helper_name)
        return MicroInstruction(insn)

    # -- serialization -----------------------------------------------------

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

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    @property
    def raw_graph(self) -> Any:
        """Get the underlying ``mbl_graph_t`` object."""
        return self._raw

    def __len__(self) -> int:
        return self._raw.node_qty()

    def __getitem__(self, i: int) -> MicroBlock:
        return MicroBlock(self._raw.get_mblock(i), i)

    def __iter__(self) -> Iterator[MicroBlock]:
        for i in range(self._raw.node_qty()):
            yield MicroBlock(self._raw.get_mblock(i), i)

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
        if search_set & use_set:      # has_common
            results.append(insn.ea)
        search_set -= def_set          # subtract
    """

    def __init__(self, raw: mlist_t):
        self._raw = raw

    @property
    def raw_mlist(self) -> mlist_t:
        """Get the underlying ``mlist_t`` object."""
        return self._raw

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

    def __and__(self, other: MicroLocationSet) -> bool:
        """Intersection test (``has_common``)."""
        return self.has_common(other)

    def __ior__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Union in-place."""
        self.add(other)
        return self

    def __isub__(self, other: MicroLocationSet) -> MicroLocationSet:
        """Subtract in-place."""
        self.subtract(other)
        return self

    def __contains__(self, other: MicroLocationSet) -> bool:
        """True if this set includes all locations from *other*."""
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

    def __init__(self, parent_block: Optional[MicroBlock] = None):
        super().__init__()
        self._block = parent_block

    def visit_minsn(self) -> int:
        return self.visit(MicroInstruction(self.curins, self._block))

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
        mb = MicroBlock(blk, blk.serial)
        mi = MicroInstruction(ins, mb)
        return self.optimize(mb, mi, optflags)

    def optimize(self, block: MicroBlock, insn: MicroInstruction, optflags: int) -> int:
        """Override this. Return number of changes made."""
        return 0


class MicroBlockOptimizer(ida_hexrays.optblock_t):
    """Per-block optimizer. Override :meth:`optimize`."""

    def func(self, blk: Any) -> int:
        mb = MicroBlock(blk, blk.serial)
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
        ida_hexrays.install_microcode_filter(self, True)

    def uninstall(self) -> None:
        """Uninstall this filter."""
        ida_hexrays.install_microcode_filter(self, False)


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
# Module-level helpers
# ---------------------------------------------------------------------------

def reg_to_mreg(processor_reg: int) -> int:
    """Convert a processor register number to a micro-register number.

    Wraps ``ida_hexrays.reg2mreg()``.  Essential for instruction lifters.
    """
    return ida_hexrays.reg2mreg(processor_reg)


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
    errea = hf.errea if hf.errea else None
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
        func: Any,
        maturity: MicroMaturity = MicroMaturity.GENERATED,
        flags: int = ida_hexrays.DECOMP_WARNINGS,
        build_graph: bool = True,
    ) -> MicroBlockArray:
        """Generate microcode for a function.

        Args:
            func: An IDA ``func_t`` object (e.g. from ``db.functions.get_at()``).
            maturity: The desired maturity level.
            flags: Decompilation flags (default: ``DECOMP_WARNINGS``).
            build_graph: Whether to build the CFG graph after generation.

        Returns:
            A :class:`MicroBlockArray` wrapping the generated ``mba_t``.

        Raises:
            MicrocodeError: If microcode generation fails.
        """
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        ml = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, ml, flags, int(maturity))

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
        flags: int = ida_hexrays.DECOMP_WARNINGS,
        build_graph: bool = True,
    ) -> MicroBlockArray:
        """Generate microcode for an address range.

        Args:
            start_ea: Range start address.
            end_ea: Range end address.
            maturity: The desired maturity level.
            flags: Decompilation flags.
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
        mba = ida_hexrays.gen_microcode(mbr, hf, ml, flags, int(maturity))

        if not mba:
            raise _microcode_error_from(hf, f'range 0x{start_ea:x}:0x{end_ea:x}')

        if build_graph:
            mba.build_graph()

        return MicroBlockArray(mba)

    def from_decompilation(self, func: Any) -> MicroBlockArray:
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
        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            raise MicrocodeError(
                f'Failed to decompile function at 0x{func.start_ea:x}'
            )
        return MicroBlockArray(cfunc.mba)

    def get_text(
        self,
        func: Any,
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
