from __future__ import annotations

import logging
from enum import IntEnum, IntFlag

import ida_hexrays
import ida_idaapi
import ida_lines
import ida_name
from ida_funcs import func_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional, Union

from .base import (
    DatabaseEntity,
    DecompilerError,
    check_db_open,
    decorate_all_methods,
)
from .microcode import (
    DecompilationFlags,
    MicroBlockArray,
    MicroLocalVar,
    MicroLocalVars,
)

if TYPE_CHECKING:
    from ida_hexrays import fnumber_t, var_ref_t
    from ida_idaapi import ea_t
    from ida_typeinf import tinfo_t

    from .database import Database

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PseudocodeExpressionOp(IntEnum):
    """Expression operator types corresponding to ``cot_*`` constants."""

    # Empty
    EMPTY = ida_hexrays.cot_empty       # 0

    # Assignment operators
    COMMA = ida_hexrays.cot_comma       # 1  x, y
    ASG = ida_hexrays.cot_asg           # 2  x = y
    ASG_BOR = ida_hexrays.cot_asgbor    # 3  x |= y
    ASG_XOR = ida_hexrays.cot_asgxor    # 4  x ^= y
    ASG_BAND = ida_hexrays.cot_asgband  # 5  x &= y
    ASG_ADD = ida_hexrays.cot_asgadd    # 6  x += y
    ASG_SUB = ida_hexrays.cot_asgsub    # 7  x -= y
    ASG_MUL = ida_hexrays.cot_asgmul    # 8  x *= y
    ASG_SSHR = ida_hexrays.cot_asgsshr  # 9  x >>= y signed
    ASG_USHR = ida_hexrays.cot_asgushr  # 10 x >>= y unsigned
    ASG_SHL = ida_hexrays.cot_asgshl    # 11 x <<= y
    ASG_SDIV = ida_hexrays.cot_asgsdiv  # 12 x /= y signed
    ASG_UDIV = ida_hexrays.cot_asgudiv  # 13 x /= y unsigned
    ASG_SMOD = ida_hexrays.cot_asgsmod  # 14 x %= y signed
    ASG_UMOD = ida_hexrays.cot_asgumod  # 15 x %= y unsigned

    # Ternary / logical
    TERNARY = ida_hexrays.cot_tern      # 16 x ? y : z
    LOR = ida_hexrays.cot_lor           # 17 x || y
    LAND = ida_hexrays.cot_land         # 18 x && y

    # Bitwise
    BOR = ida_hexrays.cot_bor           # 19 x | y
    XOR = ida_hexrays.cot_xor           # 20 x ^ y
    BAND = ida_hexrays.cot_band         # 21 x & y

    # Comparison
    EQ = ida_hexrays.cot_eq             # 22 x == y
    NE = ida_hexrays.cot_ne             # 23 x != y
    SGE = ida_hexrays.cot_sge           # 24 x >= y signed
    UGE = ida_hexrays.cot_uge           # 25 x >= y unsigned
    SLE = ida_hexrays.cot_sle           # 26 x <= y signed
    ULE = ida_hexrays.cot_ule           # 27 x <= y unsigned
    SGT = ida_hexrays.cot_sgt           # 28 x > y signed
    UGT = ida_hexrays.cot_ugt          # 29 x > y unsigned
    SLT = ida_hexrays.cot_slt           # 30 x < y signed
    ULT = ida_hexrays.cot_ult           # 31 x < y unsigned

    # Shift
    SSHR = ida_hexrays.cot_sshr         # 32 x >> y signed
    USHR = ida_hexrays.cot_ushr         # 33 x >> y unsigned
    SHL = ida_hexrays.cot_shl           # 34 x << y

    # Arithmetic
    ADD = ida_hexrays.cot_add           # 35 x + y
    SUB = ida_hexrays.cot_sub           # 36 x - y
    MUL = ida_hexrays.cot_mul           # 37 x * y
    SDIV = ida_hexrays.cot_sdiv         # 38 x / y signed
    UDIV = ida_hexrays.cot_udiv         # 39 x / y unsigned
    SMOD = ida_hexrays.cot_smod         # 40 x % y signed
    UMOD = ida_hexrays.cot_umod         # 41 x % y unsigned

    # Floating-point arithmetic
    FADD = ida_hexrays.cot_fadd         # 42 x + y fp
    FSUB = ida_hexrays.cot_fsub         # 43 x - y fp
    FMUL = ida_hexrays.cot_fmul         # 44 x * y fp
    FDIV = ida_hexrays.cot_fdiv         # 45 x / y fp

    # Unary
    FNEG = ida_hexrays.cot_fneg         # 46 -x fp
    NEG = ida_hexrays.cot_neg           # 47 -x
    CAST = ida_hexrays.cot_cast         # 48 (type)x
    LNOT = ida_hexrays.cot_lnot        # 49 !x
    BNOT = ida_hexrays.cot_bnot         # 50 ~x
    PTR = ida_hexrays.cot_ptr           # 51 *x
    REF = ida_hexrays.cot_ref           # 52 &x
    POSTINC = ida_hexrays.cot_postinc   # 53 x++
    POSTDEC = ida_hexrays.cot_postdec   # 54 x--
    PREINC = ida_hexrays.cot_preinc     # 55 ++x
    PREDEC = ida_hexrays.cot_predec     # 56 --x

    # Access
    CALL = ida_hexrays.cot_call         # 57 x(...)
    IDX = ida_hexrays.cot_idx           # 58 x[y]
    MEMREF = ida_hexrays.cot_memref     # 59 x.m
    MEMPTR = ida_hexrays.cot_memptr     # 60 x->m

    # Leaf / literal
    NUM = ida_hexrays.cot_num           # 61 number
    FNUM = ida_hexrays.cot_fnum         # 62 fp number
    STR = ida_hexrays.cot_str           # 63 string constant
    OBJ = ida_hexrays.cot_obj           # 64 obj_ea
    VAR = ida_hexrays.cot_var           # 65 local variable
    INSN = ida_hexrays.cot_insn         # 66 embedded insn (internal)
    SIZEOF = ida_hexrays.cot_sizeof     # 67 sizeof(x)
    HELPER = ida_hexrays.cot_helper     # 68 helper name
    TYPE = ida_hexrays.cot_type         # 69 arbitrary type

    # -- category queries --------------------------------------------------

    @property
    def is_assignment(self) -> bool:
        """True for all assignment operators (``=``, ``+=``, ``-=``, etc.)."""
        return ida_hexrays.is_assignment(self.value)

    @property
    def is_relational(self) -> bool:
        """True for comparison operators (``==``, ``!=``, ``<``, ``>``, etc.)."""
        return ida_hexrays.is_relational(self.value)

    @property
    def is_unary(self) -> bool:
        """True for unary operators (``-x``, ``!x``, ``~x``, ``*x``, ``&x``, casts, etc.)."""
        return (
            ida_hexrays.op_uses_x(self.value)
            and not ida_hexrays.op_uses_y(self.value)
        )

    @property
    def is_binary(self) -> bool:
        """True for binary operators (``x+y``, ``x-y``, etc.). Excludes ternary."""
        return ida_hexrays.is_binary(self.value)

    @property
    def is_leaf(self) -> bool:
        """True for leaf nodes (``num``, ``fnum``, ``str``, ``obj``, ``var``, ``helper``, ``type``)."""
        return self.value >= ida_hexrays.cot_num and self.value <= ida_hexrays.cot_type

    @property
    def is_call(self) -> bool:
        """True for call expressions."""
        return self.value == ida_hexrays.cot_call

    @property
    def is_prepost(self) -> bool:
        """True for pre/post increment/decrement operators."""
        return ida_hexrays.is_prepost(self.value)

    @property
    def is_arithmetic(self) -> bool:
        """True for integer arithmetic operators (``+``, ``-``, ``*``, ``/``, ``%``)."""
        return self.value in (
            ida_hexrays.cot_add, ida_hexrays.cot_sub, ida_hexrays.cot_mul,
            ida_hexrays.cot_sdiv, ida_hexrays.cot_udiv,
            ida_hexrays.cot_smod, ida_hexrays.cot_umod,
        )

    @property
    def is_floating_point(self) -> bool:
        """True for floating-point arithmetic operators."""
        return self.value in (
            ida_hexrays.cot_fadd, ida_hexrays.cot_fsub,
            ida_hexrays.cot_fmul, ida_hexrays.cot_fdiv,
            ida_hexrays.cot_fneg,
        )


class PseudocodeInstructionOp(IntEnum):
    """Statement/instruction operator types corresponding to ``cit_*`` constants."""

    EMPTY = ida_hexrays.cit_empty       # 70
    BLOCK = ida_hexrays.cit_block       # 71
    EXPR = ida_hexrays.cit_expr         # 72
    IF = ida_hexrays.cit_if             # 73
    FOR = ida_hexrays.cit_for           # 74
    WHILE = ida_hexrays.cit_while       # 75
    DO = ida_hexrays.cit_do             # 76
    SWITCH = ida_hexrays.cit_switch     # 77
    BREAK = ida_hexrays.cit_break       # 78
    CONTINUE = ida_hexrays.cit_continue # 79
    RETURN = ida_hexrays.cit_return     # 80
    GOTO = ida_hexrays.cit_goto         # 81
    ASM = ida_hexrays.cit_asm           # 82
    TRY = ida_hexrays.cit_try           # 83
    THROW = ida_hexrays.cit_throw       # 84

    # -- category queries --------------------------------------------------

    @property
    def is_loop(self) -> bool:
        """True for loop instructions (``for``, ``while``, ``do``)."""
        return self.value in (
            ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do,
        )

    @property
    def is_control_flow(self) -> bool:
        """True for control-flow instructions (``break``, ``continue``, ``return``, ``goto``)."""
        return self.value in (
            ida_hexrays.cit_break, ida_hexrays.cit_continue,
            ida_hexrays.cit_return, ida_hexrays.cit_goto,
        )


class PseudocodeMaturity(IntEnum):
    """CTree maturity levels corresponding to ``CMAT_*`` constants."""

    ZERO = ida_hexrays.CMAT_ZERO
    BUILT = ida_hexrays.CMAT_BUILT
    TRANS1 = ida_hexrays.CMAT_TRANS1
    NICE = ida_hexrays.CMAT_NICE
    TRANS2 = ida_hexrays.CMAT_TRANS2
    CPA = ida_hexrays.CMAT_CPA
    TRANS3 = ida_hexrays.CMAT_TRANS3
    CASTED = ida_hexrays.CMAT_CASTED
    FINAL = ida_hexrays.CMAT_FINAL


class PseudocodeVisitorFlags(IntFlag):
    """CTree visitor flags corresponding to ``CV_*`` constants."""

    FAST = ida_hexrays.CV_FAST
    PRUNE = ida_hexrays.CV_PRUNE
    PARENTS = ida_hexrays.CV_PARENTS
    POST = ida_hexrays.CV_POST
    RESTART = ida_hexrays.CV_RESTART
    INSNS = ida_hexrays.CV_INSNS


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class PseudocodeError(DecompilerError):
    """Raised when pseudocode/ctree operations fail.

    Attributes:
        errea: The address where the error occurred (``None`` if unavailable).
    """

    def __init__(self, message: str, errea: Optional[int] = None):
        self.errea = errea
        super().__init__(message)


# ---------------------------------------------------------------------------
# PseudocodeNumber — wraps cnumber_t
# ---------------------------------------------------------------------------


class PseudocodeNumber:
    """Wrapper around an IDA ``cnumber_t`` numeric constant.

    Supports the full numeric protocol, so instances can be compared
    and used in arithmetic directly::

        if expr.number == 0: ...
        if expr.number > 10: ...
        x = expr.number + 1
    """

    def __init__(
        self, raw: ida_hexrays.cnumber_t,
        _parent_expr: Optional[PseudocodeExpression] = None,
    ):
        self._raw = raw
        self._parent_expr = _parent_expr

    @property
    def raw_number(self) -> ida_hexrays.cnumber_t:
        """Get the underlying ``cnumber_t`` object."""
        return self._raw

    @property
    def value(self) -> int:
        """Raw 64-bit unsigned value."""
        return self._raw._value

    def typed_value(self, type_info: tinfo_t) -> int:
        """Value with sign extension based on *type_info*."""
        return self._raw.value(type_info)

    @property
    def number_format(self) -> Any:
        """Number format (``number_format_t``) for display customization."""
        return self._raw.nf

    # -- numeric protocol --------------------------------------------------

    def __int__(self) -> int:
        return self._raw._value

    def __float__(self) -> float:
        return float(self._raw._value)

    def __index__(self) -> int:
        return self._raw._value

    def __bool__(self) -> bool:
        return self._raw._value != 0

    def __hash__(self) -> int:
        return hash(self._raw._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PseudocodeNumber):
            return self._raw._value == other._raw._value
        if isinstance(other, (int, float)):
            return self._raw._value == other
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, PseudocodeNumber):
            return self._raw._value < other._raw._value
        if isinstance(other, (int, float)):
            return self._raw._value < other
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, PseudocodeNumber):
            return self._raw._value <= other._raw._value
        if isinstance(other, (int, float)):
            return self._raw._value <= other
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, PseudocodeNumber):
            return self._raw._value > other._raw._value
        if isinstance(other, (int, float)):
            return self._raw._value > other
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, PseudocodeNumber):
            return self._raw._value >= other._raw._value
        if isinstance(other, (int, float)):
            return self._raw._value >= other
        return NotImplemented

    def __add__(self, other: object) -> int:
        if isinstance(other, (int, PseudocodeNumber)):
            return self._raw._value + int(other)
        return NotImplemented

    def __radd__(self, other: object) -> int:
        if isinstance(other, int):
            return other + self._raw._value
        return NotImplemented

    def __sub__(self, other: object) -> int:
        if isinstance(other, (int, PseudocodeNumber)):
            return self._raw._value - int(other)
        return NotImplemented

    def __rsub__(self, other: object) -> int:
        if isinstance(other, int):
            return other - self._raw._value
        return NotImplemented

    # -- display -----------------------------------------------------------

    def __str__(self) -> str:
        return str(self._raw._value)

    def __repr__(self) -> str:
        return f'PseudocodeNumber(value={self._raw._value})'


# ---------------------------------------------------------------------------
# PseudocodeCallArg / PseudocodeCallArgList — wraps carg_t / carglist_t
# ---------------------------------------------------------------------------


class PseudocodeCallArg:
    """Wrapper around an IDA ``carg_t`` call argument.

    ``carg_t`` extends ``cexpr_t``, so each argument is also an expression.
    """

    def __init__(
        self, raw: ida_hexrays.carg_t,
        _parent_list: Optional[PseudocodeCallArgList] = None,
    ):
        self._raw = raw
        self._parent_list = _parent_list

    @property
    def raw_arg(self) -> ida_hexrays.carg_t:
        """Get the underlying ``carg_t`` object."""
        return self._raw

    @property
    def is_vararg(self) -> bool:
        """True if this is a variadic argument."""
        return self._raw.is_vararg

    @property
    def formal_type(self) -> tinfo_t:
        """Formal argument type from the function prototype."""
        return self._raw.formal_type

    @property
    def expression(self) -> PseudocodeExpression:
        """The argument value as a :class:`PseudocodeExpression`.

        ``carg_t`` inherits from ``cexpr_t``, so the argument itself
        is an expression.
        """
        return PseudocodeExpression(self._raw)

    def __str__(self) -> str:
        return self.expression.to_text()

    def __repr__(self) -> str:
        return f'PseudocodeCallArg(op={self._raw.op!r})'


class PseudocodeCallArgList:
    """Wrapper around an IDA ``carglist_t`` argument list.

    Supports iteration, indexing, and ``len()``.
    """

    def __init__(self, raw: ida_hexrays.carglist_t):
        self._raw = raw

    @property
    def raw_arglist(self) -> ida_hexrays.carglist_t:
        """Get the underlying ``carglist_t`` object."""
        return self._raw

    @property
    def func_type(self) -> tinfo_t:
        """Function type information for the call."""
        return self._raw.functype

    @property
    def flags(self) -> int:
        """Argument list flags."""
        return self._raw.flags

    def __len__(self) -> int:
        return len(self._raw)

    def __getitem__(self, i: int) -> PseudocodeCallArg:
        if i < 0:
            i += len(self._raw)
        if i < 0 or i >= len(self._raw):
            raise IndexError(
                f'Argument index out of range (0..{len(self._raw) - 1})'
            )
        return PseudocodeCallArg(self._raw[i], self)

    def __iter__(self) -> Iterator[PseudocodeCallArg]:
        for i in range(len(self._raw)):
            yield PseudocodeCallArg(self._raw[i], self)

    def __repr__(self) -> str:
        return f'PseudocodeCallArgList(count={len(self._raw)})'


# ---------------------------------------------------------------------------
# PseudocodeExpression — wraps cexpr_t
# ---------------------------------------------------------------------------


class PseudocodeExpression:
    """Wrapper around an IDA ``cexpr_t`` expression node.

    Provides Pythonic access to expression type, operands, and sub-fields.
    Type-specific properties return ``None`` when the expression type
    does not match, avoiding undefined behavior from wrong union access.
    """

    def __init__(
        self, raw: ida_hexrays.cexpr_t,
        _parent: Optional[Any] = None,
    ):
        self._raw = raw
        self._parent = _parent

    # -- raw access --------------------------------------------------------

    @property
    def raw_expr(self) -> ida_hexrays.cexpr_t:
        """Get the underlying ``cexpr_t`` object."""
        return self._raw

    # -- basic properties (from citem_t) -----------------------------------

    @property
    def ea(self) -> ea_t:
        """Effective address of this expression."""
        return self._raw.ea

    @property
    def op(self) -> PseudocodeExpressionOp:
        """Expression operator type."""
        return PseudocodeExpressionOp(self._raw.op)

    @property
    def label_num(self) -> int:
        """Label number (``-1`` if none)."""
        return self._raw.label_num

    @property
    def index(self) -> int:
        """Item index in the ctree arrays."""
        return self._raw.index

    @property
    def type_info(self) -> tinfo_t:
        """Expression type information (``tinfo_t``)."""
        return self._raw.type

    @property
    def exflags(self) -> int:
        """Expression flags (``EXFL_*``)."""
        return self._raw.exflags

    # -- sub-expression access (binary/unary: x, y, z) --------------------

    _Op = PseudocodeExpressionOp  # shorthand for internal checks

    @property
    def x(self) -> Optional[PseudocodeExpression]:
        """First operand (left), or ``None`` if the operator does not use x."""
        if ida_hexrays.op_uses_x(self._raw.op):
            return PseudocodeExpression(self._raw.x, self)
        return None

    @property
    def y(self) -> Optional[PseudocodeExpression]:
        """Second operand (right), or ``None`` if the operator does not use y."""
        if ida_hexrays.op_uses_y(self._raw.op):
            return PseudocodeExpression(self._raw.y, self)
        return None

    @property
    def z(self) -> Optional[PseudocodeExpression]:
        """Third operand (ternary ``z``), or ``None`` if not ternary."""
        if self._raw.op == self._Op.TERNARY:
            return PseudocodeExpression(self._raw.z, self)
        return None

    # -- type-specific accessors -------------------------------------------

    @property
    def number(self) -> Optional[PseudocodeNumber]:
        """For ``cot_num``: the numeric constant. ``None`` otherwise."""
        if self._raw.op == self._Op.NUM:
            return PseudocodeNumber(self._raw.n, self)
        return None

    @property
    def fp_number(self) -> Optional[fnumber_t]:
        """For ``cot_fnum``: floating-point constant (``fnumber_t``). ``None`` otherwise."""
        if self._raw.op == self._Op.FNUM:
            return self._raw.fpc
        return None

    @property
    def variable(self) -> Optional[var_ref_t]:
        """For ``cot_var``: the variable reference (``var_ref_t``). ``None`` otherwise."""
        if self._raw.op == self._Op.VAR:
            return self._raw.v
        return None

    @property
    def variable_index(self) -> Optional[int]:
        """For ``cot_var``: index into the local variable list. ``None`` otherwise."""
        if self._raw.op == self._Op.VAR:
            return self._raw.v.idx
        return None

    @property
    def obj_ea(self) -> Optional[ea_t]:
        """For ``cot_obj``: the object effective address. ``None`` otherwise."""
        if self._raw.op == self._Op.OBJ:
            return self._raw.obj_ea
        return None

    @property
    def obj_name(self) -> Optional[str]:
        """For ``cot_obj``: the object name (resolved via IDA names). ``None`` otherwise."""
        if self._raw.op == self._Op.OBJ:
            return ida_name.get_name(self._raw.obj_ea)
        return None

    @property
    def string(self) -> Optional[str]:
        """For ``cot_str``: the string constant value. ``None`` otherwise."""
        if self._raw.op == self._Op.STR:
            return self._raw.string
        return None

    @property
    def helper_name(self) -> Optional[str]:
        """For ``cot_helper``: the helper function name. ``None`` otherwise."""
        if self._raw.op == self._Op.HELPER:
            return self._raw.helper
        return None

    @property
    def call_args(self) -> Optional[PseudocodeCallArgList]:
        """For ``cot_call``: the argument list. ``None`` otherwise."""
        if self._raw.op == self._Op.CALL:
            return PseudocodeCallArgList(self._raw.a)
        return None

    @property
    def member_offset(self) -> Optional[int]:
        """For ``cot_memref`` / ``cot_memptr``: the member offset. ``None`` otherwise."""
        if self._raw.op in (self._Op.MEMREF, self._Op.MEMPTR):
            return self._raw.m
        return None

    @property
    def ptr_size(self) -> Optional[int]:
        """For ``cot_ptr`` / ``cot_memptr``: the access size. ``None`` otherwise."""
        if self._raw.op in (self._Op.PTR, self._Op.MEMPTR):
            return self._raw.ptrsize
        return None

    # -- type-check shortcuts ----------------------------------------------

    @property
    def is_call(self) -> bool:
        """True if this is a call expression."""
        return self._raw.op == self._Op.CALL

    @property
    def is_assignment(self) -> bool:
        """True if this is any assignment expression."""
        return self.op.is_assignment

    @property
    def is_number(self) -> bool:
        """True if this is a numeric constant."""
        return self._raw.op == self._Op.NUM

    @property
    def is_variable(self) -> bool:
        """True if this is a local variable reference."""
        return self._raw.op == self._Op.VAR

    @property
    def is_string(self) -> bool:
        """True if this is a string constant."""
        return self._raw.op == self._Op.STR

    @property
    def is_object(self) -> bool:
        """True if this is an object address reference."""
        return self._raw.op == self._Op.OBJ

    # -- query methods -----------------------------------------------------

    def contains_operator(self, op: PseudocodeExpressionOp, times: int = 1) -> bool:
        """Check if this expression contains the given operator at least *times* times."""
        return self._raw.contains_operator(int(op), times)

    def contains_comma(self, times: int = 1) -> bool:
        """Check if this expression contains comma operators."""
        return self._raw.contains_comma(times)

    def is_nice_cond(self) -> bool:
        """Check if this expression is a \"nice\" condition (no side effects)."""
        return self._raw.is_nice_cond()

    def equal_effect(self, other: PseudocodeExpression) -> bool:
        """Check if this expression has the same effect as *other*."""
        return self._raw.equal_effect(other._raw)

    # -- text / display ----------------------------------------------------

    def to_text(self) -> str:
        """Get the expression as a text string."""
        return self._raw.dstr()

    def __str__(self) -> str:
        return self.to_text()

    def __repr__(self) -> str:
        try:
            opname = PseudocodeExpressionOp(self._raw.op).name
        except ValueError:
            opname = str(self._raw.op)
        return f'PseudocodeExpression(op={opname}, ea=0x{self._raw.ea:x})'


# ---------------------------------------------------------------------------
# PseudocodeInstruction — wraps cinsn_t
# ---------------------------------------------------------------------------


class PseudocodeInstruction:
    """Wrapper around an IDA ``cinsn_t`` instruction/statement node.

    Type-specific detail properties return ``None`` when the instruction
    type does not match.
    """

    def __init__(
        self, raw: ida_hexrays.cinsn_t,
        _parent: Optional[Any] = None,
    ):
        self._raw = raw
        self._parent = _parent

    # -- raw access --------------------------------------------------------

    @property
    def raw_insn(self) -> ida_hexrays.cinsn_t:
        """Get the underlying ``cinsn_t`` object."""
        return self._raw

    # -- basic properties (from citem_t) -----------------------------------

    @property
    def ea(self) -> ea_t:
        """Effective address of this instruction."""
        return self._raw.ea

    @property
    def op(self) -> PseudocodeInstructionOp:
        """Instruction operator type."""
        return PseudocodeInstructionOp(self._raw.op)

    @property
    def label_num(self) -> int:
        """Label number (``-1`` if none)."""
        return self._raw.label_num

    @property
    def index(self) -> int:
        """Item index in the ctree arrays."""
        return self._raw.index

    # -- type-specific detail accessors ------------------------------------

    _Op = PseudocodeInstructionOp  # shorthand for internal checks

    @property
    def block(self) -> Optional[PseudocodeBlock]:
        """For ``cit_block``: the statement block. ``None`` otherwise."""
        if self._raw.op == self._Op.BLOCK:
            return PseudocodeBlock(self._raw.cblock, self)
        return None

    @property
    def expression(self) -> Optional[PseudocodeExpression]:
        """For ``cit_expr``: the contained expression. ``None`` otherwise."""
        if self._raw.op == self._Op.EXPR:
            return PseudocodeExpression(self._raw.cexpr, self)
        return None

    @property
    def if_details(self) -> Optional[PseudocodeIf]:
        """For ``cit_if``: the if-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.IF:
            return PseudocodeIf(self._raw.cif, self)
        return None

    @property
    def for_details(self) -> Optional[PseudocodeFor]:
        """For ``cit_for``: the for-loop details. ``None`` otherwise."""
        if self._raw.op == self._Op.FOR:
            return PseudocodeFor(self._raw.cfor, self)
        return None

    @property
    def while_details(self) -> Optional[PseudocodeWhile]:
        """For ``cit_while``: the while-loop details. ``None`` otherwise."""
        if self._raw.op == self._Op.WHILE:
            return PseudocodeWhile(self._raw.cwhile, self)
        return None

    @property
    def do_details(self) -> Optional[PseudocodeDo]:
        """For ``cit_do``: the do-while details. ``None`` otherwise."""
        if self._raw.op == self._Op.DO:
            return PseudocodeDo(self._raw.cdo, self)
        return None

    @property
    def switch_details(self) -> Optional[PseudocodeSwitch]:
        """For ``cit_switch``: the switch-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.SWITCH:
            return PseudocodeSwitch(self._raw.cswitch, self)
        return None

    @property
    def return_details(self) -> Optional[PseudocodeReturn]:
        """For ``cit_return``: the return-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.RETURN:
            return PseudocodeReturn(self._raw.creturn, self)
        return None

    @property
    def goto_details(self) -> Optional[PseudocodeGoto]:
        """For ``cit_goto``: the goto-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.GOTO:
            return PseudocodeGoto(self._raw.cgoto, self)
        return None

    @property
    def try_details(self) -> Optional[PseudocodeTry]:
        """For ``cit_try``: the try-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.TRY:
            return PseudocodeTry(self._raw.ctry, self)
        return None

    @property
    def throw_details(self) -> Optional[PseudocodeThrow]:
        """For ``cit_throw``: the throw-instruction details. ``None`` otherwise."""
        if self._raw.op == self._Op.THROW:
            return PseudocodeThrow(self._raw.cthrow, self)
        return None

    # -- type-check shortcuts ----------------------------------------------

    @property
    def is_block(self) -> bool:
        """True if this is a block instruction."""
        return self._raw.op == self._Op.BLOCK

    @property
    def is_if(self) -> bool:
        """True if this is an if-instruction."""
        return self._raw.op == self._Op.IF

    @property
    def is_loop(self) -> bool:
        """True if this is a loop instruction (``for``, ``while``, ``do``)."""
        return self.op.is_loop

    @property
    def is_return(self) -> bool:
        """True if this is a return instruction."""
        return self._raw.op == self._Op.RETURN

    @property
    def is_goto(self) -> bool:
        """True if this is a goto instruction."""
        return self._raw.op == self._Op.GOTO

    @property
    def is_switch(self) -> bool:
        """True if this is a switch instruction."""
        return self._raw.op == self._Op.SWITCH

    # -- query methods -----------------------------------------------------

    def is_ordinary_flow(self) -> bool:
        """True if this instruction has ordinary control flow (no jumps/breaks)."""
        return self._raw.is_ordinary_flow()

    def contains_insn(self, op: PseudocodeInstructionOp, times: int = 1) -> bool:
        """Check if this instruction contains the given instruction type."""
        return self._raw.contains_insn(int(op), times)

    # -- tree traversal ----------------------------------------------------

    def walk_expressions(self) -> Iterator[PseudocodeExpression]:
        """Iterate over all expressions in the subtree rooted at this instruction.

        Collects all items first, so it is safe to inspect during iteration
        but do not modify the tree without refreshing afterward.
        """

        class _Collector(ida_hexrays.ctree_visitor_t):
            def __init__(self) -> None:
                super().__init__(ida_hexrays.CV_FAST)
                self.items: List[PseudocodeExpression] = []

            def visit_expr(self, expr: Any) -> int:
                self.items.append(PseudocodeExpression(expr))
                return 0

        collector = _Collector()
        collector.apply_to(self._raw, None)
        yield from collector.items

    def walk_instructions(self) -> Iterator[PseudocodeInstruction]:
        """Iterate over all instructions in the subtree rooted at this instruction."""

        class _Collector(ida_hexrays.ctree_visitor_t):
            def __init__(self) -> None:
                super().__init__(ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
                self.items: List[PseudocodeInstruction] = []

            def visit_insn(self, insn: Any) -> int:
                self.items.append(PseudocodeInstruction(insn))
                return 0

        collector = _Collector()
        collector.apply_to(self._raw, None)
        yield from collector.items

    def walk_all(self) -> Iterator[Union[PseudocodeExpression, PseudocodeInstruction]]:
        """Iterate over all ctree items (expressions and instructions)
        in the subtree rooted at this instruction."""

        class _Collector(ida_hexrays.ctree_visitor_t):
            def __init__(self) -> None:
                super().__init__(ida_hexrays.CV_FAST)
                self.items: List[Union[PseudocodeExpression, PseudocodeInstruction]] = []

            def visit_expr(self, expr: Any) -> int:
                self.items.append(PseudocodeExpression(expr))
                return 0

            def visit_insn(self, insn: Any) -> int:
                self.items.append(PseudocodeInstruction(insn))
                return 0

        collector = _Collector()
        collector.apply_to(self._raw, None)
        yield from collector.items

    # -- text / display ----------------------------------------------------

    def __str__(self) -> str:
        try:
            opname = PseudocodeInstructionOp(self._raw.op).name
        except ValueError:
            opname = str(self._raw.op)
        return f'{opname} @ 0x{self._raw.ea:x}'

    def __repr__(self) -> str:
        try:
            opname = PseudocodeInstructionOp(self._raw.op).name
        except ValueError:
            opname = str(self._raw.op)
        return f'PseudocodeInstruction(op={opname}, ea=0x{self._raw.ea:x})'


# ---------------------------------------------------------------------------
# PseudocodeBlock — wraps cblock_t
# ---------------------------------------------------------------------------


class PseudocodeBlock:
    """Wrapper around an IDA ``cblock_t`` statement block.

    Supports iteration, indexing, and ``len()``.
    """

    def __init__(
        self, raw: ida_hexrays.cblock_t,
        _parent: Optional[Any] = None,
    ):
        self._raw = raw
        self._parent = _parent

    @property
    def raw_block(self) -> ida_hexrays.cblock_t:
        """Get the underlying ``cblock_t`` object."""
        return self._raw

    def __len__(self) -> int:
        return sum(1 for _ in self._raw)

    def __getitem__(self, i: int) -> PseudocodeInstruction:
        items = list(self._raw)
        if i < 0:
            i += len(items)
        if i < 0 or i >= len(items):
            raise IndexError(
                f'Block index out of range (0..{len(items) - 1})'
            )
        return PseudocodeInstruction(items[i], self)

    def __iter__(self) -> Iterator[PseudocodeInstruction]:
        for insn in self._raw:
            yield PseudocodeInstruction(insn, self)

    def __bool__(self) -> bool:
        """True if block is non-empty."""
        for _ in self._raw:
            return True
        return False

    def __repr__(self) -> str:
        return f'PseudocodeBlock(count={len(self)})'


# ---------------------------------------------------------------------------
# Instruction sub-type wrappers
# ---------------------------------------------------------------------------


class PseudocodeIf:
    """Wrapper around an IDA ``cif_t`` (if-instruction details)."""

    def __init__(
        self, raw: ida_hexrays.cif_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_if(self) -> ida_hexrays.cif_t:
        """Get the underlying ``cif_t`` object."""
        return self._raw

    @property
    def condition(self) -> PseudocodeExpression:
        """The if-condition expression."""
        return PseudocodeExpression(self._raw.expr)

    @property
    def then_branch(self) -> PseudocodeInstruction:
        """The then-branch instruction."""
        return PseudocodeInstruction(self._raw.ithen)

    @property
    def else_branch(self) -> Optional[PseudocodeInstruction]:
        """The else-branch instruction, or ``None`` if no else clause."""
        if self._raw.ielse and self._raw.ielse.op != PseudocodeInstructionOp.EMPTY:
            return PseudocodeInstruction(self._raw.ielse)
        return None

    @property
    def has_else(self) -> bool:
        """True if there is an else-branch."""
        return (
            self._raw.ielse is not None
            and self._raw.ielse.op != PseudocodeInstructionOp.EMPTY
        )

    def __repr__(self) -> str:
        return f'PseudocodeIf(has_else={self.has_else})'


class PseudocodeFor:
    """Wrapper around an IDA ``cfor_t`` (for-loop details)."""

    def __init__(
        self, raw: ida_hexrays.cfor_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_for(self) -> ida_hexrays.cfor_t:
        """Get the underlying ``cfor_t`` object."""
        return self._raw

    @property
    def init(self) -> PseudocodeExpression:
        """Initialization expression."""
        return PseudocodeExpression(self._raw.init)

    @property
    def condition(self) -> PseudocodeExpression:
        """Loop condition expression."""
        return PseudocodeExpression(self._raw.expr)

    @property
    def step(self) -> PseudocodeExpression:
        """Step/increment expression."""
        return PseudocodeExpression(self._raw.step)

    @property
    def body(self) -> PseudocodeInstruction:
        """Loop body instruction."""
        return PseudocodeInstruction(self._raw.body)

    def __repr__(self) -> str:
        return f'PseudocodeFor(ea=0x{self._raw.expr.ea:x})'


class PseudocodeWhile:
    """Wrapper around an IDA ``cwhile_t`` (while-loop details)."""

    def __init__(
        self, raw: ida_hexrays.cwhile_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_while(self) -> ida_hexrays.cwhile_t:
        """Get the underlying ``cwhile_t`` object."""
        return self._raw

    @property
    def condition(self) -> PseudocodeExpression:
        """Loop condition expression."""
        return PseudocodeExpression(self._raw.expr)

    @property
    def body(self) -> PseudocodeInstruction:
        """Loop body instruction."""
        return PseudocodeInstruction(self._raw.body)

    def __repr__(self) -> str:
        return f'PseudocodeWhile(ea=0x{self._raw.expr.ea:x})'


class PseudocodeDo:
    """Wrapper around an IDA ``cdo_t`` (do-while details)."""

    def __init__(
        self, raw: ida_hexrays.cdo_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_do(self) -> ida_hexrays.cdo_t:
        """Get the underlying ``cdo_t`` object."""
        return self._raw

    @property
    def body(self) -> PseudocodeInstruction:
        """Loop body instruction."""
        return PseudocodeInstruction(self._raw.body)

    @property
    def condition(self) -> PseudocodeExpression:
        """Loop condition expression."""
        return PseudocodeExpression(self._raw.expr)

    def __repr__(self) -> str:
        return f'PseudocodeDo(ea=0x{self._raw.expr.ea:x})'


class PseudocodeCase:
    """Wrapper around an IDA ``ccase_t`` (single switch case)."""

    def __init__(
        self, raw: ida_hexrays.ccase_t,
        _parent_switch: Optional[PseudocodeSwitch] = None,
    ):
        self._raw = raw
        self._parent_switch = _parent_switch

    @property
    def raw_case(self) -> ida_hexrays.ccase_t:
        """Get the underlying ``ccase_t`` object."""
        return self._raw

    @property
    def values(self) -> List[int]:
        """List of case values. Empty list means ``default``."""
        return list(self._raw.values)

    @property
    def is_default(self) -> bool:
        """True if this is the default case."""
        return len(self._raw.values) == 0

    @property
    def body(self) -> PseudocodeInstruction:
        """The case body instruction.

        ``ccase_t`` extends ``cinsn_t``, so the case itself is the body.
        """
        return PseudocodeInstruction(self._raw)

    def __repr__(self) -> str:
        if self.is_default:
            return 'PseudocodeCase(default)'
        return f'PseudocodeCase(values={self.values})'


class PseudocodeSwitch:
    """Wrapper around an IDA ``cswitch_t`` (switch-instruction details).

    Supports iteration over cases.
    """

    def __init__(
        self, raw: ida_hexrays.cswitch_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_switch(self) -> ida_hexrays.cswitch_t:
        """Get the underlying ``cswitch_t`` object."""
        return self._raw

    @property
    def expression(self) -> PseudocodeExpression:
        """The switch expression being tested."""
        return PseudocodeExpression(self._raw.expr)

    @property
    def cases(self) -> List[PseudocodeCase]:
        """List of switch cases."""
        return [PseudocodeCase(c, self) for c in self._raw.cases]

    def __iter__(self) -> Iterator[PseudocodeCase]:
        for c in self._raw.cases:
            yield PseudocodeCase(c, self)

    def __len__(self) -> int:
        return len(self._raw.cases)

    def __repr__(self) -> str:
        return f'PseudocodeSwitch(cases={len(self)})'


class PseudocodeReturn:
    """Wrapper around an IDA ``creturn_t`` (return-instruction details)."""

    def __init__(
        self, raw: ida_hexrays.creturn_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_return(self) -> ida_hexrays.creturn_t:
        """Get the underlying ``creturn_t`` object."""
        return self._raw

    @property
    def expression(self) -> PseudocodeExpression:
        """The returned expression."""
        return PseudocodeExpression(self._raw.expr)

    def __repr__(self) -> str:
        return f'PseudocodeReturn(ea=0x{self._raw.expr.ea:x})'


class PseudocodeGoto:
    """Wrapper around an IDA ``cgoto_t`` (goto-instruction details)."""

    def __init__(
        self, raw: ida_hexrays.cgoto_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_goto(self) -> ida_hexrays.cgoto_t:
        """Get the underlying ``cgoto_t`` object."""
        return self._raw

    @property
    def label_num(self) -> int:
        """Target label number."""
        return self._raw.label_num

    def __repr__(self) -> str:
        return f'PseudocodeGoto(label={self._raw.label_num})'


class PseudocodeTry:
    """Wrapper around an IDA ``ctry_t`` (C++ try-instruction details)."""

    def __init__(
        self, raw: ida_hexrays.ctry_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_try(self) -> ida_hexrays.ctry_t:
        """Get the underlying ``ctry_t`` object."""
        return self._raw

    @property
    def body(self) -> PseudocodeBlock:
        """The try body block (``ctry_t`` extends ``cblock_t``)."""
        return PseudocodeBlock(self._raw)

    @property
    def catches(self) -> List[Any]:
        """List of catch clauses (``catchlist_t``)."""
        return list(self._raw.catches)

    def __repr__(self) -> str:
        return f'PseudocodeTry(catches={len(self._raw.catches)})'


class PseudocodeThrow:
    """Wrapper around an IDA ``cthrow_t`` (C++ throw-instruction details)."""

    def __init__(
        self, raw: ida_hexrays.cthrow_t,
        _parent_insn: Optional[PseudocodeInstruction] = None,
    ):
        self._raw = raw
        self._parent_insn = _parent_insn

    @property
    def raw_throw(self) -> ida_hexrays.cthrow_t:
        """Get the underlying ``cthrow_t`` object."""
        return self._raw

    @property
    def expression(self) -> PseudocodeExpression:
        """The thrown expression."""
        return PseudocodeExpression(self._raw.expr)

    def __repr__(self) -> str:
        return 'PseudocodeThrow()'


# ---------------------------------------------------------------------------
# PseudocodeFunction — wraps cfuncptr_t
# ---------------------------------------------------------------------------


class PseudocodeFunction:
    """Wrapper around an IDA ``cfunc_t`` decompiled function result.

    This is the primary result of decompilation. It provides access to:

    - The function body as a ctree (instruction/expression tree)
    - Pseudocode text lines
    - Local variables (reuses :class:`~ida_domain.microcode.MicroLocalVars`)
    - User annotations (comments, labels, flags)
    - Address-to-instruction mappings

    Obtained via ``db.pseudocode.decompile(ea)``.
    """

    def __init__(self, raw: Any):
        self._raw = raw  # cfuncptr_t (reference-counted)

    @property
    def raw_cfunc(self) -> Any:
        """Get the underlying ``cfunc_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def entry_ea(self) -> ea_t:
        """Function entry address."""
        return self._raw.entry_ea

    @property
    def maturity(self) -> PseudocodeMaturity:
        """Current maturity level of the ctree."""
        return PseudocodeMaturity(self._raw.maturity)

    @property
    def body(self) -> PseudocodeInstruction:
        """Function body as a :class:`PseudocodeInstruction` (always a block)."""
        return PseudocodeInstruction(self._raw.body)

    @property
    def mba(self) -> MicroBlockArray:
        """Underlying :class:`~ida_domain.microcode.MicroBlockArray`."""
        return MicroBlockArray(self._raw.mba, _owner=self._raw)

    # -- local variables ---------------------------------------------------

    @property
    def local_variables(self) -> MicroLocalVars:
        """Local variables list as :class:`~ida_domain.microcode.MicroLocalVars`."""
        return MicroLocalVars(self._raw.get_lvars(), self.mba)

    @property
    def arguments(self) -> List[MicroLocalVar]:
        """Function arguments (filtered from local variables)."""
        lvars = self._raw.get_lvars()
        return [
            MicroLocalVar(lvars.at(i))
            for i in range(lvars.size())
            if lvars.at(i).is_arg_var
        ]

    def get_local_variable(self, name: str) -> Optional[MicroLocalVar]:
        """Find a local variable by name.

        Args:
            name: Variable name to search for.

        Returns:
            The :class:`~ida_domain.microcode.MicroLocalVar`, or ``None`` if not found.
        """
        lvars = self._raw.get_lvars()
        for i in range(lvars.size()):
            v = lvars.at(i)
            if v.name == name:
                return MicroLocalVar(v)
        return None

    # -- pseudocode text ---------------------------------------------------

    def to_text(self, remove_tags: bool = True) -> List[str]:
        """Get the decompiled pseudocode as text lines.

        Args:
            remove_tags: If ``True``, strips IDA color/formatting tags.

        Returns:
            A list of strings, each a line of pseudocode.
        """
        lines = []
        sv = self._raw.get_pseudocode()
        for i in range(len(sv)):
            line = sv[i].line
            if remove_tags:
                line = ida_lines.tag_remove(line)
            lines.append(line)
        return lines

    @property
    def header_lines(self) -> int:
        """Number of lines in the declaration/header area."""
        return self._raw.hdrlines

    def get_func_type(self) -> Optional[tinfo_t]:
        """Get the function type information."""
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        if self._raw.get_func_type(tif):
            return tif
        return None

    # -- address mappings --------------------------------------------------

    @property
    def eamap(self) -> Any:
        """Address-to-ctree-items map (``eamap_t``).

        Maps binary addresses to the ctree items generated from them.
        """
        return self._raw.get_eamap()

    @property
    def boundaries(self) -> Any:
        """Instruction boundaries map (``boundaries_t``)."""
        return self._raw.get_boundaries()

    # -- user annotations --------------------------------------------------

    def save_user_comments(self) -> None:
        """Save user comments to the database."""
        self._raw.save_user_cmts()

    def save_user_labels(self) -> None:
        """Save user labels to the database."""
        self._raw.save_user_labels()

    def save_user_numforms(self) -> None:
        """Save user number formats to the database."""
        self._raw.save_user_numforms()

    def save_user_iflags(self) -> None:
        """Save user item flags to the database."""
        self._raw.save_user_iflags()

    def save_user_unions(self) -> None:
        """Save user union field selections to the database."""
        self._raw.save_user_unions()

    # -- ctree verification and refresh ------------------------------------

    def verify(self, allow_unused_labels: bool = True) -> None:
        """Verify ctree consistency.

        Args:
            allow_unused_labels: If ``True``, unused labels are allowed.

        Raises:
            PseudocodeError: If verification fails.
        """
        flags = ida_hexrays.ALLOW_UNUSED_LABELS if allow_unused_labels else 0
        self._raw.verify(flags, True)

    def refresh(self) -> None:
        """Refresh the pseudocode text after ctree modifications."""
        self._raw.refresh_func_ctext()

    def build_ctree(self) -> None:
        """Regenerate the function body from microcode."""
        self._raw.build_c_tree()

    # -- convenience tree traversal ----------------------------------------

    def walk_expressions(self) -> Iterator[PseudocodeExpression]:
        """Iterate over all expressions in the function body.

        Collects all items first, so it is safe to inspect during iteration
        but do not modify the tree without calling :meth:`refresh` afterward.
        """
        return self.body.walk_expressions()

    def walk_instructions(self) -> Iterator[PseudocodeInstruction]:
        """Iterate over all instructions in the function body."""
        return self.body.walk_instructions()

    def walk_all(self) -> Iterator[Union[PseudocodeExpression, PseudocodeInstruction]]:
        """Iterate over all ctree items (expressions and instructions)."""
        return self.body.walk_all()

    # -- convenience finders -----------------------------------------------

    def find_calls(
        self,
        target_name: Optional[str] = None,
        target_ea: Optional[int] = None,
    ) -> List[PseudocodeExpression]:
        """Find all call expressions, optionally filtered by target.

        Args:
            target_name: If provided, only return calls to this function name.
            target_ea: If provided, only return calls to this address.

        Returns:
            List of call :class:`PseudocodeExpression` nodes.
        """
        results = []
        for expr in self.walk_expressions():
            if not expr.is_call:
                continue
            if target_name is not None:
                callee = expr.x
                if callee is None:
                    continue
                if callee.is_object:
                    if callee.obj_name != target_name:
                        continue
                elif callee.helper_name is not None:
                    if callee.helper_name != target_name:
                        continue
                else:
                    continue
            if target_ea is not None:
                callee = expr.x
                if callee is None or not callee.is_object:
                    continue
                if callee.obj_ea != target_ea:
                    continue
            results.append(expr)
        return results

    def find_strings(self) -> List[PseudocodeExpression]:
        """Find all string constant expressions.

        Returns:
            List of :class:`PseudocodeExpression` nodes where ``is_string`` is True.
        """
        return [
            expr for expr in self.walk_expressions()
            if expr.is_string
        ]

    def find_variables(
        self,
        var_index: Optional[int] = None,
        var_name: Optional[str] = None,
    ) -> List[PseudocodeExpression]:
        """Find all variable reference expressions, optionally filtered.

        Args:
            var_index: If provided, only return references to this variable index.
            var_name: If provided, only return references to this variable name.

        Returns:
            List of :class:`PseudocodeExpression` nodes where ``is_variable`` is True.
        """
        results = []
        lvars = self._raw.get_lvars() if var_name is not None else None
        for expr in self.walk_expressions():
            if not expr.is_variable:
                continue
            idx = expr.variable_index
            if var_index is not None and idx != var_index:
                continue
            if var_name is not None and lvars is not None:
                if lvars.at(idx).name != var_name:
                    continue
            results.append(expr)
        return results

    def find_objects(self, obj_ea: Optional[int] = None) -> List[PseudocodeExpression]:
        """Find all object reference expressions, optionally filtered by address.

        Args:
            obj_ea: If provided, only return references to this address.

        Returns:
            List of :class:`PseudocodeExpression` nodes where ``is_object`` is True.
        """
        return [
            expr for expr in self.walk_expressions()
            if expr.is_object and (obj_ea is None or expr.obj_ea == obj_ea)
        ]

    def find_assignments(self) -> List[PseudocodeExpression]:
        """Find all assignment expressions.

        Returns:
            List of :class:`PseudocodeExpression` nodes where ``is_assignment`` is True.
        """
        return [
            expr for expr in self.walk_expressions()
            if expr.is_assignment
        ]

    def find_if_instructions(self) -> List[PseudocodeInstruction]:
        """Find all if-instructions.

        Returns:
            List of :class:`PseudocodeInstruction` nodes where ``is_if`` is True.
        """
        return [
            insn for insn in self.walk_instructions()
            if insn.is_if
        ]

    def find_loops(self) -> List[PseudocodeInstruction]:
        """Find all loop instructions (``for``, ``while``, ``do``).

        Returns:
            List of loop :class:`PseudocodeInstruction` nodes.
        """
        return [
            insn for insn in self.walk_instructions()
            if insn.is_loop
        ]

    def find_return_instructions(self) -> List[PseudocodeInstruction]:
        """Find all return instructions.

        Returns:
            List of :class:`PseudocodeInstruction` nodes where ``is_return`` is True.
        """
        return [
            insn for insn in self.walk_instructions()
            if insn.is_return
        ]

    # -- dunder protocols --------------------------------------------------

    def __str__(self) -> str:
        """Return the full pseudocode as a string."""
        return '\n'.join(self.to_text())

    def __repr__(self) -> str:
        return (
            f'PseudocodeFunction(ea=0x{self._raw.entry_ea:x}, '
            f'maturity={self.maturity.name})'
        )


# ---------------------------------------------------------------------------
# Visitor classes
# ---------------------------------------------------------------------------


class PseudocodeExpressionVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor for ctree expressions. Override :meth:`visit_expression`.

    Wraps raw ``cexpr_t`` into :class:`PseudocodeExpression` before
    calling the user callback.

    Example::

        class FindCalls(PseudocodeExpressionVisitor):
            def __init__(self):
                super().__init__()
                self.calls = []

            def visit_expression(self, expr):
                if expr.is_call:
                    self.calls.append(expr)
                return 0

        visitor = FindCalls()
        visitor.apply_to(decomp.body)
    """

    def __init__(self, flags: int = ida_hexrays.CV_FAST):
        super().__init__(flags)

    def visit_expr(self, raw_expr: Any) -> int:
        return self.visit_expression(PseudocodeExpression(raw_expr))

    def visit_expression(self, expr: PseudocodeExpression) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def apply_to(self, body: PseudocodeInstruction, parent: Optional[Any] = None) -> int:
        """Apply the visitor to a ctree starting at *body*.

        Args:
            body: The root instruction to start traversal from.
            parent: Optional parent item (usually ``None``).
        """
        return super().apply_to(body._raw, parent)


class PseudocodeInstructionVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor for ctree instructions. Override :meth:`visit_instruction`.

    Only visits instruction nodes (``CV_INSNS`` flag is set automatically).

    Example::

        class FindReturns(PseudocodeInstructionVisitor):
            def __init__(self):
                super().__init__()
                self.returns = []

            def visit_instruction(self, insn):
                if insn.is_return:
                    self.returns.append(insn)
                return 0

        visitor = FindReturns()
        visitor.apply_to(decomp.body)
    """

    def __init__(self, flags: int = ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS):
        super().__init__(flags)

    def visit_insn(self, raw_insn: Any) -> int:
        return self.visit_instruction(PseudocodeInstruction(raw_insn))

    def visit_instruction(self, insn: PseudocodeInstruction) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def apply_to(self, body: PseudocodeInstruction, parent: Optional[Any] = None) -> int:
        """Apply the visitor to a ctree starting at *body*."""
        return super().apply_to(body._raw, parent)


class PseudocodeVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor for both expressions and instructions.

    Override :meth:`visit_expression` and/or :meth:`visit_instruction`.

    Example::

        class CollectAll(PseudocodeVisitor):
            def __init__(self):
                super().__init__()
                self.items = []

            def visit_expression(self, expr):
                self.items.append(expr)
                return 0

            def visit_instruction(self, insn):
                self.items.append(insn)
                return 0
    """

    def __init__(self, flags: int = ida_hexrays.CV_FAST):
        super().__init__(flags)

    def visit_expr(self, raw_expr: Any) -> int:
        return self.visit_expression(PseudocodeExpression(raw_expr))

    def visit_insn(self, raw_insn: Any) -> int:
        return self.visit_instruction(PseudocodeInstruction(raw_insn))

    def visit_expression(self, expr: PseudocodeExpression) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def visit_instruction(self, insn: PseudocodeInstruction) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def apply_to(self, body: PseudocodeInstruction, parent: Optional[Any] = None) -> int:
        """Apply the visitor to a ctree starting at *body*."""
        return super().apply_to(body._raw, parent)


class PseudocodeParentVisitor(ida_hexrays.ctree_parentee_t):
    """Visitor with parent tracking.

    Extends :class:`PseudocodeVisitor` with methods to access the parent
    expression or instruction at any point during traversal.

    Example::

        class FindAssignedVars(PseudocodeParentVisitor):
            def visit_expression(self, expr):
                if expr.is_variable:
                    parent = self.parent_expression()
                    if parent and parent.is_assignment:
                        ...
                return 0
    """

    def __init__(self, post: bool = False):
        super().__init__(post)

    def visit_expr(self, raw_expr: Any) -> int:
        return self.visit_expression(PseudocodeExpression(raw_expr))

    def visit_insn(self, raw_insn: Any) -> int:
        return self.visit_instruction(PseudocodeInstruction(raw_insn))

    def visit_expression(self, expr: PseudocodeExpression) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def visit_instruction(self, insn: PseudocodeInstruction) -> int:
        """Override this. Return 0 to continue, non-zero to stop."""
        return 0

    def parent_expression(self) -> Optional[PseudocodeExpression]:
        """Get the parent as a :class:`PseudocodeExpression`, or ``None``."""
        raw = self.parent_expr()
        return PseudocodeExpression(raw) if raw else None

    def parent_instruction(self) -> Optional[PseudocodeInstruction]:
        """Get the parent as a :class:`PseudocodeInstruction`, or ``None``."""
        raw = self.parent_insn()
        return PseudocodeInstruction(raw) if raw else None

    def apply_to(self, body: PseudocodeInstruction, parent: Optional[Any] = None) -> int:
        """Apply the visitor to a ctree starting at *body*."""
        return super().apply_to(body._raw, parent)


# ---------------------------------------------------------------------------
# Entry point: Pseudocode (DatabaseEntity)
# ---------------------------------------------------------------------------


@decorate_all_methods(check_db_open)
class Pseudocode(DatabaseEntity):
    """Provides access to IDA's Hex-Rays decompiler pseudocode/ctree.

    Access via ``db.pseudocode``.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def decompile(
        self,
        ea_or_func: Union[int, func_t],
        flags: DecompilationFlags = DecompilationFlags(0),
    ) -> PseudocodeFunction:
        """Decompile a function and return the ctree result.

        Args:
            ea_or_func: Function entry address or ``func_t`` object.
            flags: Decompilation flags (``DecompilationFlags``).

        Returns:
            A :class:`PseudocodeFunction` wrapping the ``cfunc_t`` result.

        Raises:
            PseudocodeError: If decompilation fails.
        """
        ea = ea_or_func.start_ea if isinstance(ea_or_func, func_t) else ea_or_func
        hf = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(ea, hf, int(flags))
        if not cfunc:
            errea = hf.errea if hf.errea != ida_idaapi.BADADDR else None
            raise PseudocodeError(
                f'Failed to decompile function at 0x{ea:x}: {hf.str}',
                errea=errea,
            )
        return PseudocodeFunction(cfunc)

    def get_text(
        self,
        ea_or_func: Union[int, func_t],
        remove_tags: bool = True,
    ) -> List[str]:
        """Decompile and return pseudocode text lines.

        Convenience method equivalent to::

            decomp = db.pseudocode.decompile(ea_or_func)
            return decomp.to_text(remove_tags)

        Args:
            ea_or_func: Function entry address or ``func_t`` object.
            remove_tags: If ``True``, strips IDA color/formatting tags.

        Returns:
            A list of strings, each a line of pseudocode.
        """
        decomp = self.decompile(ea_or_func)
        return decomp.to_text(remove_tags=remove_tags)

    def decompile_many(
        self,
        functions: List[Union[int, func_t]],
    ) -> List[PseudocodeFunction]:
        """Decompile multiple functions.

        Args:
            functions: List of function addresses or ``func_t`` objects.

        Returns:
            List of :class:`PseudocodeFunction` results.

        Raises:
            PseudocodeError: If any decompilation fails.
        """
        return [self.decompile(f) for f in functions]
