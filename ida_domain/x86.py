from typing import Optional
from dataclasses import dataclass


class RexPrefix:
    """
    Helper class for decoding REX prefixes from instruction prefix bytes.
    """

    def __init__(self, insnpref: int):
        self.val = insnpref

    @property
    def w(self) -> int:
        """REX.W: Operand size override (64-bit)."""
        return 1 if (self.val & 8) else 0

    @property
    def r(self) -> int:
        """REX.R: Extension of the ModR/M reg field."""
        return 1 if (self.val & 4) else 0

    @property
    def x(self) -> int:
        """REX.X: Extension of the SIB index field."""
        return 1 if (self.val & 2) else 0

    @property
    def b(self) -> int:
        """REX.B: Extension of the ModR/M r/m field, SIB base field, or Opcode reg field."""
        return 1 if (self.val & 1) else 0


class SIB:
    """
    Helper class for decoding x86/x64 SIB (Scale-Index-Base) bytes.
    """

    def __init__(self, specflag2: int):
        self.val = specflag2

    @property
    def scale(self) -> int:
        """Get scale factor (1, 2, 4, 8)."""
        shift = (self.val >> 6) & 3
        return 1 << shift

    @property
    def index(self) -> int:
        """Get index register index (0-7)."""
        return (self.val >> 3) & 7

    @property
    def base(self) -> int:
        """Get base register index (0-7)."""
        return self.val & 7


@dataclass
class MemoryComponents:
    """
    Structured representation of memory operand components.
    """

    base_reg: Optional[str] = None
    index_reg: Optional[str] = None
    scale: Optional[int] = None
    displacement: Optional[str] = None
    disp_val: Optional[int] = None
