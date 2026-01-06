from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Optional, cast

import ida_idp
import ida_lines
import ida_name
import ida_ua
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class OperandType(IntEnum):
    """Enumeration of operand types for easier identification."""

    VOID = ida_ua.o_void
    REGISTER = ida_ua.o_reg
    MEMORY = ida_ua.o_mem
    PHRASE = ida_ua.o_phrase
    DISPLACEMENT = ida_ua.o_displ
    IMMEDIATE = ida_ua.o_imm
    FAR_ADDRESS = ida_ua.o_far
    NEAR_ADDRESS = ida_ua.o_near
    PROCESSOR_SPECIFIC_0 = ida_ua.o_idpspec0
    PROCESSOR_SPECIFIC_1 = ida_ua.o_idpspec1
    PROCESSOR_SPECIFIC_2 = ida_ua.o_idpspec2
    PROCESSOR_SPECIFIC_3 = ida_ua.o_idpspec3
    PROCESSOR_SPECIFIC_4 = ida_ua.o_idpspec4
    PROCESSOR_SPECIFIC_5 = ida_ua.o_idpspec5


class OperandDataType(IntEnum):
    """Enumeration of operand data types."""

    BYTE = ida_ua.dt_byte
    WORD = ida_ua.dt_word
    DWORD = ida_ua.dt_dword
    QWORD = ida_ua.dt_qword
    FLOAT = ida_ua.dt_float
    DOUBLE = ida_ua.dt_double
    TBYTE = ida_ua.dt_tbyte
    PACKREAL = ida_ua.dt_packreal
    BYTE16 = ida_ua.dt_byte16
    BYTE32 = ida_ua.dt_byte32
    BYTE64 = ida_ua.dt_byte64
    HALF = ida_ua.dt_half
    FWORD = ida_ua.dt_fword
    BITFIELD = ida_ua.dt_bitfild
    STRING = ida_ua.dt_string
    UNICODE = ida_ua.dt_unicode
    LDBL = ida_ua.dt_ldbl
    CODE = ida_ua.dt_code
    VOID = ida_ua.dt_void


class AccessType(Enum):
    """Enumeration of operand access types."""

    NONE = 'none'
    READ = 'read'
    WRITE = 'write'
    READ_WRITE = 'read_write'


@dataclass(frozen=True)
class OperandInfo:
    """Basic information about an operand."""

    number: int
    type: OperandType
    data_type: OperandDataType
    access_type: AccessType
    size_bytes: int
    size_bits: int
    flags: int
    is_hidden: bool
    is_floating_point: bool


class Operand(ABC):
    """Abstract base class for all operand types."""

    def __init__(self, database: Database, operand: ida_ua.op_t, instruction_ea: ea_t):
        self._database = database
        self._op = operand
        self._instruction_ea = instruction_ea

    @property
    def raw_operand(self) -> ida_ua.op_t:
        """Get the underlying op_t object."""
        return self._op

    @property
    def number(self) -> int:
        """Get the operand number (0, 1, 2, etc.)."""
        return cast(int, self._op.n)

    @property
    def type(self) -> OperandType:
        """Get the operand type as an enum."""
        return OperandType(self._op.type)

    @property
    def data_type(self) -> OperandDataType:
        """Get the operand data type as an enum."""
        return OperandDataType(self._op.dtype)

    @property
    def flags(self) -> int:
        """Get the operand flags."""
        return cast(int, self._op.flags)

    @property
    def is_shown(self) -> bool:
        """Check if the operand should be displayed."""
        return cast(bool, self._op.shown())

    @property
    def size_bytes(self) -> int:
        """Get the size of the operand in bytes."""
        return cast(int, ida_ua.get_dtype_size(self._op.dtype))

    @property
    def size_bits(self) -> int:
        """Get the size of the operand in bits."""
        return self.size_bytes * 8

    def is_floating_point(self) -> bool:
        """Check if this is a floating point operand."""
        return cast(bool, ida_ua.is_floating_dtype(self._op.dtype))

    def is_read(self) -> bool:
        """Check if this operand is read (used) by the instruction."""
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, self._instruction_ea):
            return False
        ph = ida_idp.get_ph()
        feature = ph.get_canon_feature(insn.itype)
        return cast(bool, ida_idp.has_cf_use(feature, self.number))

    def is_write(self) -> bool:
        """Check if this operand is written (modified) by the instruction."""
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, self._instruction_ea):
            return False
        ph = ida_idp.get_ph()
        feature = ph.get_canon_feature(insn.itype)
        return cast(bool, ida_idp.has_cf_chg(feature, self.number))

    def get_access_type(self) -> AccessType:
        """Get a string description of how this operand is accessed."""
        is_read = self.is_read()
        is_write = self.is_write()
        if is_read and is_write:
            return AccessType.READ_WRITE
        elif is_read:
            return AccessType.READ
        elif is_write:
            return AccessType.WRITE
        else:
            return AccessType.NONE

    def get_info(self) -> OperandInfo:
        """Get structured information about the operand."""
        return OperandInfo(
            number=self.number,
            type=self.type,
            data_type=self.data_type,
            access_type=self.get_access_type(),
            size_bytes=self.size_bytes,
            size_bits=self.size_bits,
            flags=self.flags,
            is_hidden=not self.is_shown,
            is_floating_point=self.is_floating_point(),
        )

    @abstractmethod
    def get_value(self) -> Any:
        """Get the primary value of the operand."""
        pass

    def __str__(self) -> str:
        """String representation using class name."""
        class_name = self.__class__.__name__
        return f'{class_name}(Op{self.number})'

    def __repr__(self) -> str:
        return self.__str__()


class RegisterOperand(Operand):
    """Operand representing a processor register (o_reg)."""

    @property
    def register_number(self) -> int:
        """Get the register number."""
        return cast(int, self._op.reg)

    def get_value(self) -> int:
        return self.register_number

    def get_register_name(self) -> str:
        """Get the name of this register using the operand's size."""
        return cast(str, ida_idp.get_reg_name(self.register_number, self.size_bytes))

    def __str__(self) -> str:
        class_name = self.__class__.__name__
        reg_name = self.get_register_name()
        access_type = self.get_access_type().value
        return f'{class_name}(Op{self.number}, {reg_name}, {access_type})'


class ImmediateOperand(Operand):
    """Operand representing immediate values (o_imm, o_far, o_near)."""

    def get_value(self) -> int:
        """Get the immediate value or address."""
        if self.type in (OperandType.FAR_ADDRESS, OperandType.NEAR_ADDRESS):
            return cast(int, self._op.addr)
        return cast(int, self._op.value)

    def is_address(self) -> bool:
        """Check if this is an address operand (far/near)."""
        return self.type in (OperandType.FAR_ADDRESS, OperandType.NEAR_ADDRESS)

    def has_outer_displacement(self) -> bool:
        """Check if this operand has an outer displacement.

        Returns True if the OF_OUTER_DISP flag is set.
        """
        return bool(self._op.flags & ida_ua.OF_OUTER_DISP)

    def get_name(self) -> Optional[str]:
        """Get the symbolic name for address operands."""
        if self.is_address():
            name = ida_name.get_name(self.get_value())
            return name if name else None
        return None

    def __str__(self) -> str:
        class_name = self.__class__.__name__
        value = self.get_value()
        if self.is_address():
            name = self.get_name()
            addr_str = name if name else f'0x{value:x}'
            type_name = self.type.name.lower()
            return f'{class_name}(Op{self.number}, {type_name}, {addr_str})'
        return f'{class_name}(Op{self.number}, 0x{value:x})'


class MemoryOperand(Operand):
    """Operand representing memory access (o_mem, o_phrase, o_displ)."""

    def get_value(self) -> Any:
        """Get the primary value based on memory type."""
        if self.type == OperandType.MEMORY:
            return self._op.addr
        elif self.type == OperandType.PHRASE:
            return self._op.phrase
        elif self.type == OperandType.DISPLACEMENT:
            return {'phrase': self._op.phrase, 'displacement': self._op.addr}
        return self._op.addr

    def is_direct_memory(self) -> bool:
        """Check if this is direct memory access."""
        return self.type == OperandType.MEMORY

    def is_register_based(self) -> bool:
        """Check if this uses register-based addressing."""
        return self.type in (OperandType.PHRASE, OperandType.DISPLACEMENT)

    def get_address(self) -> Optional[ea_t]:
        """Get the address for direct memory operands."""
        if self.type == OperandType.MEMORY:
            return self._op.addr
        elif self.type == OperandType.DISPLACEMENT:
            return self._op.addr  # displacement value
        return None

    def get_phrase_number(self) -> Optional[int]:
        """Get the phrase number for register-based operands."""
        if self.is_register_based():
            return cast(int, self._op.phrase)
        return None

    def get_displacement(self) -> Optional[int]:
        """Get the base displacement value.

        This is the primary displacement used in addressing modes like [reg + disp].
        Stored in op_t.addr field.
        """
        if self.type == OperandType.DISPLACEMENT:
            return cast(int, self._op.addr)
        return None

    def get_outer_displacement(self) -> Optional[int]:
        """Get the outer displacement value for complex addressing modes.

        Only present when OF_OUTER_DISP flag is set. Stored in op_t.value field.
        """
        if (
            self.type == OperandType.DISPLACEMENT
            and self._op.value
            and self.has_outer_displacement()
        ):
            return cast(int, self._op.value)
        return None

    def has_outer_displacement(self) -> bool:
        """Check if this operand has an outer displacement.

        Returns True if the OF_OUTER_DISP flag is set.
        """
        return bool(self._op.flags & ida_ua.OF_OUTER_DISP)

    def get_name(self) -> Optional[str]:
        """Get the symbolic name for direct memory operands."""
        if self.type == OperandType.MEMORY:
            name = ida_name.get_name(self._op.addr)
            return name if name else None
        return None

    def get_formatted_string(self) -> Optional[str]:
        """Get the formatted operand string from IDA."""
        ret = ida_ua.print_operand(self._instruction_ea, self.number)
        return cast(str, ida_lines.tag_remove(ret))

    def __str__(self) -> str:
        class_name = self.__class__.__name__
        if self.type == OperandType.MEMORY:
            addr = self.get_address()
            name = self.get_name()
            addr_str = f'[{name}]' if name else f'[0x{addr:x}]'
            return f'{class_name}(Op{self.number}, direct, {addr_str})'
        else:
            addressing_str = self.get_formatted_string()
            type_name = self.type.name.lower()
            if addressing_str:
                return f'{class_name}(Op{self.number}, {type_name}, {addressing_str})'
            else:
                return f'{class_name}(Op{self.number}, {type_name})'


class ProcessorSpecificOperand(Operand):
    """Operand representing processor-specific types (o_idpspec0-5)."""

    def __init__(self, database: Database, operand: ida_ua.op_t, instruction_ea: int):
        super().__init__(database, operand, instruction_ea)
        self._spec_type: int = cast(int, operand.type - ida_ua.o_idpspec0)

    def get_value(self) -> Any:
        """Return raw value for processor-specific operands."""
        return self._op.value

    def get_spec_type(self) -> int:
        """Get the processor-specific type number (0-5)."""
        return self._spec_type

    def __str__(self) -> str:
        class_name = self.__class__.__name__
        return f'{class_name}(Op{self.number}, type={self._spec_type}, value=0x{self._op.value:x})'


class OperandFactory:
    """Factory for creating appropriate operand instances."""

    @staticmethod
    def create(database: Database, operand: ida_ua.op_t, instruction_ea: int) -> Optional[Operand]:
        """Create an operand instance based on the operand type."""
        if not operand or operand.type == ida_ua.o_void:
            return None

        op_type = operand.type

        if op_type == ida_ua.o_reg:
            return RegisterOperand(database, operand, instruction_ea)
        elif op_type in (ida_ua.o_imm, ida_ua.o_far, ida_ua.o_near):
            return ImmediateOperand(database, operand, instruction_ea)
        elif op_type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
            return MemoryOperand(database, operand, instruction_ea)
        elif ida_ua.o_idpspec0 <= op_type <= ida_ua.o_idpspec5:
            return ProcessorSpecificOperand(database, operand, instruction_ea)
        else:
            # Unknown operand type, treat as processor-specific
            return ProcessorSpecificOperand(database, operand, instruction_ea)
