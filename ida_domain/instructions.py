from __future__ import annotations

import logging

import ida_bytes
import ida_idaapi
import ida_idp
import ida_lines
import ida_offset
import ida_typeinf
import ida_ua
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional, Tuple

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .operands import Operand, OperandFactory, OperandFormat

if TYPE_CHECKING:
    from ida_idaapi import ea_t

    from .database import Database

logger = logging.getLogger(__name__)


@decorate_all_methods(check_db_open)
class Instructions(DatabaseEntity):
    """
    Provides access to instruction-related operations using structured operand hierarchy.

    Can be used to iterate over all instructions in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[insn_t]:
        return self.get_all()

    def is_valid(self, insn: insn_t) -> bool:
        """
        Checks if the given instruction is valid.

        Args:
            insn: The instruction to validate.

        Returns:
            `True` if the instruction is valid, `False` otherwise.
        """
        return insn and insn.itype != 0

    def is_valid_operand(self, insn: insn_t, index: int) -> bool:
        """
        Checks whether operand `index` exists on the given instruction.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            `True` if the index refers to a present (non-void) operand.
        """
        return 0 <= index < len(insn.ops) and insn.ops[index].type != ida_ua.o_void

    def get_disassembly(self, insn: insn_t, remove_tags: bool = True) -> Optional[str]:
        """
        Retrieves the disassembled string representation of the given instruction.

        Args:
            insn: The instruction to disassemble.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            The disassembly as string, if fails, returns None.
        """
        options = ida_lines.GENDSM_MULTI_LINE
        if remove_tags:
            options |= ida_lines.GENDSM_REMOVE_TAGS
        return ida_lines.generate_disasm_line(insn.ea, options)

    def get_at(self, ea: ea_t) -> Optional[insn_t]:
        """
        Decodes the instruction at the specified address.

        Args:
            ea: The effective address of the instruction.

        Returns:
            An insn_t instance, if fails returns None.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        insn = insn_t()
        if ida_ua.decode_insn(insn, ea) > 0:
            return insn
        return None

    def get_previous(self, ea: ea_t) -> Optional[insn_t]:
        """
        Decodes previous instruction of the one at specified address.

        Args:
            ea: The effective address of the instruction.

        Returns:
            An insn_t instance, if fails returns None.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        insn = insn_t()
        prev_addr, _ = ida_ua.decode_preceding_insn(insn, ea)
        return insn if prev_addr != ida_idaapi.BADADDR else None

    def get_all(self) -> Iterator[insn_t]:
        """
        Retrieves an iterator over all instructions in the database.

        Returns:
            An iterator over the instructions.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_between(self, start: ea_t, end: ea_t) -> Iterator[insn_t]:
        """
        Retrieves instructions between the specified addresses.

        Args:
            start: Start of the address range.
            end: End of the address range.

        Returns:
            An instruction iterator.

        Raises:
            InvalidEAError: If start or end are not within database bounds.
            InvalidParameterError: If start >= end.
        """
        if not self.database.is_valid_ea(start, strict_check=False):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end, strict_check=False):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        current = start
        while current < end:
            insn = insn_t()
            if ida_ua.decode_insn(insn, current) > 0:
                yield insn
            # Move to next instruction for next call
            next_addr = ida_bytes.next_head(current, end)
            if next_addr == current or next_addr == ida_idaapi.BADADDR:
                break
            current = next_addr

    def get_mnemonic(self, insn: insn_t) -> Optional[str]:
        """
        Retrieves the mnemonic of the given instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            A string representing the mnemonic of the given instruction.
            If retrieving fails, returns None.
        """
        return ida_ua.print_insn_mnem(insn.ea)

    def get_operands_count(self, insn: insn_t) -> int:
        """
        Retrieve the operands number of the given instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            An integer representing the number, if error, the number is negative.
        """
        count = 0
        for n in range(len(insn.ops)):
            if insn.ops[n].type == ida_ua.o_void:
                break
            count += 1
        return count

    def get_operand(self, insn: insn_t, index: int) -> Optional[Operand] | None:
        """
        Get a specific operand from the instruction.

        Args:
            insn: The instruction to analyze.
            index: The operand index (0, 1, 2, etc.).

        Returns:
            An Operand instance of the appropriate type, or None
            if the index is invalid or operand is void.
        """
        if not self.is_valid_operand(insn, index):
            return None

        return OperandFactory.create(self.database, insn.ops[index], insn.ea)

    def get_operands(self, insn: insn_t) -> List[Operand]:
        """
        Get all operands from the instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            A list of Operand instances of appropriate types (excludes void operands).
        """
        operands: List[Operand] = []
        for i in range(len(insn.ops)):
            op = insn.ops[i]
            if op.type == ida_ua.o_void:
                break
            operand = OperandFactory.create(self.database, op, insn.ea)
            if operand:
                operands.append(operand)
        return operands

    def is_call_instruction(self, insn: insn_t) -> bool:
        """
        Check if the instruction is a call instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            True if this is a call instruction.
        """
        # Get canonical feature flags for the instruction
        feature = insn.get_canon_feature()
        return bool(feature & ida_idp.CF_CALL)

    def is_indirect_jump_or_call(self, insn: insn_t) -> bool:
        """
        Check if the instruction passes execution using indirect jump or call

        Args:
            insn: The instruction to analyze.
        Returns:
            True if this instruction has the CF_JUMP flag set.
        """

        # Get canonical feature flags for the instruction
        feature = insn.get_canon_feature()
        return bool(feature & ida_idp.CF_JUMP)

    def breaks_sequential_flow(self, insn: insn_t) -> bool:
        """
        Check if the instruction stops sequential control flow.

        This includes return instructions, unconditional jumps,
        halt instructions, and any other instruction that doesn't
        pass execution to the next sequential instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            True if this instruction has the CF_STOP flag set.
        """

        # Get canonical feature flags for the instruction
        feature = insn.get_canon_feature()
        return bool(feature & ida_idp.CF_STOP)

    def set_operand_hex(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` in hexadecimal.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.HEX)

    def set_operand_decimal(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` in decimal.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.DECIMAL)

    def set_operand_octal(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` in octal.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.OCTAL)

    def set_operand_binary(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` in binary.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.BINARY)

    def set_operand_char(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` as a character literal.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.CHARACTER)

    def set_operand_float(self, insn: insn_t, index: int) -> bool:
        """
        Renders operand `index` as a floating point number.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        return self.set_operand_format(insn, index, OperandFormat.FLOAT)

    def set_operand_format(
        self, insn: insn_t, index: int, format: OperandFormat, base: int = 0
    ) -> bool:
        """
        Renders operand `index` using the given format.

        Args:
            insn: The instruction.
            index: The operand index.
            format: The representation to apply.
            base: Base address, only used for `OperandFormat.OFFSET`.

        Returns:
            True if the representation was applied, False otherwise.

        Raises:
            InvalidParameterError: If the format is unknown.
        """
        if not self.is_valid_operand(insn, index):
            return False

        if format == OperandFormat.OFFSET:
            return ida_offset.op_plain_offset(insn.ea, index, base)

        setters = {
            OperandFormat.HEX: ida_bytes.op_hex,
            OperandFormat.DECIMAL: ida_bytes.op_dec,
            OperandFormat.OCTAL: ida_bytes.op_oct,
            OperandFormat.BINARY: ida_bytes.op_bin,
            OperandFormat.CHARACTER: ida_bytes.op_chr,
            OperandFormat.FLOAT: ida_bytes.op_flt,
            OperandFormat.NUMBER: ida_bytes.op_num,
        }
        setter = setters.get(format)
        if setter is None:
            raise InvalidParameterError('format', format, 'unknown operand format')
        return setter(insn.ea, index)

    def set_operand_offset(self, insn: insn_t, index: int, base: int = 0) -> bool:
        """
        Renders operand `index` as an offset from `base`.

        Args:
            insn: The instruction.
            index: The operand index.
            base: Base address the offset is relative to.

        Returns:
            True if the representation was applied, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_offset.op_plain_offset(insn.ea, index, base)

    def set_operand_struct_offset(
        self, insn: insn_t, index: int, path: int | List[int], delta: int = 0
    ) -> bool:
        """
        Renders operand `index` as a structure member offset.

        Args:
            insn: The instruction.
            index: The operand index.
            path: A structure type id, or a path of ids for nested members.
            delta: Difference between the operand value and the member offset.

        Returns:
            True if the representation was applied, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        tids = list(path) if isinstance(path, (list, tuple)) else [path]
        return ida_bytes.op_stroff(insn, index, tids, delta)

    def set_operand_based_struct_offset(
        self, insn: insn_t, index: int, opval: int, base: ea_t
    ) -> bool:
        """
        Renders operand `index` as a structure member offset based at `base`.

        Args:
            insn: The instruction.
            index: The operand index.
            opval: The operand value to resolve (usually its value or address).
            base: Address the structure is based at.

        Returns:
            True if the representation was applied, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.op_based_stroff(insn, index, opval, base)

    def operand_struct_offset_path(
        self, insn: insn_t, index: int
    ) -> Optional[Tuple[List[int], int]]:
        """
        Reads the structure offset path for operand `index`.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            A tuple of (path of type ids, delta), or None if the operand is not
            represented as a structure offset.
        """
        if not self.is_valid_operand(insn, index):
            return None
        path, delta = ida_bytes.get_stroff_path(insn.ea, index)
        if path is None:
            return None
        return path, delta

    def operand_struct_offset_path_names(self, insn: insn_t, index: int) -> List[str]:
        """
        Reads the structure offset path for operand `index` as type names.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            The path as a list of type names, empty if the operand is not
            represented as a structure offset. An unnamed type appears as its
            hex tid.
        """
        result = self.operand_struct_offset_path(insn, index)
        if result is None:
            return []
        path, _ = result
        return [ida_typeinf.get_tid_name(tid) or f'{tid:#x}' for tid in path]

    def set_operand_stack_var(self, insn: insn_t, index: int) -> bool:
        """
        Links operand `index` to a stack variable.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was applied, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.op_stkvar(insn.ea, index)

    def clear_operand_representation(self, insn: insn_t, index: int) -> bool:
        """
        Resets operand `index` to its default rendering.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the representation was cleared, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.clr_op_type(insn.ea, index)

    def set_forced_operand(self, insn: insn_t, index: int, text: str) -> bool:
        """
        Overrides the display text of operand `index`.

        Args:
            insn: The instruction.
            index: The operand index.
            text: The text to display; an empty string removes the override.

        Returns:
            True if the override was applied, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.set_forced_operand(insn.ea, index, text)

    def get_forced_operand(self, insn: insn_t, index: int) -> Optional[str]:
        """
        Reads the display text override of operand `index`.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            The override text, or None if the operand has no override.
        """
        if not self.is_valid_operand(insn, index):
            return None
        return ida_bytes.get_forced_operand(insn.ea, index)

    def toggle_operand_sign(self, insn: insn_t, index: int) -> bool:
        """
        Flips the sign rendering of operand `index`.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the sign was toggled, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.toggle_sign(insn.ea, index)

    def toggle_operand_negate(self, insn: insn_t, index: int) -> bool:
        """
        Toggles the bitwise-negation rendering of operand `index`.

        Args:
            insn: The instruction.
            index: The operand index.

        Returns:
            True if the negation was toggled, False otherwise.
        """
        if not self.is_valid_operand(insn, index):
            return False
        return ida_bytes.toggle_bnot(insn.ea, index)

    def text(self, insn: insn_t) -> Optional[str]:
        """
        Retrieves the tagged disassembly text of the given instruction.

        Convenience wrapper over `get_disassembly` that keeps IDA
        color/formatting tags.

        Args:
            insn: The instruction.

        Returns:
            The tagged disassembly text, or None if none could be generated.
        """
        return self.get_disassembly(insn, remove_tags=False)

    def create(self, ea: ea_t) -> int:
        """
        Forces creation of an instruction at the specified address.

        Args:
            ea: The effective address to convert to an instruction.

        Returns:
            The length in bytes of the created instruction, or 0 if none was
            created.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_ua.create_insn(ea)

    def next(self, ea: ea_t) -> Optional[insn_t]:
        """
        Decodes the instruction following the one at the specified address.

        Args:
            ea: The effective address of the instruction.

        Returns:
            An insn_t instance, or None if there is no following instruction.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        next_ea = ida_bytes.get_item_end(ea)
        if not self.database.is_valid_ea(next_ea):
            return None
        if not ida_bytes.is_code(ida_bytes.get_flags(next_ea)):
            return None
        return self.get_at(next_ea)

    def has_fall_through(self, insn: insn_t) -> bool:
        """
        Checks whether the instruction passes execution to the next one.

        Args:
            insn: The instruction.

        Returns:
            True if the instruction can fall through, False otherwise.
        """
        return not self.breaks_sequential_flow(insn)

    def is_return(self, insn: insn_t) -> bool:
        """
        Checks whether the instruction is a return.

        Args:
            insn: The instruction.

        Returns:
            True if the instruction is a return, False otherwise.
        """
        return ida_idp.is_ret_insn(insn)

    def is_jump(self, insn: insn_t) -> bool:
        """
        Checks whether the instruction is a jump.

        Args:
            insn: The instruction.

        Returns:
            True if the instruction is a jump, False otherwise.
        """
        if ida_idp.is_indirect_jump_insn(insn):
            return True
        return any(True for _ in self.database.xrefs.jumps_from_ea(insn.ea))

    def is_conditional_jump(self, insn: insn_t) -> bool:
        """
        Checks whether the instruction is a conditional jump.

        Args:
            insn: The instruction.

        Returns:
            True if the instruction is a conditional jump, False otherwise.
        """
        return self.is_jump(insn) and self.has_fall_through(insn)

    def call_targets(self, insn: insn_t) -> Iterator[ea_t]:
        """
        Retrieves the direct call targets of the instruction.

        Args:
            insn: The instruction.

        Returns:
            An iterator over the called addresses.
        """
        return self.database.xrefs.calls_from_ea(insn.ea)

    def jump_targets(self, insn: insn_t) -> Iterator[ea_t]:
        """
        Retrieves the direct jump targets of the instruction.

        Args:
            insn: The instruction.

        Returns:
            An iterator over the jump target addresses.
        """
        return self.database.xrefs.jumps_from_ea(insn.ea)
