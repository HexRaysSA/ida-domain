from __future__ import annotations

import logging

import ida_bytes
import ida_idaapi
import ida_idp
import ida_lines
import ida_ua
import ida_xref
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .operands import Operand, OperandFactory

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

    def has_operand(self, insn: insn_t, index: int) -> bool:
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
        Decodes the instruction that precedes the one at `ea` in execution flow.

        Usually just the previous instruction by address, falling through into
        `ea`. The special cases:

        - a jump or call from a lower address targets `ea`: that instruction is
          returned instead, the first one by address when several do. A jump or
          call from a higher address, like a loop jumping back, doesn't count.
          Use `db.xrefs.jumps_to_ea` and `db.xrefs.calls_to_ea` to list them all.
        - nothing falls through into `ea` and no jump or call from a lower
          address targets it, e.g. the program entry point or code only
          reached from higher addresses: None.

        Flow is many-to-many, so `get_next` on the result won't always lead
        back to `ea`. Use `db.heads.get_previous` to walk addresses instead of
        flow.

        Args:
            ea: The effective address of the instruction.

        Returns:
            An insn_t instance, or None when `ea` has no known predecessor.

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
        if not self.has_operand(insn, index):
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

    def get_next(self, ea: ea_t) -> Optional[insn_t]:
        """
        Decodes the instruction that follows the one at `ea` in execution flow.

        Usually just the next instruction by address - nearly everything falls
        through, calls and conditional jumps included. The special cases:

        - `ea` never falls through, e.g. an unconditional jump, a switch
          dispatch resolved by analysis, or a call that never returns: its jump
          or call target is returned, the first one by address when there are
          several. Use `db.xrefs.jumps_from_ea` and `db.xrefs.calls_from_ea` to
          list them all.
        - `ea` breaks execution flow (e.g. return) or no target is known (an
          unresolved indirect jump): None.

        Flow is many-to-many, so `get_previous` on the result won't always
        lead back to `ea`. Use `db.heads.get_next` to walk addresses instead
        of flow.

        Args:
            ea: The effective address of the instruction.

        Returns:
            An insn_t instance, or None when `ea` has no known successor.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        next_ea = ida_xref.get_first_cref_from(ea)

        if self.database.is_valid_ea(next_ea):
            return self.get_at(next_ea)
        else:
            return None

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
        return next(self.database.xrefs.jumps_from_ea(insn.ea), None) is not None

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
