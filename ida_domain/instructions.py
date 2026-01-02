from __future__ import annotations

import logging
from typing import Tuple, cast

import ida_bytes
import ida_idaapi
import ida_idp
import ida_lines
import ida_nalt
import ida_offset
import ida_ua
import ida_xref
from ida_ua import insn_t, op_t
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
        return cast(bool, insn and insn.itype != 0)

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
        return cast(Optional[str], ida_lines.generate_disasm_line(insn.ea, options))

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

    def get_page(self, offset: int = 0, limit: int = 100) -> List[insn_t]:
        """
        Get a page of instructions for random access patterns.

        Unlike get_all() which returns an iterator, this returns a list
        suitable for indexing and length checks. Useful for pagination in UIs.

        Args:
            offset: Number of instructions to skip (default: 0).
            limit: Maximum number of instructions to return (default: 100).

        Returns:
            List of instructions, may be shorter than limit if fewer remain.

        Example:
            >>> # Display page 3 of instructions (25 per page)
            >>> page = db.instructions.get_page(offset=50, limit=25)
            >>> for insn in page:
            ...     print(db.instructions.get_disassembly(insn))
        """
        import itertools

        return list(itertools.islice(self.get_all(), offset, offset + limit))

    def get_chunked(self, chunk_size: int = 1000) -> Iterator[List[insn_t]]:
        """
        Yield instructions in chunks for batch processing.

        Useful for processing large numbers of instructions with periodic
        progress updates or commits.

        Args:
            chunk_size: Maximum instructions per chunk (default: 1000).

        Yields:
            Lists of instructions, each at most chunk_size items.

        Example:
            >>> # Process in batches with progress
            >>> for i, chunk in enumerate(db.instructions.get_chunked(100)):
            ...     print(f"Processing batch {i+1}: {len(chunk)} instructions")
            ...     for insn in chunk:
            ...         process(insn)
        """
        chunk: List[insn_t] = []
        for insn in self.get_all():
            chunk.append(insn)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[insn_t]:
        """
        Retrieves instructions between the specified addresses.

        Args:
            start_ea: Start of the address range.
            end_ea: End of the address range.

        Returns:
            An instruction iterator.

        Raises:
            InvalidEAError: If start_ea or end_ea are not within database bounds.
            InvalidParameterError: If start_ea >= end_ea.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        current = start_ea
        while current < end_ea:
            insn = insn_t()
            if ida_ua.decode_insn(insn, current) > 0:
                yield insn
            # Move to next instruction for next call
            current = ida_bytes.next_head(current, end_ea)

    def get_mnemonic(self, insn: insn_t) -> Optional[str]:
        """
        Retrieves the mnemonic of the given instruction.

        Args:
            insn: The instruction to analyze.

        Returns:
            A string representing the mnemonic of the given instruction.
            If retrieving fails, returns None.
        """
        return cast(Optional[str], ida_ua.print_insn_mnem(insn.ea))

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

    def get_operand(self, insn: insn_t, index: int) -> Optional[Operand]:
        """
        Get a specific operand from the instruction.

        Args:
            insn: The instruction to analyze.
            index: The operand index (0, 1, 2, etc.).

        Returns:
            An Operand instance of the appropriate type, or None
            if the index is invalid or operand is void.
        """
        if index < 0 or index >= len(insn.ops):
            return None

        op = insn.ops[index]
        if op.type == ida_ua.o_void:
            return None

        return OperandFactory.create(self.database, op, insn.ea)

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

    def decode_at(self, ea: ea_t, out: insn_t) -> int:
        """
        Decode instruction at address, filling the provided insn_t structure.

        This method provides legacy-style interface for advanced use cases requiring
        precise control over instruction decoding.

        Args:
            ea: Effective address of the instruction
            out: insn_t structure to fill with decoded data

        Returns:
            Length of the decoded instruction in bytes, or 0 if decoding failed

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> insn = ida_ua.insn_t()
            >>> length = db.instructions.decode_at(0x401000, insn)
            >>> if length > 0:
            ...     print(f"Decoded {length} byte instruction")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(int, ida_ua.decode_insn(out, ea))

    def get_preceding(self, ea: ea_t) -> Tuple[Optional[insn_t], Optional[bool]]:
        """
        Get the instruction preceding the given address, following execution flow.

        This method is more sophisticated than get_previous() - it follows control flow
        including cross-references to find the preceding instruction.

        Args:
            ea: Effective address to search backward from

        Returns:
            Tuple of (insn_t object or None, far_reference flag or None)
            The far_reference flag indicates if a far jump/call was followed

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> insn, is_far = db.instructions.get_preceding(0x401010)
            >>> if insn:
            ...     print(f"Preceding instruction at {insn.ea:#x}")
            ...     if is_far:
            ...         print("Reached via far reference")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        insn = insn_t()
        p_farref = ida_ua.cvar.cmd if hasattr(ida_ua.cvar, 'cmd') else None

        # decode_preceding_insn returns tuple (ea, farref)
        prev_ea, farref = ida_ua.decode_preceding_insn(insn, ea)

        if prev_ea != ida_idaapi.BADADDR:
            return (insn, farref)
        return (None, None)

    def get_next(self, ea: ea_t) -> Optional[insn_t]:
        """
        Get the instruction immediately following the specified address.

        Args:
            ea: Effective address to search forward from

        Returns:
            insn_t object for the next instruction, or None if no next instruction exists

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> current = db.instructions.get_at(0x401000)
            >>> if current:
            ...     next_insn = db.instructions.get_next(current.ea)
            ...     if next_insn:
            ...         print(f"Next instruction at {next_insn.ea:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Decode current instruction to get size
        current = self.get_at(ea)
        if not current:
            return None

        # Calculate next instruction address
        next_ea = ea + current.size

        # Make sure next_ea is valid
        if not self.database.is_valid_ea(next_ea):
            return None

        # Decode next instruction
        return self.get_at(next_ea)

    def create_at(self, ea: ea_t) -> bool:
        """
        Create (analyze and decode) an instruction at the specified address.

        This forces IDA to analyze bytes at the given address as an instruction,
        potentially converting undefined bytes or data into code.

        Args:
            ea: Address where instruction should be created

        Returns:
            True if instruction created successfully, False otherwise

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.instructions.create_at(0x401000):
            ...     print("Successfully created instruction")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        length = cast(int, ida_ua.create_insn(ea))
        return length > 0

    def can_decode(self, ea: ea_t) -> bool:
        """
        Check if bytes at address can be decoded as a valid instruction.

        This is an alias for is_valid() that checks if the bytes form a valid
        instruction without necessarily creating it in the database.

        Args:
            ea: Address to check

        Returns:
            True if bytes can be decoded as valid instruction, False otherwise

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> if db.instructions.can_decode(0x401000):
            ...     print("Valid instruction exists at address")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        insn = insn_t()
        return cast(int, ida_ua.decode_insn(insn, ea)) > 0

    def get_size(self, ea: ea_t) -> int:
        """
        Get the size of the instruction at the specified address.

        Args:
            ea: Address of the instruction

        Returns:
            Size of instruction in bytes (0 if no instruction exists)

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> size = db.instructions.get_size(0x401000)
            >>> print(f"Instruction is {size} bytes")
        """
        insn = self.get_at(ea)
        if not insn:
            return 0

        return cast(int, insn.size)

    def format_operand(self, ea: ea_t, operand_index: int, flags: int = 0) -> str:
        """
        Format a single operand as text with fine-grained control.

        Args:
            ea: Address of the instruction
            operand_index: Index of operand to format (0-based)
            flags: Formatting flags (OOF_* constants from ida_ua)

        Returns:
            Formatted operand string (empty string if formatting fails)

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> operand_text = db.instructions.format_operand(0x401000, 0)
            >>> print(f"First operand: {operand_text}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        result = ida_ua.print_operand(ea, operand_index, flags)
        return result if result else ''

    def add_code_reference(self, from_ea: ea_t, to_ea: ea_t, reference_type: int) -> None:
        """
        Add a code cross-reference from one instruction to another.

        Args:
            from_ea: Source instruction address
            to_ea: Target code address
            reference_type: Type of code reference (fl_CN, fl_CF, fl_JN, fl_JF, fl_F, fl_U)

        Raises:
            InvalidEAError: If either address is invalid

        Example:
            >>> from ida_xref import fl_CN
            >>> db = Database.open_current()
            >>> db.instructions.add_code_reference(0x401000, 0x402000, fl_CN)
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        # Add cross-reference using ida_xref
        ida_xref.add_cref(from_ea, to_ea, reference_type)

    def add_data_reference(self, from_ea: ea_t, to_ea: ea_t, reference_type: int) -> None:
        """
        Add a data cross-reference from an instruction to a data address.

        Args:
            from_ea: Source instruction address
            to_ea: Target data address
            reference_type: Type of data reference (dr_R, dr_W, dr_O, dr_T, dr_I)

        Raises:
            InvalidEAError: If either address is invalid

        Example:
            >>> from ida_xref import dr_R
            >>> db = Database.open_current()
            >>> db.instructions.add_data_reference(0x401000, 0x403000, dr_R)
        """
        if not self.database.is_valid_ea(from_ea):
            raise InvalidEAError(from_ea)
        if not self.database.is_valid_ea(to_ea):
            raise InvalidEAError(to_ea)

        # Add data cross-reference using ida_xref
        ida_xref.add_dref(from_ea, to_ea, reference_type)

    def get_data_type_size(self, dtype: int) -> int:
        """
        Get the size in bytes of an operand data type.

        Args:
            dtype: Operand data type constant (dt_byte, dt_word, dt_dword, etc.)

        Returns:
            Size of data type in bytes

        Example:
            >>> import ida_ua
            >>> db = Database.open_current()
            >>> size = db.instructions.get_data_type_size(ida_ua.dt_dword)
            >>> print(f"DWORD size: {size} bytes")  # Output: 4 bytes
        """
        return cast(int, ida_ua.get_dtype_size(dtype))

    def get_data_type_by_size(self, size: int) -> int:
        """
        Get the appropriate operand data type for a given size.

        Args:
            size: Size in bytes (1, 2, 4, 8, etc.)

        Returns:
            Corresponding operand data type constant

        Raises:
            InvalidParameterError: If size doesn't map to a standard data type

        Example:
            >>> db = Database.open_current()
            >>> dtype = db.instructions.get_data_type_by_size(4)
            >>> # dtype will be ida_ua.dt_dword
        """
        dtype = cast(int, ida_ua.get_dtype_by_size(size))

        if dtype == ida_ua.dt_void:
            raise InvalidParameterError('size', size, 'no standard data type for this size')

        return dtype

    def get_data_type_flag(self, dtype: int) -> int:
        """
        Get the flags representation of an operand data type.

        Args:
            dtype: Operand data type constant

        Returns:
            Flags value corresponding to data type

        Example:
            >>> import ida_ua
            >>> db = Database.open_current()
            >>> flags = db.instructions.get_data_type_flag(ida_ua.dt_dword)
        """
        return cast(int, ida_ua.get_dtype_flag(dtype))

    def is_floating_data_type(self, dtype: int) -> bool:
        """
        Check if an operand data type represents a floating-point value.

        Args:
            dtype: Operand data type constant

        Returns:
            True if data type is floating-point (float, double, tbyte)

        Example:
            >>> import ida_ua
            >>> db = Database.open_current()
            >>> is_float = db.instructions.is_floating_data_type(ida_ua.dt_float)
            >>> print(is_float)  # Output: True
        """
        return cast(bool, ida_ua.is_floating_dtype(dtype))

    def map_operand_address(self, insn: insn_t, operand: op_t, is_code: bool) -> ea_t:
        """
        Map operand address to actual effective address (handle segments).

        This handles segment registers and other addressing modes to resolve
        the actual effective address referenced by an operand.

        Args:
            insn: Decoded instruction
            operand: Operand to map
            is_code: True if mapping code address, False for data address

        Returns:
            Mapped effective address

        Example:
            >>> db = Database.open_current()
            >>> insn = db.instructions.get_at(0x401000)
            >>> if insn:
            ...     op = insn.ops[0]
            ...     ea = db.instructions.map_operand_address(insn, op, True)
        """
        if is_code:
            return ida_ua.map_code_ea(insn, operand)
        else:
            return ida_ua.map_data_ea(insn, operand)

    def calculate_data_segment(
        self, insn: insn_t, operand_index: int = -1, reg_num: int = -1
    ) -> ea_t:
        """
        Calculate data segment base address for instruction operand.

        Args:
            insn: Decoded instruction
            operand_index: Index of operand (default: -1 for automatic)
            reg_num: Register number (default: -1 for automatic)

        Returns:
            Data segment base address

        Example:
            >>> db = Database.open_current()
            >>> insn = db.instructions.get_at(0x401000)
            >>> if insn:
            ...     seg_base = db.instructions.calculate_data_segment(insn)
        """
        return ida_ua.calc_dataseg(insn, operand_index, reg_num)

    def set_operand_offset(
        self,
        ea: ea_t,
        operand_n: int,
        base: ea_t,
        target: Optional[ea_t] = None,
        ref_type: Optional[int] = None,
    ) -> bool:
        """
        Convert an operand to an offset reference.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based, or ida_bytes.OPND_MASK for all)
            base: Base address for the offset calculation
            target: Target address (optional, calculated if not specified)
            ref_type: Reference type (optional, uses default if not specified)

        Returns:
            True if successful, False otherwise

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> # Convert operand 0 to offset from segment base
            >>> db.instructions.set_operand_offset(0x401000, 0, 0x400000)
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # If ref_type not specified, get default for segment
        if ref_type is None:
            ref_type = ida_offset.get_default_reftype(ea)

        # If target not specified, use BADADDR (auto-calculate)
        if target is None:
            target = ida_idaapi.BADADDR

        # Call legacy API
        return cast(bool, ida_offset.op_offset(ea, operand_n, ref_type, target, base, 0))

    def set_operand_offset_ex(
        self,
        ea: ea_t,
        operand_n: int,
        ref_info: ida_nalt.refinfo_t,  # refinfo_t from ida_nalt
    ) -> bool:
        """
        Convert an operand to offset using detailed reference information.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based, or ida_bytes.OPND_MASK for all)
            ref_info: refinfo_t structure with detailed offset parameters

        Returns:
            True if successful, False otherwise

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> import ida_nalt
            >>> db = Database.open_current()
            >>> ri = ida_nalt.refinfo_t()
            >>> ri.base = 0x400000
            >>> db.instructions.set_operand_offset_ex(0x401000, 0, ri)
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Call legacy API with refinfo_t
        return cast(bool, ida_offset.op_offset_ex(ea, operand_n, ref_info))

    def get_operand_offset_base(self, ea: ea_t, operand_n: int) -> Optional[ea_t]:
        """
        Get the offset base address for an operand.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based)

        Returns:
            Base address or None if operand is not an offset

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> base = db.instructions.get_operand_offset_base(0x401000, 0)
            >>> if base:
            ...     print(f"Offset base: {base:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Call legacy API
        base = ida_offset.get_offbase(ea, operand_n)

        # Convert BADADDR to None for Pythonic interface
        return base if base != ida_idaapi.BADADDR else None

    def get_operand_offset_target(self, ea: ea_t, operand_n: int) -> Optional[ea_t]:
        """
        Calculate the target address for an offset operand.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based)

        Returns:
            Target address or None if operand is not an offset

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> target = db.instructions.get_operand_offset_target(0x401000, 0)
            >>> if target:
            ...     print(f"Offset target: {target:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Get refinfo for operand
        ri = ida_nalt.refinfo_t()
        if not ida_nalt.get_refinfo(ri, ea, operand_n):
            return None  # Not an offset operand

        # Decode instruction to get operand value
        insn = self.get_at(ea)
        if not insn or operand_n >= len(insn.ops):
            return None

        # Get operand value (typically op_t.value or op_t.addr)
        op = insn.ops[operand_n]
        if op.type == ida_ua.o_void:
            return None

        opval = op.value if op.type == ida_ua.o_imm else op.addr

        # Calculate target using refinfo and operand value
        target = ida_offset.calc_target(ea, opval, ri)

        # Convert BADADDR to None
        return target if target != ida_idaapi.BADADDR else None

    def format_offset_expression(
        self, ea: ea_t, operand_n: int, include_displacement: bool = True
    ) -> Optional[str]:
        """
        Get a formatted offset expression for display.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based)
            include_displacement: Include displacement in output (default: True)

        Returns:
            Formatted offset expression or None if not an offset

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> expr = db.instructions.format_offset_expression(0x401000, 0)
            >>> if expr:
            ...     print(f"Offset expression: {expr}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Decode instruction to get operand value
        insn = self.get_at(ea)
        if not insn or operand_n >= len(insn.ops):
            return None

        op = insn.ops[operand_n]
        if op.type == ida_ua.o_void:
            return None

        # Get operand value
        opval = op.value if op.type == ida_ua.o_imm else op.addr

        # Get offset expression
        from_ea = ea + op.offb  # offb is operand offset in instruction bytes

        result = ida_offset.get_offset_expression(
            ea,
            operand_n,
            from_ea,
            opval,
            0,  # flags=0 for default formatting
        )

        # Return None if empty result
        if not result:
            return None

        # Note: include_displacement parameter is documented but the underlying
        # ida_offset.get_offset_expression doesn't have a direct flag for this.
        # The parameter is kept for API compatibility but currently has no effect.
        return cast(Optional[str], result)

    def calculate_offset_base(self, ea: ea_t, operand_n: int) -> Optional[ea_t]:
        """
        Calculate offset base considering fixup information and segment registers.

        Args:
            ea: Effective address of the instruction
            operand_n: Operand number (0-based)

        Returns:
            Calculated base address or None if calculation failed

        Raises:
            InvalidEAError: If the address is invalid

        Example:
            >>> db = Database.open_current()
            >>> base = db.instructions.calculate_offset_base(0x401000, 0)
            >>> if base:
            ...     print(f"Calculated base: {base:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Call legacy API
        base = ida_offset.calc_offset_base(ea, operand_n)

        # Convert BADADDR to None
        return base if base != ida_idaapi.BADADDR else None
