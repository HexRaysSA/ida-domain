"""
Stack frame analysis and management entity for IDA Domain API.

Provides comprehensive access to function stack frame operations within the IDA database,
including frame creation, variable management, and SP tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import ida_frame
import ida_funcs
import ida_range
import ida_typeinf
from ida_idaapi import BADADDR, ea_t
from ida_typeinf import tinfo_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .functions import StackPoint

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


__all__ = [
    "StackFrames",
    "StackFrameInstance",
    "StackVariable",
    "FrameSection",
    "StackVarXref",
]


# ============================================================================
# Supporting Data Classes
# ============================================================================


@dataclass
class StackVariable:
    """
    Represents a stack variable or function argument.

    Stack variables include function arguments (positive frame offsets),
    local variables (negative frame offsets), and special members like
    return addresses and saved registers.
    """

    name: str
    """Variable name"""
    offset: int
    """Frame offset (negative for locals, positive for arguments)"""
    type: tinfo_t
    """Type information"""
    size: int
    """Size in bytes"""
    is_argument: bool
    """True if this is a function argument, False if local variable"""
    is_special: bool
    """True for return address or saved registers, False for user variables"""


@dataclass
class FrameSection:
    """
    Represents the boundaries of a stack frame section.

    Frame sections include arguments, local variables, saved registers,
    and return address. Each section has a start and end offset.
    """

    start_offset: int
    """Start offset (inclusive)"""
    end_offset: int
    """End offset (exclusive)"""


@dataclass
class StackVarXref:
    """
    Cross-reference to a stack variable.

    Represents a location in code where a stack variable is accessed.
    """

    ea: ea_t
    """Instruction address where variable is accessed"""
    operand: int
    """Operand number (0-based) that references the variable"""
    type: int
    """Xref type (cref_t or dref_t value)"""


# ============================================================================
# StackFrames Entity
# ============================================================================


@decorate_all_methods(check_db_open)
class StackFrames(DatabaseEntity):
    """
    Provides access to stack frame operations within the IDA database.

    This entity manages function stack frames, including creation, deletion,
    variable management, and stack pointer tracking. Stack frames represent
    the memory layout used by functions during execution.

    Example:
        >>> db = Database.open_current()
        >>> frame = db.stack_frames.get_at(0x401000)
        >>> if frame:
        ...     print(f"Frame size: {frame.size} bytes")
        ...     print(f"Local variables: {frame.local_size} bytes")
        ...     for var in frame.variables:
        ...         print(f"  {var.name} at offset {var.offset}")
    """

    def __init__(self, database: Database) -> None:
        """Initialize the stack frames entity."""
        super().__init__(database)

    def get_at(self, func_ea: ea_t) -> Optional[StackFrameInstance]:
        """
        Get stack frame instance at function address.

        Args:
            func_ea: Address of the function

        Returns:
            StackFrameInstance object if frame exists, None otherwise

        Raises:
            InvalidEAError: If func_ea is not a valid function address

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> if frame:
            ...     print(f"Frame size: {frame.size}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Check if frame exists
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return None

        return StackFrameInstance(self.database, func_ea, func)

    # ========================================================================
    # Frame Lifecycle Methods
    # ========================================================================

    def create(
        self,
        func_ea: ea_t,
        local_size: int,
        saved_regs_size: int = 0,
        argument_size: int = 0,
    ) -> bool:
        """
        Create a new stack frame for a function.

        Args:
            func_ea: Address of the function
            local_size: Size of local variables section in bytes
            saved_regs_size: Size of saved registers section (default: 0)
            argument_size: Size of arguments to be purged (__stdcall/__fastcall) (default: 0)

        Returns:
            True if frame was created successfully

        Raises:
            InvalidEAError: If func_ea is not a valid function start address
            RuntimeError: If frame already exists

        Example:
            >>> # Create frame with 0x20 bytes of locals
            >>> success = db.stack_frames.create(0x401000, local_size=0x20)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Check if frame already exists
        frame_type = tinfo_t()
        if ida_frame.get_func_frame(frame_type, func):
            raise RuntimeError(f"Frame already exists at 0x{func_ea:x}")

        return ida_frame.add_frame(
            func, frsize=local_size, frregs=saved_regs_size, argsize=argument_size
        )

    def delete(self, func_ea: ea_t) -> bool:
        """
        Delete the stack frame for a function.

        Args:
            func_ea: Address of the function

        Returns:
            True if frame was deleted, False if no frame existed

        Raises:
            InvalidEAError: If func_ea is not a valid function start address

        Example:
            >>> db.stack_frames.delete(0x401000)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        return ida_frame.del_frame(func)

    def resize(
        self,
        func_ea: ea_t,
        local_size: int,
        saved_regs_size: Optional[int] = None,
        argument_size: Optional[int] = None,
    ) -> bool:
        """
        Resize an existing stack frame.

        Args:
            func_ea: Address of the function
            local_size: New size of local variables section
            saved_regs_size: New size of saved registers (None = keep current)
            argument_size: New argument size (None = keep current)

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not a valid function
            RuntimeError: If no frame exists

        Example:
            >>> # Expand locals to 0x40 bytes
            >>> db.stack_frames.resize(0x401000, local_size=0x40)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Ensure frame exists
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            raise RuntimeError(f"No frame exists at 0x{func_ea:x}")

        # Get current values if not provided
        if saved_regs_size is None:
            saved_regs_size = func.frregs
        if argument_size is None:
            argument_size = func.argsize

        return ida_frame.set_frame_size(
            func, frsize=local_size, frregs=saved_regs_size, argsize=argument_size
        )

    def set_purged_bytes(self, func_ea: ea_t, nbytes: int, override: bool = True) -> bool:
        """
        Set the number of bytes purged by the function upon return.

        Used for __stdcall and __fastcall calling conventions where the
        callee cleans the stack.

        Args:
            func_ea: Address of the function
            nbytes: Number of bytes to purge
            override: Allow overwriting existing value (default: True)

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> # Mark as __stdcall with 12 bytes of arguments
            >>> db.stack_frames.set_purged_bytes(0x401000, 12)
        """
        return ida_frame.set_purged(func_ea, nbytes, override_old_value=override)

    # ========================================================================
    # Section Accessor Methods
    # ========================================================================

    def get_arguments_section(self, func_ea: ea_t) -> FrameSection:
        """
        Get the boundaries of the arguments section.

        Args:
            func_ea: Address of the function

        Returns:
            FrameSection with start and end offsets

        Raises:
            InvalidEAError: If func_ea is not a valid function

        Example:
            >>> section = db.stack_frames.get_arguments_section(0x401000)
            >>> print(f"Arguments: {section.start_offset} to {section.end_offset}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        range_obj = ida_range.range_t()
        ida_frame.get_frame_part(range_obj, func, ida_frame.FPC_ARGS)

        return FrameSection(start_offset=range_obj.start_ea, end_offset=range_obj.end_ea)

    def get_locals_section(self, func_ea: ea_t) -> FrameSection:
        """
        Get the boundaries of the local variables section.

        Args:
            func_ea: Address of the function

        Returns:
            FrameSection with start and end offsets (negative values)

        Raises:
            InvalidEAError: If func_ea is not a valid function

        Example:
            >>> section = db.stack_frames.get_locals_section(0x401000)
            >>> print(f"Locals: {section.start_offset} to {section.end_offset}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        range_obj = ida_range.range_t()
        ida_frame.get_frame_part(range_obj, func, ida_frame.FPC_LVARS)

        return FrameSection(start_offset=range_obj.start_ea, end_offset=range_obj.end_ea)

    def get_saved_regs_section(self, func_ea: ea_t) -> FrameSection:
        """
        Get the boundaries of the saved registers section.

        Args:
            func_ea: Address of the function

        Returns:
            FrameSection with start and end offsets

        Raises:
            InvalidEAError: If func_ea is not a valid function

        Example:
            >>> section = db.stack_frames.get_saved_regs_section(0x401000)
            >>> print(f"Saved regs: {section.start_offset} to {section.end_offset}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        range_obj = ida_range.range_t()
        ida_frame.get_frame_part(range_obj, func, ida_frame.FPC_SAVREGS)

        return FrameSection(start_offset=range_obj.start_ea, end_offset=range_obj.end_ea)

    # ========================================================================
    # Variable Management Methods
    # ========================================================================

    def define_variable(
        self, func_ea: ea_t, name: str, offset: int, var_type: tinfo_t
    ) -> bool:
        """
        Define or redefine a stack variable at the specified offset.

        Args:
            func_ea: Address of the function
            name: Variable name (use None for auto-generated name)
            offset: Frame offset (negative for locals, positive for arguments)
            var_type: Type information for the variable

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not valid
            TypeError: If var_type is invalid

        Example:
            >>> from ida_typeinf import tinfo_t
            >>> # Define a local variable at offset -4
            >>> int_type = tinfo_t()
            >>> int_type.create_simple_type(BT_INT32)
            >>> db.stack_frames.define_variable(0x401000, "counter", -4, int_type)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        return ida_frame.define_stkvar(func, name=name, off=offset, tif=var_type, repr=None)

    def get_variable(self, func_ea: ea_t, offset: int) -> Optional[StackVariable]:
        """
        Get the stack variable at the specified offset.

        Args:
            func_ea: Address of the function
            offset: Frame offset

        Returns:
            StackVariable object or None if no variable at offset

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> var = db.stack_frames.get_variable(0x401000, -4)
            >>> if var:
            ...     print(f"Variable: {var.name} ({var.type})")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return None

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return None

        # Search for member at offset
        for i in range(udt_data.size()):
            member = udt_data[i]
            member_offset = ida_frame.soff_to_fpoff(func, member.offset)

            if member_offset == offset:
                is_special = member.name.startswith(' ')
                is_argument = offset >= 0

                return StackVariable(
                    name=member.name,
                    offset=offset,
                    type=member.type,
                    size=member.size,
                    is_argument=is_argument,
                    is_special=is_special,
                )

        return None

    def get_variable_by_name(self, func_ea: ea_t, name: str) -> Optional[StackVariable]:
        """
        Find a stack variable by name.

        Args:
            func_ea: Address of the function
            name: Variable name to search for

        Returns:
            StackVariable object or None if not found

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> var = db.stack_frames.get_variable_by_name(0x401000, "counter")
            >>> if var:
            ...     print(f"Offset: {var.offset}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        frame_instance = StackFrameInstance(self.database, func_ea, func)
        for var in frame_instance.variables:
            if var.name == name:
                return var

        return None

    def set_variable_type(self, func_ea: ea_t, offset: int, var_type: tinfo_t) -> bool:
        """
        Change the type of an existing stack variable.

        Args:
            func_ea: Address of the function
            offset: Frame offset of the variable
            var_type: New type information

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not valid
            LookupError: If no variable exists at offset

        Example:
            >>> ptr_type = tinfo_t()
            >>> ptr_type.create_ptr(int_type)
            >>> db.stack_frames.set_variable_type(0x401000, -4, ptr_type)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Verify variable exists and get its struct offset
        var = self.get_variable(func_ea, offset)
        if not var:
            raise LookupError(f"No variable at offset {offset}")

        # Find the struct offset by iterating through frame members
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return False

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return False

        # Search for member at FP offset and get its struct offset
        struct_offset = None
        for i in range(udt_data.size()):
            member = udt_data[i]
            member_offset = ida_frame.soff_to_fpoff(func, member.offset)
            if member_offset == offset:
                struct_offset = member.offset
                break

        if struct_offset is None:
            raise LookupError(f"No variable at offset {offset}")

        return ida_frame.set_frame_member_type(
            func, offset=struct_offset, tif=var_type, repr=None, etf_flags=0
        )

    def rename_variable(self, func_ea: ea_t, offset: int, new_name: str) -> bool:
        """
        Rename a stack variable.

        Args:
            func_ea: Address of the function
            offset: Frame offset of the variable
            new_name: New name for the variable

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not valid
            LookupError: If no variable exists at offset
            ValueError: If new_name is invalid

        Example:
            >>> db.stack_frames.rename_variable(0x401000, -4, "loop_counter")
        """
        var = self.get_variable(func_ea, offset)
        if not var:
            raise LookupError(f"No variable at offset {offset}")

        if not new_name or not new_name.strip():
            raise ValueError("Variable name cannot be empty")

        return self.define_variable(func_ea, new_name, offset, var.type)

    def delete_variable(self, func_ea: ea_t, offset: int) -> bool:
        """
        Delete a stack variable at the specified offset.

        Args:
            func_ea: Address of the function
            offset: Frame offset of the variable to delete

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> db.stack_frames.delete_variable(0x401000, -4)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Find the struct offset by iterating through frame members
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return False

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return False

        # Search for member at FP offset and get its struct offset
        struct_offset = None
        for i in range(udt_data.size()):
            member = udt_data[i]
            member_offset = ida_frame.soff_to_fpoff(func, member.offset)
            if member_offset == offset:
                struct_offset = member.offset
                break

        if struct_offset is None:
            # No variable at this offset - return False (not an error)
            return False

        # Delete single member (end = start + 1)
        return ida_frame.delete_frame_members(
            func, start_offset=struct_offset, end_offset=struct_offset + 1
        )

    def delete_variables_in_range(
        self, func_ea: ea_t, start_offset: int, end_offset: int
    ) -> int:
        """
        Delete all stack variables within an offset range.

        Args:
            func_ea: Address of the function
            start_offset: Start of range (inclusive)
            end_offset: End of range (exclusive)

        Returns:
            Number of variables deleted

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> # Delete all locals from -0x20 to -0x10
            >>> count = db.stack_frames.delete_variables_in_range(0x401000, -0x20, -0x10)
            >>> print(f"Deleted {count} variables")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Find all variables in the FP offset range and collect their struct offsets
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return 0

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return 0

        # Collect variables in range with their struct offsets
        to_delete = []
        for i in range(udt_data.size()):
            member = udt_data[i]
            fp_offset = ida_frame.soff_to_fpoff(func, member.offset)
            if start_offset <= fp_offset < end_offset:
                to_delete.append(member.offset)

        # Delete each variable individually
        count = 0
        for struct_offset in to_delete:
            if ida_frame.delete_frame_members(func, struct_offset, struct_offset + 1):
                count += 1

        return count

    def get_variable_xrefs(self, func_ea: ea_t, offset: int) -> Iterator[StackVarXref]:
        """
        Get all cross-references to a stack variable.

        Args:
            func_ea: Address of the function
            offset: Frame offset of the variable

        Yields:
            StackVarXref: Each cross-reference to the variable

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> for xref in db.stack_frames.get_variable_xrefs(0x401000, -4):
            ...     print(f"Used at 0x{xref.ea:x}, operand {xref.operand}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Find the struct offset by iterating through frame members
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            return

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return

        # Search for member at FP offset and get its struct offset
        struct_offset = None
        for i in range(udt_data.size()):
            member = udt_data[i]
            member_offset = ida_frame.soff_to_fpoff(func, member.offset)
            if member_offset == offset:
                struct_offset = member.offset
                break

        if struct_offset is None:
            return

        # Build xrefs for single variable (small range)
        xrefs = ida_frame.build_stkvar_xrefs(
            func, start_offset=struct_offset, end_offset=struct_offset + 1
        )

        for xref in xrefs:
            yield StackVarXref(ea=xref.ea, operand=xref.opnum, type=xref.type)

    def get_as_struct(self, func_ea: ea_t) -> tinfo_t:
        """
        Get the frame as a structured type (tinfo_t).

        Args:
            func_ea: Address of the function

        Returns:
            tinfo_t representing the frame as a structure

        Raises:
            InvalidEAError: If func_ea is not valid
            RuntimeError: If no frame exists

        Example:
            >>> frame_type = db.stack_frames.get_as_struct(0x401000)
            >>> udt_data = ida_typeinf.udt_type_data_t()
            >>> frame_type.get_udt_details(udt_data)
            >>> for i in range(udt_data.size()):
            ...     member = udt_data[i]
            ...     print(f"Member: {member.name} at offset {member.offset}")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, func):
            raise RuntimeError(f"No frame at 0x{func_ea:x}")

        return frame_type

    # ========================================================================
    # Offset Calculation Methods
    # ========================================================================

    def calc_runtime_offset(self, func_ea: ea_t, frame_offset: int, insn_ea: ea_t) -> int:
        """
        Convert frame offset to runtime SP/FP-relative offset at specific instruction.

        Args:
            func_ea: Address of the function
            frame_offset: Offset in frame structure
            insn_ea: Address of the instruction

        Returns:
            Runtime offset relative to SP or FP

        Raises:
            InvalidEAError: If func_ea or insn_ea is not valid

        Example:
            >>> # Frame offset -4 might be [ebp-4] or [esp+0xC] depending on context
            >>> runtime_offset = db.stack_frames.calc_runtime_offset(0x401000, -4, 0x401010)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Get SP delta at instruction
        sp_delta = ida_frame.get_spd(func, insn_ea)

        # Calculate runtime offset
        runtime_offset = frame_offset - sp_delta

        return runtime_offset

    def calc_frame_offset(self, func_ea: ea_t, runtime_offset: int, insn_ea: ea_t) -> int:
        """
        Convert runtime SP/FP-relative offset to frame offset.

        Args:
            func_ea: Address of the function
            runtime_offset: Offset relative to SP or FP in the instruction
            insn_ea: Address of the instruction

        Returns:
            Offset in frame structure

        Raises:
            InvalidEAError: If func_ea or insn_ea is not valid

        Example:
            >>> # [esp+0x10] might be frame offset +8 (argument)
            >>> frame_offset = db.stack_frames.calc_frame_offset(0x401000, 0x10, 0x401010)
            >>> var = db.stack_frames.get_variable(0x401000, frame_offset)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        # Use IDA's calc_frame_offset which handles complex cases
        import ida_ua

        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, insn_ea)

        frame_offset = ida_frame.calc_frame_offset(func, off=runtime_offset, insn=insn, op=None)

        return frame_offset

    def generate_auto_name(self, func_ea: ea_t, offset: int) -> str:
        """
        Generate automatic variable name based on offset.

        Args:
            func_ea: Address of the function
            offset: Frame offset

        Returns:
            Auto-generated name (e.g., "var_4", "arg_8")

        Raises:
            InvalidEAError: If func_ea is not valid

        Example:
            >>> name = db.stack_frames.generate_auto_name(0x401000, -4)  # Returns "var_4"
            >>> name = db.stack_frames.generate_auto_name(0x401000, 8)   # Returns "arg_8"
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        name = ida_frame.build_stkvar_name(func, offset)
        return name if name else ""

    # ========================================================================
    # SP Tracking Methods
    # ========================================================================

    def add_sp_change_point(
        self, func_ea: ea_t, ea: ea_t, delta: int, automatic: bool = False
    ) -> bool:
        """
        Add a stack pointer change point.

        Args:
            func_ea: Address of the function
            ea: Address where SP changes (usually end of instruction)
            delta: Change in SP value (negative = stack grows)
            automatic: True for automatic point (IDA-managed), False for user-defined

        Returns:
            True if successful

        Raises:
            InvalidEAError: If func_ea or ea is not valid

        Example:
            >>> # Manual correction: at 0x401010, SP decreases by 4
            >>> db.stack_frames.add_sp_change_point(0x401000, 0x401010, -4, automatic=False)
        """
        if automatic:
            func = ida_funcs.get_func(func_ea)
            if not func:
                raise InvalidEAError(func_ea)
            return ida_frame.add_auto_stkpnt(func, ea, delta)
        else:
            return ida_frame.add_user_stkpnt(ea, delta)

    def delete_sp_change_point(self, func_ea: ea_t, ea: ea_t) -> bool:
        """
        Delete a stack pointer change point.

        Args:
            func_ea: Address of the function
            ea: Address of the change point

        Returns:
            True if point was deleted

        Raises:
            InvalidEAError: If func_ea or ea is not valid

        Example:
            >>> db.stack_frames.delete_sp_change_point(0x401000, 0x401010)
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        return ida_frame.del_stkpnt(func, ea)

    def get_sp_delta(self, func_ea: ea_t, ea: ea_t) -> int:
        """
        Get the cumulative SP delta at an instruction (before execution).

        Args:
            func_ea: Address of the function
            ea: Address of the instruction

        Returns:
            Cumulative SP delta (usually negative for downward-growing stack)

        Raises:
            InvalidEAError: If func_ea or ea is not valid

        Example:
            >>> delta = db.stack_frames.get_sp_delta(0x401000, 0x401010)
            >>> print(f"SP is {-delta} bytes below entry point")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        return ida_frame.get_spd(func, ea)

    def get_sp_change(self, func_ea: ea_t, ea: ea_t) -> int:
        """
        Get the SP modification made at a specific location.

        Args:
            func_ea: Address of the function
            ea: Address to check

        Returns:
            Delta if change point exists, 0 otherwise

        Raises:
            InvalidEAError: If func_ea or ea is not valid

        Example:
            >>> change = db.stack_frames.get_sp_change(0x401000, 0x401010)
            >>> if change != 0:
            ...     print(f"SP changes by {change} at this location")
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            raise InvalidEAError(func_ea)

        return ida_frame.get_sp_delta(func, ea)


# ============================================================================
# StackFrameInstance
# ============================================================================


class StackFrameInstance:
    """
    Instance of a stack frame for a specific function.

    Provides property-based access to frame information including size,
    variables, and sections. This class is created by StackFrames.get_at()
    and should not be instantiated directly.

    Note:
        This class does not inherit from DatabaseEntity and is not decorated
        with @check_db_open because it's created by StackFrames which already
        performs the database check.
    """

    def __init__(self, database: Database, func_ea: ea_t, func: ida_funcs.func_t) -> None:
        """
        Initialize a stack frame instance.

        Args:
            database: Database reference
            func_ea: Function address
            func: Function object from IDA
        """
        self._database = database
        self._func_ea = func_ea
        self._func = func

    # ========================================================================
    # Properties - Frame Dimensions
    # ========================================================================

    @property
    def size(self) -> int:
        """
        Total size of the function's stack frame in bytes.

        This includes local variables, saved registers, return address,
        and purged bytes.

        Returns:
            Total frame size in bytes

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"Frame size: {frame.size} bytes")
        """
        return ida_frame.get_frame_size(self._func)

    @property
    def local_size(self) -> int:
        """
        Size of the local variables section in bytes.

        Returns:
            Number of bytes allocated for local variables

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"Local variables: {frame.local_size} bytes")
        """
        return self._func.frsize if self._func else 0

    @property
    def argument_size(self) -> int:
        """
        Size of the function arguments section in bytes.

        Only includes arguments passed on the stack; register arguments
        are not counted.

        Returns:
            Total size of stack-based arguments in bytes

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"Stack arguments: {frame.argument_size} bytes")
        """
        # Get arguments section range
        range_obj = ida_range.range_t()
        ida_frame.get_frame_part(range_obj, self._func, ida_frame.FPC_ARGS)
        return range_obj.end_ea - range_obj.start_ea

    @property
    def saved_registers_size(self) -> int:
        """
        Size of the saved registers section in bytes.

        Returns:
            Number of bytes used to save registers (e.g., EBP, ESI, EDI)

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"Saved registers: {frame.saved_registers_size} bytes")
        """
        return self._func.frregs if self._func else 0

    @property
    def return_address_size(self) -> int:
        """
        Size of the return address in bytes.

        Returns:
            Return address size (typically 4 for 32-bit, 8 for 64-bit)

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"Return address: {frame.return_address_size} bytes")
        """
        return ida_frame.get_frame_retsize(self._func)

    @property
    def purged_bytes(self) -> int:
        """
        Number of bytes purged from stack upon return (calling convention).

        For __cdecl, this is zero (caller cleans stack). For __stdcall and
        __fastcall, this is non-zero (callee cleans stack).

        Returns:
            Bytes cleaned by callee upon return

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> if frame.purged_bytes > 0:
            ...     print(f"__stdcall: purges {frame.purged_bytes} bytes")
        """
        return self._func.argsize if self._func else 0

    @property
    def frame_pointer_delta(self) -> int:
        """
        Delta between frame pointer and base pointer.

        The FPD (frame pointer delta) is the distance from BP to the
        actual frame base.

        Returns:
            FPD value

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> print(f"FP delta: {frame.frame_pointer_delta}")
        """
        return self._func.fpd if self._func else 0

    # ========================================================================
    # Properties - Variable Iterators
    # ========================================================================

    @property
    def variables(self) -> Iterator[StackVariable]:
        """
        Iterate over all stack variables (arguments and locals).

        Yields:
            StackVariable: Each variable in the frame

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> for var in frame.variables:
            ...     print(f"{var.name} at offset {var.offset}: {var.type}")
        """
        frame_type = tinfo_t()
        if not ida_frame.get_func_frame(frame_type, self._func):
            return

        udt_data = ida_typeinf.udt_type_data_t()
        if not frame_type.get_udt_details(udt_data):
            return

        for i in range(udt_data.size()):
            member = udt_data[i]

            # Calculate actual offset (convert from struct offset)
            offset = ida_frame.soff_to_fpoff(self._func, member.offset)

            # Check if special member by name (return address, saved registers)
            # Special members typically have names starting with space like " r" or " s"
            is_special = member.name.startswith(' ')

            # Determine if argument or local
            is_argument = offset >= 0

            yield StackVariable(
                name=member.name,
                offset=offset,
                type=member.type,
                size=member.size,
                is_argument=is_argument,
                is_special=is_special,
            )

    @property
    def arguments(self) -> Iterator[StackVariable]:
        """
        Iterate over function arguments (positive frame offsets).

        Yields:
            StackVariable: Each argument variable

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> for arg in frame.arguments:
            ...     print(f"Argument: {arg.name} ({arg.type})")
        """
        for var in self.variables:
            if var.is_argument and not var.is_special:
                yield var

    @property
    def locals(self) -> Iterator[StackVariable]:
        """
        Iterate over local variables (negative frame offsets).

        Yields:
            StackVariable: Each local variable

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> for local in frame.locals:
            ...     print(f"Local: {local.name} at offset {local.offset}")
        """
        for var in self.variables:
            if not var.is_argument and not var.is_special:
                yield var

    @property
    def stack_points(self) -> Iterator[StackPoint]:
        """
        Iterate over stack pointer change points.

        Yields:
            StackPoint: Each SP change point in the function

        Example:
            >>> frame = db.stack_frames.get_at(0x401000)
            >>> for sp in frame.stack_points:
            ...     print(f"SP changes by {sp.sp_delta} at 0x{sp.ea:x}")
        """
        for i in range(self._func.pntqty):
            pnt = self._func.points[i]
            yield StackPoint(ea=pnt.ea, sp_delta=pnt.spd)
