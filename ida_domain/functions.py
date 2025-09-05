from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Flag

import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_typeinf
import ida_ua
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional

import ida_domain
import ida_domain.flowchart

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .flowchart import FlowChart, FlowChartFlags

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


class FunctionFlags(Flag):
    """Function attribute flags from IDA SDK."""

    NORET = ida_funcs.FUNC_NORET  # Function doesn't return
    FAR = ida_funcs.FUNC_FAR  # Far function
    LIB = ida_funcs.FUNC_LIB  # Library function
    STATICDEF = ida_funcs.FUNC_STATICDEF  # Static function
    FRAME = ida_funcs.FUNC_FRAME  # Function uses frame pointer (BP)
    USERFAR = ida_funcs.FUNC_USERFAR  # User has specified far-ness of the function
    HIDDEN = ida_funcs.FUNC_HIDDEN  # A hidden function chunk
    THUNK = ida_funcs.FUNC_THUNK  # Thunk (jump) function
    BOTTOMBP = ida_funcs.FUNC_BOTTOMBP  # BP points to the bottom of the stack frame
    NORET_PENDING = ida_funcs.FUNC_NORET_PENDING  # Function 'non-return' analysis needed
    SP_READY = ida_funcs.FUNC_SP_READY  # SP-analysis has been performed
    FUZZY_SP = ida_funcs.FUNC_FUZZY_SP  # Function changes SP in untraceable way
    PROLOG_OK = ida_funcs.FUNC_PROLOG_OK  # Prolog analysis has been performed
    PURGED_OK = ida_funcs.FUNC_PURGED_OK  # 'argsize' field has been validated
    TAIL = ida_funcs.FUNC_TAIL  # This is a function tail
    LUMINA = ida_funcs.FUNC_LUMINA  # Function info is provided by Lumina
    OUTLINE = ida_funcs.FUNC_OUTLINE  # Outlined code, not a real function
    REANALYZE = ida_funcs.FUNC_REANALYZE  # Function frame changed, request to reanalyze
    UNWIND = ida_funcs.FUNC_UNWIND  # Function is an exception unwind handler
    CATCH = ida_funcs.FUNC_CATCH  # Function is an exception catch handler


@dataclass
class StackPoint:
    """Stack pointer change information."""

    ea: ea_t  # Address where SP changes
    sp_delta: int  # Stack pointer delta at this point


@dataclass
class TailInfo:
    """Function tail chunk information."""

    owner_ea: ea_t  # Address of owning function
    owner_name: str  # Name of owning function


@dataclass
class FunctionChunk:
    """Represents a function chunk (main or tail)."""

    start_ea: ea_t
    end_ea: ea_t
    is_main: bool


@decorate_all_methods(check_db_open)
class Functions(DatabaseEntity):
    """
    Provides access to function-related operations within the IDA database.

    This class handles function discovery, analysis, manipulation, and provides
    access to function properties like names, signatures, basic blocks, and pseudocode.

    Can be used to iterate over all functions in the opened database.

    Args:
        database: Reference to the active IDA database.

    Note:
        Since this class does not manage the lifetime of IDA kernel objects (func_t*),
        it is recommended to use these pointers within a limited scope. Obtain the pointer,
        perform the necessary operations, and avoid retaining references beyond the
        immediate context to prevent potential issues with object invalidation.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[func_t]:
        return self.get_all()

    def __len__(self) -> int:
        """Return the total number of functions in the database.

        Returns:
            int: The number of functions in the program.
        """
        return ida_funcs.get_func_qty()

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[func_t]:
        """
        Retrieves functions within the specified address range.

        Args:
            start_ea: Start address of the range (inclusive).
            end_ea: End address of the range (exclusive).

        Yields:
            Function objects whose start address falls within the specified range.

        Raises:
            InvalidEAError: If the start_ea/end_ea are specified but they are not
            in the database range.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue

            if func.start_ea >= end_ea:
                # Functions are typically ordered by address, so we can break early
                break

            if start_ea <= func.start_ea < end_ea:
                yield func

    def get_all(self) -> Iterator[func_t]:
        """
        Retrieves all functions in the database.

        Returns:
            An iterator over all functions in the database.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_at(self, ea: ea_t) -> Optional[func_t]:
        """
        Retrieves the function that contains the given address.

        Args:
            ea: An effective address within the function body.

        Returns:
            The function object containing the address,
            or None if no function exists at that address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.get_func(ea)

    def set_name(self, func: func_t, name: str, auto_correct: bool = True) -> bool:
        """
        Renames the given function.

        Args:
            func: The function instance.
            name: The new name to assign to the function.
            auto_correct: If True, allows IDA to replace invalid characters automatically.

        Returns:
            True if the function was successfully renamed, False otherwise.

        Raises:
            InvalidParameterError: If the name parameter is empty or invalid.
        """
        if not name.strip():
            raise InvalidParameterError('name', name, 'The name parameter cannot be empty')

        flags = ida_name.SN_NOCHECK if auto_correct else ida_name.SN_CHECK
        return ida_name.set_name(func.start_ea, name, flags)

    def get_flowchart(
        self, func: func_t, flags: FlowChartFlags = FlowChartFlags.NONE
    ) -> Optional[FlowChart]:
        """
        Retrieves the flowchart of the specified function,
        which the user can use to retrieve basic blocks.

        Args:
            func: The function instance.

        Returns:
            An iterator over the function's basic blocks, or empty iterator if function is invalid.
        """
        return ida_domain.flowchart.FlowChart(self.database, func, None, flags)

    def get_instructions(self, func: func_t) -> Optional[Iterator[insn_t]]:
        """
        Retrieves all instructions within the given function.

        Args:
            func: The function instance.

        Returns:
            An iterator over all instructions in the function,
            or empty iterator if function is invalid.
        """
        return self.database.instructions.get_between(func.start_ea, func.end_ea)

    def get_disassembly(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the disassembly lines for the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of disassembly.
            Returns empty list if function is invalid.
        """
        lines = []
        ea = func.start_ea

        options = ida_lines.GENDSM_MULTI_LINE
        if remove_tags:
            options |= ida_lines.GENDSM_REMOVE_TAGS

        while ea != BADADDR and ea < func.end_ea:
            line = ida_lines.generate_disasm_line(ea, options)
            if line:
                lines.append(line)

            ea = ida_bytes.next_head(ea, func.end_ea)

        return lines

    def get_pseudocode(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the decompiled pseudocode of the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of pseudocode. Returns empty list if
            function is invalid or decompilation fails.

        Raises:
            RuntimeError: If decompilation fails for the function.
        """
        # Attempt to decompile the function
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RuntimeError(f'Failed to decompile function at 0x{func.start_ea:x}')

        # Extract pseudocode lines
        pseudocode = []
        sv = cfunc.get_pseudocode()
        for i in range(len(sv)):
            line = sv[i].line
            if remove_tags:
                line = ida_lines.tag_remove(line)
            pseudocode.append(line)
        return pseudocode

    def get_microcode(self, func: func_t, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the microcode of the given function.

        Args:
            func: The function instance.
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of microcode. Returns empty list if
            function is invalid or decompilation fails.

        Raises:
            RuntimeError: If microcode generation fails for the function.
        """
        return self.database.bytes.get_microcode_between(func.start_ea, func.end_ea, remove_tags)

    def get_signature(self, func: func_t) -> str:
        """
        Retrieves the function's type signature.

        Args:
            func: The function instance.

        Returns:
            The function signature as a string,
            or empty string if unavailable or function is invalid.
        """
        return ida_typeinf.idc_get_type(func.start_ea)

    def get_name(self, func: func_t) -> str:
        """
        Retrieves the function's name.

        Args:
            func: The function instance.

        Returns:
            The function name as a string, or empty string if no name is set.
        """
        name = self.database.names.get_at(func.start_ea)
        return name if name is not None else ''

    def create(self, ea: ea_t) -> bool:
        """
        Creates a new function at the specified address.

        Args:
            ea: The effective address where the function should start.

        Returns:
            True if the function was successfully created, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.add_func(ea)

    def remove(self, ea: ea_t) -> bool:
        """
        Removes the function at the specified address.

        Args:
            ea: The effective address of the function to remove.

        Returns:
            True if the function was successfully removed, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.del_func(ea)

    def get_next(self, ea: int) -> Optional[func_t]:
        """
        Get the next function after the given address.

        Args:
            ea: Address to search from

        Returns:
            Next function after ea, or None if no more functions

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)
        return ida_funcs.get_next_func(ea)

    def get_chunk_at(self, ea: int) -> Optional[func_t]:
        """
        Get function chunk at exact address.

        Args:
            ea: Address within function chunk

        Returns:
            Function chunk or None

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ida_funcs.get_fchunk(ea)

    def is_entry_chunk(self, chunk: func_t) -> bool:
        """
        Check if chunk is entry chunk.

        Args:
            chunk: Function chunk to check

        Returns:
            True if this is an entry chunk, False otherwise
        """
        return ida_funcs.is_func_entry(chunk)

    def is_tail_chunk(self, chunk: func_t) -> bool:
        """
        Check if chunk is tail chunk.

        Args:
            chunk: Function chunk to check

        Returns:
            True if this is a tail chunk, False otherwise
        """
        return ida_funcs.is_func_tail(chunk)

    def get_flags(self, func: func_t) -> FunctionFlags:
        """
        Get function attribute flags.

        Args:
            func: Function object

        Returns:
            FunctionFlags enum with all active flags
        """
        return FunctionFlags(func.flags)

    def is_far(self, func: func_t) -> bool:
        """
        Check if function is far.

        Args:
            func: Function object

        Returns:
            True if function is far, False otherwise
        """
        return func.is_far()

    def does_return(self, func: func_t) -> bool:
        """
        Check if function returns.

        Args:
            func: Function object

        Returns:
            True if function returns, False if it's noreturn
        """
        return func.does_return()

    def get_callers(self, func: func_t) -> List[func_t]:
        """
        Gets all functions that call this function.

        Args:
            func: The function instance.

        Returns:
            List of calling functions.
        """
        callers: List[func_t] = []
        caller_addrs = set()  # Use set to avoid duplicates

        # Get all call references to this function
        for caller_ea in self.database.xrefs.calls_to_ea(func.start_ea):
            # Get the function containing this call site
            caller_func = self.get_at(caller_ea)
            if caller_func and caller_func.start_ea not in caller_addrs:
                caller_addrs.add(caller_func.start_ea)
                callers.append(caller_func)

        return callers

    def get_callees(self, func: func_t) -> List[func_t]:
        """
        Gets all functions called by this function.

        Args:
            func: The function instance.

        Returns:
            List of called functions.
        """
        callees: list[func_t] = []
        callee_addrs = set()  # Use set to avoid duplicates

        # Iterate through all instructions in the function to find calls and jumps
        for inst in self.database.instructions.get_between(func.start_ea, func.end_ea):
            # Get call references from this instruction
            for target_ea in self.database.xrefs.calls_from_ea(inst.ea):
                # Get the target function
                target_func = self.get_at(target_ea)
                if target_func and target_func.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_func.start_ea != func.start_ea:
                        callee_addrs.add(target_func.start_ea)
                        callees.append(target_func)

            # Also get jump references for tail calls
            for target_ea in self.database.xrefs.jumps_from_ea(inst.ea):
                # Get the target function
                target_func = self.get_at(target_ea)
                if target_func and target_func.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_func.start_ea != func.start_ea:
                        callee_addrs.add(target_func.start_ea)
                        callees.append(target_func)

        return callees

    def get_function_by_name(self, name: str) -> Optional[func_t]:
        """
        Find a function by its name.

        Args:
            name: Function name to search for

        Returns:
            Function object if found, None otherwise
        """
        func_ea = ida_name.get_name_ea(BADADDR, name)
        if func_ea != BADADDR:
            return ida_funcs.get_func(func_ea)
        return None

    def get_tails(self, func: func_t) -> List[func_t]:
        """
        Get all tail chunks of a function.

        Args:
            func: Function object (must be entry chunk)

        Returns:
            List of tail chunks, empty if not entry chunk
        """
        if not ida_funcs.is_func_entry(func):
            return []

        tails = []
        for i in range(func.tailqty):
            tails.append(func.tails[i])
        return tails

    def get_stack_points(self, func: func_t) -> List[StackPoint]:
        """
        Get function stack points for SP tracking.

        Args:
            func: Function object

        Returns:
            List of StackPoint objects showing where SP changes
        """
        points = []
        for i in range(func.pntqty):
            pnt = func.points[i]
            points.append(StackPoint(ea=pnt.ea, sp_delta=pnt.spd))
        return points

    def get_tail_info(self, chunk: func_t) -> Optional[TailInfo]:
        """
        Get information about tail chunk's owner function.

        Args:
            chunk: Function chunk (must be tail chunk)

        Returns:
            TailInfo with owner details, or None if not a tail chunk
        """
        if not ida_funcs.is_func_tail(chunk):
            return None

        owner_name = ''
        if chunk.owner != BADADDR:
            owner_name = self.database.names.get_at(chunk.owner) or ''

        return TailInfo(owner_ea=chunk.owner, owner_name=owner_name)

    def get_data_items(self, func: func_t) -> Iterator[ea_t]:
        """
        Iterate over data items within the function.

        This method finds all addresses within the function that are defined
        as data (not code). Useful for finding embedded data, jump tables,
        or other non-code items within function boundaries.

        Args:
            func: The function object

        Yields:
            Addresses of data items within the function

        Example:
            ```python
            >>> func = db.functions.get_at(0x401000)
            >>> for data_ea in db.functions.get_data_items(func):
            ...     size = ida_bytes.get_item_size(data_ea)
            ...     print(f"Data at 0x{data_ea:x}, size: {size}")
            ```
        """
        ea = func.start_ea
        while ea < func.end_ea and ea != BADADDR:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_data(flags):
                yield ea
            ea = ida_bytes.next_head(ea, func.end_ea)

    def get_chunks(self, func: func_t) -> Iterator[FunctionChunk]:
        """
        Get all chunks (main and tail) of a function.

        Args:
            func: The function to analyze.

        Yields:
            FunctionChunk objects representing each chunk.
        """
        # Main chunk
        yield FunctionChunk(start_ea=func.start_ea, end_ea=func.end_ea, is_main=True)

        # Tail chunks
        for tail in ida_funcs.func_tail_iterator_t(func):
            if tail.start_ea != func.start_ea:  # Skip main chunk
                yield FunctionChunk(start_ea=tail.start_ea, end_ea=tail.end_ea, is_main=False)

    def is_chunk_at(self, ea: ea_t) -> bool:
        """
        Check if the given address belongs to a function chunk.

        Args:
            ea: The address to check.

        Returns:
            True if the address is in a function chunk.
        """
        func = ida_funcs.get_func(ea)
        chunk = ida_funcs.get_fchunk(ea)
        return chunk is not None and (func != chunk)

    def set_comment(self, func: func_t, comment: str, repeatable: bool = False) -> bool:
        """
        Set comment for function.

        Args:
            func: The function to set comment for.
            comment: Comment text to set.
            repeatable: If True, creates a repeatable comment (shows at all identical operands).
                        If False, creates a non-repeatable comment (shows only at this function).

        Returns:
            True if successful, False otherwise.
        """
        return ida_funcs.set_func_cmt(func, comment, repeatable)

    def get_comment(self, func: func_t, repeatable: bool = False) -> str:
        """
        Get comment for function.

        Args:
            func: The function to get comment from.
            repeatable: If True, retrieves repeatable comment (shows at all identical operands).
                        If False, retrieves non-repeatable comment (shows only at this function).

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return ida_funcs.get_func_cmt(func, repeatable) or ''
