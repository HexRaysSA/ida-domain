from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass
from enum import Flag

import ida_bytes
import ida_funcs
import ida_lines
import ida_name
import ida_typeinf
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional, Union, deprecated

import ida_domain
import ida_domain.flowchart

from . import _ida_compat
from .base import (
    DatabaseEntity,
    DecompilerError,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)
from .flowchart import FlowChart, FlowChartFlags
from .pseudocode import (
    LocalVariable,
    LocalVariableAccessType,
    LocalVariableContext,
    LocalVariableReference,
    PseudocodeFunction,
)

if TYPE_CHECKING:
    from .database import Database
    from .microcode import MicroBlockArray

logger = logging.getLogger(__name__)


class FunctionFlags(Flag):
    """Function attribute flags from IDA SDK."""

    NORET = ida_funcs.FUNC_NORET
    """Function doesn't return"""
    FAR = ida_funcs.FUNC_FAR
    """Far function"""
    LIB = ida_funcs.FUNC_LIB
    """Library function"""
    STATICDEF = ida_funcs.FUNC_STATICDEF
    """Static function"""
    FRAME = ida_funcs.FUNC_FRAME
    """Function uses frame pointer (BP)"""
    USERFAR = ida_funcs.FUNC_USERFAR
    """User has specified far-ness of the function"""
    HIDDEN = ida_funcs.FUNC_HIDDEN
    """A hidden function chunk"""
    THUNK = ida_funcs.FUNC_THUNK
    """Thunk (jump) function"""
    BOTTOMBP = ida_funcs.FUNC_BOTTOMBP
    """BP points to the bottom of the stack frame"""
    NORET_PENDING = ida_funcs.FUNC_NORET_PENDING
    """Function 'non-return' analysis needed"""
    SP_READY = ida_funcs.FUNC_SP_READY
    """SP-analysis has been performed"""
    FUZZY_SP = ida_funcs.FUNC_FUZZY_SP
    """Function changes SP in untraceable way"""
    PROLOG_OK = ida_funcs.FUNC_PROLOG_OK
    """Prolog analysis has been performed"""
    PURGED_OK = ida_funcs.FUNC_PURGED_OK
    """'argsize' field has been validated"""
    TAIL = ida_funcs.FUNC_TAIL
    """This is a function tail"""
    LUMINA = ida_funcs.FUNC_LUMINA
    """Function info is provided by Lumina"""
    OUTLINE = ida_funcs.FUNC_OUTLINE
    """Outlined code, not a real function"""
    REANALYZE = ida_funcs.FUNC_REANALYZE
    """Function frame changed, request to reanalyze"""
    UNWIND = ida_funcs.FUNC_UNWIND
    """Function is an exception unwind handler"""
    CATCH = ida_funcs.FUNC_CATCH
    """Function is an exception catch handler"""


@dataclass
class StackPoint:
    """Stack pointer change information."""

    ea: ea_t
    """Address where SP changes"""
    sp_delta: int
    """Stack pointer delta at this point"""


@dataclass
class TailInfo:
    """Function tail chunk information."""

    owner_ea: ea_t
    """Address of owning function"""
    owner_name: str
    """Name of owning function"""


@dataclass
class FunctionChunk:
    """Represents a function chunk (main or tail)."""

    start_ea: ea_t
    """Start address of the function chunk"""
    end_ea: ea_t
    """End address of the function chunk"""
    is_main: bool
    """True if is the function main chunk"""


@dataclass(frozen=True)
class FunctionInfo:
    """Value snapshot of a function.

    Not a live handle - fields reflect the database at retrieval time and do
    not track later changes. Pass it (or any address inside the function) back
    to :class:`Functions` methods; they re-resolve the function by address.
    """

    start_ea: ea_t
    """Start address of the function (entry chunk)"""
    end_ea: ea_t
    """End address of the function main chunk (exclusive)"""
    flags: FunctionFlags
    """Function attribute flags"""
    name: str
    """Function name"""

    def __contains__(self, ea: ea_t) -> bool:
        """Check if an address lies within the function main chunk."""
        return self.start_ea <= ea < self.end_ea

    @property
    def size(self) -> int:
        """Size of the function main chunk in bytes."""
        return self.end_ea - self.start_ea

    @deprecated('func_t is deprecated; use EAs or FunctionInfo with ida-domain APIs')
    def to_func_t(self) -> Optional[func_t]:
        """Return the live ``func_t`` for this function.

        Escape hatch for SDK APIs that still take a ``func_t`` pointer.
        The pointer is invalidated by function creation/deletion, boundary
        changes, and undo - use it immediately and do not retain it.

        Returns:
            The ``func_t`` at this snapshot's start address, or None if
            the function no longer exists.
        """
        return ida_funcs.get_func(self.start_ea)


FunctionLike = Union[FunctionInfo, func_t, ea_t]
"""A function reference: a FunctionInfo snapshot, any address inside the
function, or (deprecated) a func_t."""

ChunkLike = Union[FunctionChunk, func_t, ea_t]
"""A chunk reference: a FunctionChunk, any address inside the chunk, or
(deprecated) a func_t."""


def _func_info_at(ea: ea_t) -> Optional[FunctionInfo]:
    """Build a FunctionInfo snapshot of the function containing ``ea``."""
    info = _ida_compat.func_entry_info_at(ea)
    if info is None:
        return None
    start_ea, end_ea, flags, name = info
    return FunctionInfo(start_ea=start_ea, end_ea=end_ea, flags=FunctionFlags(flags), name=name)


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
        Methods return :class:`FunctionInfo` value snapshots, not live handles.
        A snapshot reflects the database at retrieval time; it stays safe to
        hold but does not track later changes. Methods accept a snapshot, a
        raw address inside the function, or (deprecated) a ``func_t`` - they
        always re-resolve the function by address before operating on it.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def _resolve_ea(self, func: FunctionLike) -> ea_t:
        """Normalize ``func`` to an effective address and validate it.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        ea = _ida_compat.func_ea(func)
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return ea

    def _resolve_start(self, func: FunctionLike) -> ea_t:
        """Normalize ``func`` to the start address of the containing function.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        ea = self._resolve_ea(func)
        start_ea = _ida_compat.get_func_start(ea)
        if start_ea == BADADDR:
            raise InvalidEAError(ea)
        return start_ea

    def _resolve_info(self, func: FunctionLike) -> FunctionInfo:
        """Normalize ``func`` to a fresh snapshot of the containing function.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        ea = self._resolve_ea(func)
        info = _func_info_at(ea)
        if info is None:
            raise InvalidEAError(ea)
        return info

    def __iter__(self) -> Iterator[FunctionInfo]:
        return self.get_all()

    def __len__(self) -> int:
        """Return the total number of functions in the database.

        Returns:
            int: The number of functions in the program.
        """
        return ida_funcs.get_func_qty()

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[FunctionInfo]:
        """
        Retrieves functions within the specified address range.

        Args:
            start_ea: Start address of the range (inclusive).
            end_ea: End address of the range (exclusive).

        Yields:
            FunctionInfo snapshots of functions whose start address falls
            within the specified range.

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
            func_ea = _ida_compat.get_func_ea_by_num(i)
            if func_ea == BADADDR:
                continue

            if func_ea >= end_ea:
                # Functions are typically ordered by address, so we can break early
                break

            if func_ea >= start_ea:
                info = _func_info_at(func_ea)
                if info is not None:
                    yield info

    def get_all(self) -> Iterator[FunctionInfo]:
        """
        Retrieves all functions in the database.

        Returns:
            An iterator over all functions in the database.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_at(self, ea: ea_t) -> Optional[FunctionInfo]:
        """
        Retrieves the function that contains the given address.

        Args:
            ea: An effective address within the function body.

        Returns:
            A FunctionInfo snapshot of the function containing the address,
            or None if no function exists at that address.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        return _func_info_at(ea)

    def set_name(self, func: FunctionLike, name: str, auto_correct: bool = True) -> bool:
        """
        Renames the given function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            name: The new name to assign to the function.
            auto_correct: If True, allows IDA to replace invalid characters automatically.

        Returns:
            True if the function was successfully renamed, False otherwise.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
            InvalidParameterError: If the name parameter is empty or invalid.
        """
        if not name.strip():
            raise InvalidParameterError('name', name, 'The name parameter cannot be empty')

        flags = ida_name.SN_NOCHECK if auto_correct else ida_name.SN_CHECK
        return ida_name.set_name(self._resolve_start(func), name, flags)

    def get_flowchart(
        self,
        func: FunctionLike,
        flags: FlowChartFlags = FlowChartFlags.NONE,
    ) -> Optional[FlowChart]:
        """
        Retrieves the flowchart of the specified function,
        which the user can use to retrieve basic blocks.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            An iterator over the function's basic blocks, or empty iterator if function is invalid.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        return ida_domain.flowchart.FlowChart(self.database, self._resolve_ea(func), None, flags)

    def get_instructions(self, func: FunctionLike) -> Iterator[insn_t]:
        """
        Retrieves all instructions within the given function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            An iterator over all instructions in the function main chunk.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        info = self._resolve_info(func)
        return self.database.instructions.get_between(info.start_ea, info.end_ea)

    def get_disassembly(self, func: FunctionLike, remove_tags: bool = True) -> List[str]:
        """
        Retrieves the disassembly lines for the given function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            remove_tags: If True, removes IDA color/formatting tags from the output.

        Returns:
            A list of strings, each representing a line of disassembly.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        info = self._resolve_info(func)

        lines = []
        ea = info.start_ea

        options = ida_lines.GENDSM_MULTI_LINE
        if remove_tags:
            options |= ida_lines.GENDSM_REMOVE_TAGS

        while ea != BADADDR and ea < info.end_ea:
            line = ida_lines.generate_disasm_line(ea, options)
            if line:
                lines.append(line)

            ea = ida_bytes.next_head(ea, info.end_ea)

        return lines

    def get_pseudocode(self, func: FunctionLike) -> PseudocodeFunction:
        """
        Decompiles the given function and returns the pseudocode result.

        Delegates to ``db.pseudocode.decompile()``.

        The returned object provides full ctree access.  To get the
        pseudocode as plain text, call ``str()`` or ``to_text()``:

        ```python
        pseudo = db.functions.get_pseudocode(func)
        print(str(pseudo))           # full text
        print(pseudo.to_text())      # list of lines
        ```

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            A :class:`~ida_domain.pseudocode.PseudocodeFunction` wrapping the
            decompiled result.

        Raises:
            PseudocodeError: If decompilation fails for the function.
        """
        return self.database.pseudocode.decompile(_ida_compat.func_ea(func))

    def get_microcode(self, func: FunctionLike) -> MicroBlockArray:
        """
        Generates microcode for the given function.

        Delegates to ``db.microcode.generate()``.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            A :class:`~ida_domain.microcode.MicroBlockArray` representing the
            generated microcode.

        Raises:
            MicrocodeError: If microcode generation fails for the function.
        """
        return self.database.microcode.generate(_ida_compat.func_ea(func))

    def get_signature(self, func: FunctionLike) -> Optional[str]:
        """
        Retrieves the function's type signature.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            The function signature as a string, or ``None`` if no type
            is stored for this function.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        return ida_typeinf.idc_get_type(self._resolve_start(func))

    def get_name(self, func: FunctionLike) -> str:
        """
        Retrieves the function's name.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            The function name as a string, or empty string if no name is set.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        name = self.database.names.get_at(self._resolve_start(func))
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

    def get_next(self, ea: int) -> Optional[FunctionInfo]:
        """
        Get the next function after the given address.

        Args:
            ea: Address to search from

        Returns:
            FunctionInfo snapshot of the next function after ea,
            or None if no more functions

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)
        next_ea = _ida_compat.get_next_func_ea(ea)
        if next_ea == BADADDR:
            return None
        return _func_info_at(next_ea)

    def get_chunk_at(self, ea: int) -> Optional[FunctionChunk]:
        """
        Get function chunk at exact address.

        Args:
            ea: Address within function chunk

        Returns:
            FunctionChunk describing the chunk containing ea, or None

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        chunk = _ida_compat.fchunk_at(ea)
        if chunk is None:
            return None
        start_ea, end_ea, is_tail = chunk
        return FunctionChunk(start_ea=start_ea, end_ea=end_ea, is_main=not is_tail)

    def is_entry_chunk(self, chunk: ChunkLike) -> bool:
        """
        Check if chunk is entry chunk.

        Args:
            chunk: The chunk (FunctionChunk, any address inside it, or func_t).

        Returns:
            True if this is an entry chunk, False otherwise
        """
        return _ida_compat.is_function_entry(_ida_compat.func_ea(chunk))

    def is_tail_chunk(self, chunk: ChunkLike) -> bool:
        """
        Check if chunk is tail chunk.

        Args:
            chunk: The chunk (FunctionChunk, any address inside it, or func_t).

        Returns:
            True if this is a tail chunk, False otherwise
        """
        return _ida_compat.is_function_tail(_ida_compat.func_ea(chunk))

    def get_flags(self, func: FunctionLike) -> FunctionFlags:
        """
        Get function attribute flags.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            FunctionFlags enum with all active flags

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        return FunctionFlags(_ida_compat.get_func_flags(self._resolve_start(func)))

    def is_far(self, func: FunctionLike) -> bool:
        """
        Check if function is far.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            True if function is far, False otherwise (including when there
            is no function at the address).

        Raises:
            InvalidEAError: If the address is invalid.
        """
        flags = _ida_compat.get_func_flags(self._resolve_ea(func))
        return bool(flags & ida_funcs.FUNC_FAR)

    def does_return(self, func: FunctionLike) -> bool:
        """
        Check if function returns.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            True if function returns, False if it's noreturn

        Raises:
            InvalidEAError: If the address is invalid.
        """
        return ida_funcs.func_does_return(self._resolve_ea(func))

    def get_callers(self, func: FunctionLike) -> List[FunctionInfo]:
        """
        Gets all functions that call this function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            List of FunctionInfo snapshots of calling functions.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        start_ea = self._resolve_start(func)

        callers: List[FunctionInfo] = []
        caller_addrs = set()  # Use set to avoid duplicates

        # Get all call references to this function
        for caller_ea in self.database.xrefs.calls_to_ea(start_ea):
            # Get the function containing this call site
            caller_info = _func_info_at(caller_ea)
            if caller_info and caller_info.start_ea not in caller_addrs:
                caller_addrs.add(caller_info.start_ea)
                callers.append(caller_info)

        return callers

    def get_callees(self, func: FunctionLike) -> List[FunctionInfo]:
        """
        Gets all functions called by this function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            List of FunctionInfo snapshots of called functions.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        info = self._resolve_info(func)

        callees: List[FunctionInfo] = []
        callee_addrs = set()  # Use set to avoid duplicates

        # Iterate through all instructions in the function to find calls and jumps
        for inst in self.database.instructions.get_between(info.start_ea, info.end_ea):
            # Get call references from this instruction
            for target_ea in self.database.xrefs.calls_from_ea(inst.ea):
                # Get the target function
                target_info = _func_info_at(target_ea)
                if target_info and target_info.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_info.start_ea != info.start_ea:
                        callee_addrs.add(target_info.start_ea)
                        callees.append(target_info)

            # Also get jump references for tail calls
            for target_ea in self.database.xrefs.jumps_from_ea(inst.ea):
                # Get the target function
                target_info = _func_info_at(target_ea)
                if target_info and target_info.start_ea not in callee_addrs:
                    # Make sure we're not including the same function (recursive calls)
                    if target_info.start_ea != info.start_ea:
                        callee_addrs.add(target_info.start_ea)
                        callees.append(target_info)

        return callees

    def get_by_name(self, name: str) -> Optional[FunctionInfo]:
        """
        Find a function by its name.

        Args:
            name: Function name to search for

        Returns:
            FunctionInfo snapshot if found, None otherwise
        """
        func_ea = ida_name.get_name_ea(BADADDR, name)
        if func_ea != BADADDR:
            return _func_info_at(func_ea)
        return None

    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        warnings.warn(
            'get_function_by_name deprecated, use get_by_name instead', DeprecationWarning
        )
        return self.get_by_name(name)

    def get_tails(self, func: FunctionLike) -> List[FunctionChunk]:
        """
        Get all tail chunks of a function.

        Args:
            func: The function (FunctionInfo, any address inside the
                entry chunk, or func_t).

        Returns:
            List of FunctionChunk objects, empty if not entry chunk

        Raises:
            InvalidEAError: If the address is invalid.
        """
        ea = self._resolve_ea(func)
        if not _ida_compat.is_function_entry(ea):
            return []

        start_ea = _ida_compat.get_func_start(ea)
        return [
            FunctionChunk(start_ea=tail_start, end_ea=tail_end, is_main=False)
            for tail_start, tail_end in _ida_compat.iter_func_tail_ranges(ea)
            if tail_start != start_ea  # Skip main chunk
        ]

    def get_stack_points(self, func: FunctionLike) -> List[StackPoint]:
        """
        Get function stack points for SP tracking.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            List of StackPoint objects showing where SP changes

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        return [
            StackPoint(ea=point_ea, sp_delta=spd)
            for point_ea, spd in _ida_compat.get_func_stack_points(self._resolve_start(func))
        ]

    def get_tail_info(self, chunk: ChunkLike) -> Optional[TailInfo]:
        """
        Get information about tail chunk's owner function.

        Args:
            chunk: The tail chunk (FunctionChunk, any address inside it, or func_t).

        Returns:
            TailInfo with owner details, or None if not a tail chunk
        """
        ea = _ida_compat.func_ea(chunk)
        if not _ida_compat.is_function_tail(ea):
            return None

        owner_ea = _ida_compat.get_tail_owner(ea)
        owner_name = ''
        if owner_ea != BADADDR:
            owner_name = self.database.names.get_at(owner_ea) or ''

        return TailInfo(owner_ea=owner_ea, owner_name=owner_name)

    def get_data_items(self, func: FunctionLike) -> Iterator[ea_t]:
        """
        Iterate over data items within the function.

        This method finds all addresses within the function that are defined
        as data (not code). Useful for finding embedded data, jump tables,
        or other non-code items within function boundaries.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Yields:
            Addresses of data items within the function

        Raises:
            InvalidEAError: If the address is invalid or not within a function.

        Example:
            ```python
            >>> for data_ea in db.functions.get_data_items(0x401000):
            ...     size = ida_bytes.get_item_size(data_ea)
            ...     print(f"Data at 0x{data_ea:x}, size: {size}")
            ```
        """
        info = self._resolve_info(func)

        ea = info.start_ea
        while ea < info.end_ea and ea != BADADDR:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_data(flags):
                yield ea
            ea = ida_bytes.next_head(ea, info.end_ea)

    def get_chunks(self, func: FunctionLike) -> Iterator[FunctionChunk]:
        """
        Get all chunks (main and tail) of a function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Yields:
            FunctionChunk objects representing each chunk.

        Raises:
            InvalidEAError: If the address is invalid or not within a function.
        """
        info = self._resolve_info(func)

        # Main chunk
        yield FunctionChunk(start_ea=info.start_ea, end_ea=info.end_ea, is_main=True)

        # Tail chunks
        for tail_start, tail_end in _ida_compat.iter_func_tail_ranges(info.start_ea):
            if tail_start != info.start_ea:  # Skip main chunk
                yield FunctionChunk(start_ea=tail_start, end_ea=tail_end, is_main=False)

    def is_chunk_at(self, ea: ea_t) -> bool:
        """
        Check if the given address belongs to a function chunk.

        Args:
            ea: The address to check.

        Returns:
            True if the address is in a function chunk.
        """
        return _ida_compat.is_function_tail(ea)

    def set_comment(self, func: FunctionLike, comment: str, repeatable: bool = False) -> bool:
        """
        Set comment for function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            comment: Comment text to set.
            repeatable: If True, creates a repeatable comment (shows at all identical operands).
                        If False, creates a non-repeatable comment (shows only at this function).

        Returns:
            True if successful, False otherwise.
        """
        return _ida_compat.set_func_cmt_ea(_ida_compat.func_ea(func), comment, repeatable)

    def get_comment(self, func: FunctionLike, repeatable: bool = False) -> str:
        """
        Get comment for function.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            repeatable: If True, retrieves repeatable comment (shows at all identical operands).
                        If False, retrieves non-repeatable comment (shows only at this function).

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return _ida_compat.get_func_cmt_ea(_ida_compat.func_ea(func), repeatable) or ''

    def get_local_variables(self, func: FunctionLike) -> List[LocalVariable]:
        """
        Get all local variables for a function.

        Delegates to ``db.pseudocode.decompile()`` and reads the cfunc's
        lvar table.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).

        Returns:
            List of local variables including arguments and local vars.

        Raises:
            PseudocodeError: If decompilation fails for the function.
        """
        pcfunc = self.database.pseudocode.decompile(_ida_compat.func_ea(func))
        raw_cfunc = pcfunc.raw_cfunc
        return [LocalVariable._from_raw(raw_cfunc, i) for i in range(raw_cfunc.lvars.size())]

    def get_local_variable_references(
        self, func: FunctionLike, lvar: LocalVariable
    ) -> List[LocalVariableReference]:
        """
        Get all references to a specific local variable.

        Convenience entry point that forwards to
        :meth:`PseudocodeFunction.find_variable_references`. Each returned
        :class:`LocalVariableReference` carries the wrapped ctree nodes
        (``expr``, ``parent``, lazy ``assignment``, ``walk_ancestors``) so
        callers can perform deeper analyses — taint tracking, type
        inference, deobfuscation — without copying any visitor internals.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            lvar: The local variable to find references for.

        Returns:
            List of references to the variable in pseudocode.

        Raises:
            PseudocodeError: If decompilation fails for the function.
        """
        pcfunc = self.database.pseudocode.decompile(_ida_compat.func_ea(func))
        return pcfunc.find_variable_references(var_index=lvar.index)

    def get_local_variable_by_name(self, func: FunctionLike, name: str) -> Optional[LocalVariable]:
        """
        Find a local variable by name.

        Args:
            func: The function (FunctionInfo, any address inside it, or func_t).
            name: Variable name to search for.

        Returns:
            LocalVariable if found

        Raises:
            PseudocodeError: If decompilation fails for the function.
            KeyError: If the variable is not found
        """
        lvars = self.get_local_variables(func)
        for lvar in lvars:
            if lvar.name == name:
                return lvar
        raise KeyError(f'Variable {name} could not be located')
