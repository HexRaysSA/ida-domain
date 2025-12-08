from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, Flag, IntEnum

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_typeinf
from ida_funcs import func_t
from ida_idaapi import BADADDR, ea_t
from ida_typeinf import tinfo_t
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Any, Iterator, List, Optional

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


class LocalVariableAccessType(IntEnum):
    """Type of access to a local variable."""

    READ = 1
    """Variable value is read"""
    WRITE = 2
    """Variable value is modified"""
    ADDRESS = 3
    """Address of variable is taken (&var)"""


class LocalVariableContext(Enum):
    """Context where local variable is referenced."""

    ASSIGNMENT = 'assignment'
    """var = expr or expr = var"""
    CONDITION = 'condition'
    """if (var), while (var), etc."""
    CALL_ARG = 'call_arg'
    """func(var)"""
    RETURN = 'return'
    """return var"""
    ARITHMETIC = 'arithmetic'
    """var + 1, var * 2, etc."""
    COMPARISON = 'comparison'
    """var == x, var < y, etc."""
    ARRAY_INDEX = 'array_index'
    """arr[var] or var[i]"""
    POINTER_DEREF = 'pointer_deref'
    """*var or var->field"""
    CAST = 'cast'
    """(type)var"""
    OTHER = 'other'
    """Other contexts"""


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
class LocalVariable:
    """Represents a local variable or argument in a function."""

    index: int
    """Variable index in function"""
    name: str
    """Variable name"""
    type: Optional[tinfo_t]
    """Type information"""
    size: int
    """Size in bytes"""
    is_argument: bool
    """True if is a function argument"""
    is_result: bool
    """True if is a return value variable"""

    @property
    def type_str(self) -> str:
        """Get string representation of the type."""
        return str(self.type) if self.type else ''


@dataclass
class LocalVariableReference:
    """Reference to a local variable in pseudocode."""

    access_type: LocalVariableAccessType
    """How variable is accessed"""
    context: Optional[LocalVariableContext] = None
    """Usage context"""
    ea: Optional[ea_t] = None
    """Binary address if mappable"""
    line_number: Optional[int] = None
    """Line number in pseudocode"""
    code_line: Optional[str] = None
    """The pseudocode line containing the reference"""


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


# ============================================================================
# Ctree Assignment Detection
# ============================================================================
#
# The hexrays ctree represents decompiled code as nested expression trees.
# Determining write access requires analyzing the tree structure.
#
# Direct assignment: v9 = 10
#
#   cot_asg
#   ├── x: cot_var (v9)     ← variable is direct child of assignment
#   └── y: cot_num (10)
#
# Nested assignment: HIWORD(v9) = a1  (helper function wrapping variable)
#
#   cot_asg
#   ├── x: cot_helper (HIWORD)
#   │       └── a[0]: cot_var (v9)   ← variable is nested in left subtree
#   └── y: cot_var (a1)
#
# Other nested patterns include casts, pointer dereferences, and array indexing:
#   *ptr = x        →  cot_ptr wraps the variable
#   arr[i] = x      →  cot_idx wraps the variable
#   (cast)v = x     →  cot_cast wraps the variable
#
# Problem:
#   A direct parent check (parent.op == cot_asg and parent.x == expr) only
#   handles direct assignments. In nested cases, the variable's immediate
#   parent is the wrapper expression (helper/cast/ptr), not the assignment.
#
# Solution:
#   Two-direction traversal:
#   1. UP: Traverse ancestor chain to locate an assignment operator
#   2. DOWN: Verify the variable resides in the assignment's left subtree
#
# Without this logic, `HIWORD(v9) = a1` incorrectly reports `v9` as READ
# because the immediate parent is cot_helper. This affects data flow analysis
# and variable access classification.
#
# Performance characteristics:
#   - Up-traversal: O(d) where d = ancestor depth, typically 1-5 levels
#   - Down-traversal: O(n) where n = nodes in left subtree, typically 1-10
#   - Invoked once per variable reference during ctree visitor traversal
#
# ============================================================================

# All assignment operators in IDA hexrays ctree
_ASSIGNMENT_OPS = (
    ida_hexrays.cot_asg,
    ida_hexrays.cot_asgadd,
    ida_hexrays.cot_asgmul,
    ida_hexrays.cot_asgsub,
    ida_hexrays.cot_asgsdiv,
    ida_hexrays.cot_asgudiv,
    ida_hexrays.cot_asgsmod,
    ida_hexrays.cot_asgumod,
    ida_hexrays.cot_asgbor,
    ida_hexrays.cot_asgxor,
    ida_hexrays.cot_asgband,
    ida_hexrays.cot_asgsshr,
    ida_hexrays.cot_asgushr,
    ida_hexrays.cot_asgshl,
)


class _LVarRefsVisitor(ida_hexrays.ctree_parentee_t):
    """Visitor to find references to a specific local variable in pseudocode.

    Uses ctree_parentee_t which properly maintains parent information.
    """

    def __init__(self, cfunc: Any, lvar_index: int):
        super().__init__()
        self.cfunc = cfunc
        self.lvar_index = lvar_index
        self.refs: List[LocalVariableReference] = []

    def visit_expr(self, expr: Any) -> int:
        """Visit expression nodes to find variable references."""
        if expr.op == ida_hexrays.cot_var:
            # Found any variable - check if it's our target
            if expr.v.idx == self.lvar_index:
                # Found a reference to our variable
                # Use parent_expr() to get the parent expression
                parent = self.parent_expr()

                access_type = self._determine_access_type(expr, parent)
                context = self._determine_context(expr, parent)
                ea = expr.ea if expr.ea != BADADDR else None

                # Extract line information
                line_number = None
                code_line = None

                # Get line coordinates from the expression
                coords = self.cfunc.find_item_coords(expr)
                if coords and len(coords) >= 2:
                    line_number = coords[1]  # y coordinate is line number

                    # Get the actual pseudocode line
                    sv = self.cfunc.get_pseudocode()
                    if 0 <= line_number < len(sv):
                        code_line = sv[line_number].line
                        # Remove IDA color/formatting tags
                        code_line = ida_lines.tag_remove(code_line).strip()

                ref = LocalVariableReference(
                    access_type=access_type,
                    context=context,
                    ea=ea,
                    line_number=line_number,
                    code_line=code_line,
                )
                self.refs.append(ref)
        return 0

    def _is_on_left_side_of_assignment(self, asg_expr: Any, child_expr: Any) -> bool:
        """Check if child_expr is in the left subtree of an assignment.

        Performs a depth-first traversal from the assignment's left operand (.x)
        to determine if child_expr is reachable. If reachable, the variable is
        on the write side of the assignment.

        This handles nested patterns where the variable is wrapped in expressions:
            HIWORD(v9) = a1  →  v9 is inside cot_helper, which is in .x
            *ptr = val       →  ptr is inside cot_ptr, which is in .x

        Args:
            asg_expr: An assignment expression (cot_asg or compound assignment).
            child_expr: The expression to search for in the left subtree.

        Returns:
            True if child_expr is found in the left subtree (write side).

        Performance:
            O(n) where n = number of nodes in left subtree. Typically 1-10 nodes
            for common patterns like helpers, casts, or pointer dereferences.
        """
        # asg_expr might be a citem_t, we need to access the cexpr_t
        # Check if it's an expression type with x attribute
        if not hasattr(asg_expr, 'x'):
            # Try to get the expression from citem_t
            if hasattr(asg_expr, 'cexpr'):
                asg_expr = asg_expr.cexpr
            else:
                return False

        # Get the left side of the assignment
        left = asg_expr.x
        if left is None:
            return False

        # Use a simple BFS/DFS to find if child_expr is in the left subtree
        stack = [left]
        while stack:
            current = stack.pop()
            if current is None:
                continue
            # Check if this is our target expression (by object identity or ea)
            if current == child_expr:
                return True
            if hasattr(current, 'ea') and hasattr(child_expr, 'ea'):
                if current.ea == child_expr.ea and current.op == child_expr.op:
                    return True
            # Traverse children based on expression type
            if hasattr(current, 'x') and current.x is not None:
                stack.append(current.x)
            if hasattr(current, 'y') and current.y is not None:
                stack.append(current.y)
            if hasattr(current, 'z') and current.z is not None:
                stack.append(current.z)
        return False

    def _find_assignment_in_ancestors(self) -> tuple:
        """Find an assignment operator in the ancestor chain.

        Traverses from the immediate parent upward through the ancestor chain
        to locate an assignment operator. When found, determines whether the
        current expression is on the left (write) or right (read) side.

        This enables correct access type detection for nested patterns:
            HIWORD(v9) = a1  →  parent of v9 is cot_helper, not assignment
                             →  ancestor traversal finds the cot_asg above

        Uses self.parents vector maintained by ctree_parentee_t during traversal.

        Returns:
            Tuple of (assignment_expr, is_on_left_side):
                - (expr, True) if in left subtree (write side)
                - (expr, False) if in right subtree (read side)
                - (None, False) if no assignment found in ancestors

        Performance:
            O(d) where d = ancestor depth. Typically 1-5 levels for common
            patterns. The parents vector is already maintained by the base
            class during tree traversal.
        """
        num_parents = len(self.parents)
        for i in range(num_parents):
            # Access parents from end (nearest) to beginning (farthest)
            parent_item = self.parents[num_parents - 1 - i]
            if parent_item is None:
                continue
            # Check if this parent is an expression with an assignment op
            if not hasattr(parent_item, 'op'):
                continue
            if parent_item.op in _ASSIGNMENT_OPS:
                # Found an assignment - determine if we're on the left side
                # The item right before this assignment in the parent chain
                # is the child that leads to our expression
                if i == 0:
                    # Immediate parent is assignment, use parent_expr()
                    child = self.parent_expr()
                else:
                    # Get the item that is child of this assignment
                    child = self.parents[num_parents - i]
                is_left = self._is_on_left_side_of_assignment(parent_item, child)
                return (parent_item, is_left)
        return (None, False)

    def _determine_access_type(self, expr: Any, parent: Any) -> LocalVariableAccessType:
        """Determine how the variable is being accessed."""
        if not parent:
            return LocalVariableAccessType.READ

        # Check if this is a write operation (left side of assignment)
        if parent.op == ida_hexrays.cot_asg and parent.x == expr:
            return LocalVariableAccessType.WRITE
        # Check compound assignments at immediate parent level
        elif parent.op in _ASSIGNMENT_OPS and parent.x == expr:
            return LocalVariableAccessType.WRITE
        # Check if address is taken - but also check ancestors for assignment
        elif parent.op == ida_hexrays.cot_ref:
            # Address is taken - check if this is part of an assignment
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableAccessType.WRITE
            return LocalVariableAccessType.ADDRESS

        # For calls (including helpers like HIWORD), casts, ptr derefs - check ancestors
        if parent.op in (
            ida_hexrays.cot_call,
            ida_hexrays.cot_helper,
            ida_hexrays.cot_cast,
            ida_hexrays.cot_ptr,
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_memref,
            ida_hexrays.cot_add,
            ida_hexrays.cot_idx,
        ):
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableAccessType.WRITE

        return LocalVariableAccessType.READ

    def _determine_context(self, expr: Any, parent: Any) -> LocalVariableContext:
        """Determine the context where the variable is used."""
        if not parent:
            return LocalVariableContext.OTHER

        if parent.op == ida_hexrays.cot_asg:
            return LocalVariableContext.ASSIGNMENT
        elif parent.op in _ASSIGNMENT_OPS:
            return LocalVariableContext.ASSIGNMENT
        elif parent.op == ida_hexrays.cot_call:
            # Check if there's an assignment ancestor - if so, this is ASSIGNMENT context
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.CALL_ARG
        elif parent.op in (
            ida_hexrays.cot_eq,
            ida_hexrays.cot_ne,
            ida_hexrays.cot_sge,
            ida_hexrays.cot_uge,
            ida_hexrays.cot_sle,
            ida_hexrays.cot_ule,
            ida_hexrays.cot_sgt,
            ida_hexrays.cot_ugt,
            ida_hexrays.cot_slt,
            ida_hexrays.cot_ult,
        ):
            return LocalVariableContext.COMPARISON
        elif parent.op in (
            ida_hexrays.cot_add,
            ida_hexrays.cot_sub,
            ida_hexrays.cot_mul,
            ida_hexrays.cot_sdiv,
            ida_hexrays.cot_udiv,
            ida_hexrays.cot_smod,
            ida_hexrays.cot_umod,
        ):
            # Check if there's an assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.ARITHMETIC
        elif parent.op == ida_hexrays.cot_idx:
            # Check if there's an assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.ARRAY_INDEX
        elif parent.op in (ida_hexrays.cot_ptr, ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            # Check if there's an assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.POINTER_DEREF
        elif parent.op == ida_hexrays.cot_cast:
            # Check if there's an assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.CAST
        elif parent.op == ida_hexrays.cot_ref:
            # Address taken - check for assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.OTHER
        elif parent.op == ida_hexrays.cot_helper:
            # Helper functions like HIWORD - check for assignment ancestor
            asg, is_left = self._find_assignment_in_ancestors()
            if asg and is_left:
                return LocalVariableContext.ASSIGNMENT
            return LocalVariableContext.OTHER

        return LocalVariableContext.OTHER


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

    def get_local_variables(self, func: func_t) -> List[LocalVariable]:
        """
        Get all local variables for a function.

        Args:
            func: The function instance.

        Returns:
            List of local variables including arguments and local vars.

        Raises:
            RuntimeError: If decompilation fails for the function.
        """
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RuntimeError(f'Failed to decompile function at 0x{func.start_ea:x}')

        lvars = []
        for i in range(cfunc.lvars.size()):
            lvar = cfunc.lvars[i]

            # Get type information
            type_info = lvar.tif

            local_var = LocalVariable(
                index=i,
                name=lvar.name,
                type=type_info,
                size=lvar.width,
                is_argument=lvar.is_arg_var,
                is_result=lvar.is_result_var,
            )
            lvars.append(local_var)

        return lvars

    def get_local_variable_references(
        self, func: func_t, lvar: LocalVariable
    ) -> List[LocalVariableReference]:
        """
        Get all references to a specific local variable.

        Args:
            func: The function instance.
            lvar: The local variable to find references for.

        Returns:
            List of references to the variable in pseudocode.

        Raises:
            RuntimeError: If decompilation fails for the function.
        """
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            raise RuntimeError(f'Failed to decompile function at 0x{func.start_ea:x}')

        # Create visitor to find variable references
        visitor = _LVarRefsVisitor(cfunc, lvar.index)

        # Visit the function body to find references
        visitor.apply_to(cfunc.body, None)

        return visitor.refs

    def get_local_variable_by_name(self, func: func_t, name: str) -> Optional[LocalVariable]:
        """
        Find a local variable by name.

        Args:
            func: The function instance.
            name: Variable name to search for.

        Returns:
            LocalVariable if found

        Raises:
            RuntimeError: If decompilation fails for the function.
            KeyError: If the variable is not found
        """
        lvars = self.get_local_variables(func)
        for lvar in lvars:
            if lvar.name == name:
                return lvar
        raise KeyError(f'Variable {name} could not be located')
