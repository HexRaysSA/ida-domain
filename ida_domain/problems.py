"""
Problems entity for IDA Domain API.

Provides access to IDA's problem lists - collections of addresses where specific
analysis issues have been detected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum

import ida_ida
import ida_problems
from ida_idaapi import BADADDR, ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional, cast

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database


logger = logging.getLogger(__name__)


class ProblemType(IntEnum):
    """Types of problems tracked by IDA."""

    NOBASE = ida_problems.PR_NOBASE  # Can't find offset base
    NONAME = ida_problems.PR_NONAME  # Can't find name
    NOXREFS = ida_problems.PR_NOXREFS  # Can't find references
    DISASM = ida_problems.PR_DISASM  # Can't disassemble
    HEAD = ida_problems.PR_HEAD  # Already head
    ILLADDR = ida_problems.PR_ILLADDR  # Execution flows beyond limits
    MANYLINES = ida_problems.PR_MANYLINES  # Too many lines
    BADSTACK = ida_problems.PR_BADSTACK  # Failed to trace stack pointer
    ATTN = ida_problems.PR_ATTN  # Attention! Probably erroneous situation
    FINAL = ida_problems.PR_FINAL  # IDA auto decision
    ROLLED = ida_problems.PR_ROLLED  # IDA decision rolled back
    COLLISION = ida_problems.PR_COLLISION  # FLAIR collision
    DECIMP = ida_problems.PR_DECIMP  # FLAIR match indecision


@dataclass(frozen=True)
class Problem:
    """Represents a problem at a specific address."""

    address: ea_t
    """Linear address where problem was detected"""
    type: ProblemType
    """Category of problem"""
    description: Optional[str] = None
    """Optional custom message describing the specific issue"""

    @property
    def type_name(self) -> str:
        """
        Get the human-readable name of the problem type.

        Returns:
            String description of the problem category.

        Example:
            >>> problem = Problem(0x401000, ProblemType.DISASM, "Invalid opcode")
            >>> print(problem.type_name)
            Can't disassemble
        """
        return cast(str, ida_problems.get_problem_name(self.type, longname=True))


@decorate_all_methods(check_db_open)
class Problems(DatabaseEntity):
    """
    Provides access to IDA's problem list operations.

    Problem lists track addresses where specific analysis issues have been detected.
    IDA maintains separate problem lists for different categories such as disassembly
    failures, missing references, stack tracing problems, FLAIR collisions, and
    rollback decisions.
    """

    def __init__(self, database: Database) -> None:
        """Initialize the Problems entity."""
        super().__init__(database)

    def __iter__(self) -> Iterator[Problem]:
        """
        Iterate through all problems of all types, sorted by address.

        Returns:
            Iterator yielding Problem objects.

        Example:
            >>> db = Database.open_current()
            >>> for problem in db.problems:
            ...     print(f"{problem.type_name} at {hex(problem.address)}")
        """
        return self.get_all()

    def __len__(self) -> int:
        """
        Get the total number of problems across all types.

        Returns:
            Total count of problem entries.

        Example:
            >>> db = Database.open_current()
            >>> count = len(db.problems)
            >>> print(f"Total problems: {count}")
        """
        count = 0
        for ptype in ProblemType:
            count += self.count_by_type(ptype)
        return count

    @property
    def count(self) -> int:
        """
        Get the total number of problems across all types.

        Returns:
            Total count of problem entries.

        Example:
            >>> db = Database.open_current()
            >>> total = db.problems.count
            >>> print(f"Total problems: {total}")
        """
        return len(self)

    def get_all(self, problem_type: Optional[ProblemType] = None) -> Iterator[Problem]:
        """
        Get all problems, optionally filtered by type.

        Args:
            problem_type: If specified, only return problems of this type.
                         If None, return all problems.

        Returns:
            Iterator yielding Problem objects sorted by address.

        Example:
            >>> db = Database.open_current()
            >>> # Get all disassembly problems
            >>> for problem in db.problems.get_all(ProblemType.DISASM):
            ...     print(f"Disassembly failure at {hex(problem.address)}")
            >>> # Get all problems
            >>> for problem in db.problems.get_all():
            ...     print(f"{problem.type_name}: {hex(problem.address)}")
        """
        if problem_type is not None:
            # Single type
            yield from self._iterate_type(problem_type)
        else:
            # All types
            for ptype in ProblemType:
                yield from self._iterate_type(ptype)

    def _iterate_type(self, problem_type: ProblemType) -> Iterator[Problem]:
        """
        Iterate through all problems of a specific type.

        Args:
            problem_type: Type of problems to iterate.

        Yields:
            Problem objects of the specified type.
        """
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        ea = min_ea
        while ea < max_ea:
            # Get next problem at or after ea
            ea = ida_problems.get_problem(problem_type, ea)
            if ea == BADADDR:
                break

            # Get description if available
            desc = ida_problems.get_problem_desc(problem_type, ea)
            if not desc:
                desc = None

            yield Problem(ea, problem_type, desc)

            # Move to next address
            ea += 1

    def get_between(
        self, start: ea_t, end: ea_t, problem_type: Optional[ProblemType] = None
    ) -> Iterator[Problem]:
        """
        Get problems within a specific address range.

        Args:
            start: Starting address (inclusive).
            end: Ending address (exclusive).
            problem_type: If specified, only return problems of this type.

        Returns:
            Iterator yielding Problem objects in the range.

        Raises:
            InvalidEAError: If start or end address is invalid.
            InvalidParameterError: If start >= end.

        Example:
            >>> db = Database.open_current()
            >>> # Get all problems in a function
            >>> func = db.functions.get_at(0x401000)
            >>> if func:
            ...     for problem in db.problems.get_between(func.start_ea, func.end_ea):
            ...         print(f"{problem.type_name} at {hex(problem.address)}")
            >>> # Get stack tracing problems in a range
            >>> for problem in db.problems.get_between(0x401000, 0x402000, ProblemType.BADSTACK):
            ...     print(f"Stack issue: {problem.description or 'Generic error'}")
        """
        # Validation
        if not self.database.is_valid_ea(start, strict_check=False):
            raise InvalidEAError(start)
        if not self.database.is_valid_ea(end, strict_check=False):
            raise InvalidEAError(end)
        if start >= end:
            raise InvalidParameterError('start', start, 'must be less than end')

        if problem_type is not None:
            # Single type in range
            yield from self._iterate_type_range(problem_type, start, end)
        else:
            # All types in range
            for ptype in ProblemType:
                yield from self._iterate_type_range(ptype, start, end)

    def _iterate_type_range(
        self, problem_type: ProblemType, start: ea_t, end: ea_t
    ) -> Iterator[Problem]:
        """
        Iterate problems of a type within a range.

        Args:
            problem_type: Type of problems to iterate.
            start: Starting address (inclusive).
            end: Ending address (exclusive).

        Yields:
            Problem objects in the specified range.
        """
        ea = start
        while ea < end:
            ea = ida_problems.get_problem(problem_type, ea)
            if ea == BADADDR or ea >= end:
                break

            desc = ida_problems.get_problem_desc(problem_type, ea)
            if not desc:
                desc = None

            yield Problem(ea, problem_type, desc)
            ea += 1

    def get_at(self, ea: ea_t) -> Iterator[Problem]:
        """
        Get all problems at a specific address.

        Multiple problems of different types can exist at the same address.

        Args:
            ea: Linear address to query.

        Returns:
            Iterator yielding Problem objects at the address (may be empty).

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> problems_at_addr = list(db.problems.get_at(0x401000))
            >>> if problems_at_addr:
            ...     print(f"Found {len(problems_at_addr)} problem(s) at 0x401000:")
            ...     for problem in problems_at_addr:
            ...         print(f"  - {problem.type_name}: {problem.description or 'No details'}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        for ptype in ProblemType:
            if ida_problems.is_problem_present(ptype, ea):
                desc = ida_problems.get_problem_desc(ptype, ea)
                if not desc:
                    desc = None
                yield Problem(ea, ptype, desc)

    def get_next(
        self, ea: ea_t, problem_type: Optional[ProblemType] = None
    ) -> Optional[Problem]:
        """
        Get the next problem at or after the specified address.

        Args:
            ea: Starting address to search from (inclusive).
            problem_type: If specified, find next problem of this type only.

        Returns:
            Next Problem at or after the address, or None if no more problems.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Find next disassembly problem after current address
            >>> next_problem = db.problems.get_next(0x401000, ProblemType.DISASM)
            >>> if next_problem:
            ...     print(f"Next disasm issue at {hex(next_problem.address)}")
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        if problem_type is not None:
            # Next problem of specific type
            next_ea = ida_problems.get_problem(problem_type, ea)
            if next_ea == BADADDR:
                return None

            desc = ida_problems.get_problem_desc(problem_type, next_ea)
            return Problem(next_ea, problem_type, desc or None)
        else:
            # Next problem of any type - find closest
            closest_ea = BADADDR
            closest_type = None

            for ptype in ProblemType:
                next_ea = ida_problems.get_problem(ptype, ea)
                if next_ea != BADADDR:
                    if closest_ea == BADADDR or next_ea < closest_ea:
                        closest_ea = next_ea
                        closest_type = ptype

            if closest_ea == BADADDR:
                return None

            # closest_type must be set if closest_ea is not BADADDR
            assert closest_type is not None
            desc = ida_problems.get_problem_desc(closest_type, closest_ea)
            return Problem(closest_ea, closest_type, desc or None)

    def has_problem(
        self, ea: ea_t, problem_type: Optional[ProblemType] = None
    ) -> bool:
        """
        Check if an address has a problem.

        Args:
            ea: Linear address to check.
            problem_type: If specified, check for problems of this specific type only.

        Returns:
            True if address has a problem (of the specified type if given),
            False otherwise.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Check if address has any problem
            >>> if db.problems.has_problem(0x401000):
            ...     print("Address 0x401000 has known issues")
            >>> # Check for specific problem type
            >>> if db.problems.has_problem(0x401500, ProblemType.BADSTACK):
            ...     print("Stack tracing failed at 0x401500")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if problem_type is not None:
            return cast(bool, ida_problems.is_problem_present(problem_type, ea))
        else:
            # Check if any problem type is present
            for ptype in ProblemType:
                if ida_problems.is_problem_present(ptype, ea):
                    return True
            return False

    def was_auto_decision(self, ea: ea_t) -> bool:
        """
        Check if IDA made an automatic decision at this address.

        Convenience method equivalent to has_problem(ea, ProblemType.FINAL).

        Args:
            ea: Linear address to check.

        Returns:
            True if IDA made an automatic decision at this address.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> if db.problems.was_auto_decision(0x401000):
            ...     print("IDA automatically decided to convert this address")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(bool, ida_problems.was_ida_decision(ea))

    def count_by_type(self, problem_type: ProblemType) -> int:
        """
        Get the count of problems of a specific type.

        Args:
            problem_type: Problem type to count.

        Returns:
            Number of problems of the specified type.

        Example:
            >>> db = Database.open_current()
            >>> disasm_count = db.problems.count_by_type(ProblemType.DISASM)
            >>> print(f"Found {disasm_count} disassembly problems")
        """
        count = 0
        for _ in self._iterate_type(problem_type):
            count += 1
        return count

    def add(
        self, ea: ea_t, problem_type: ProblemType, description: Optional[str] = None
    ) -> None:
        """
        Add a problem to the list.

        Displays a message about the problem (except for ProblemType.ATTN and
        ProblemType.FINAL which are silent).

        Args:
            ea: Linear address where problem was detected.
            problem_type: Type of problem being recorded.
            description: Optional custom message describing the specific issue.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Record a disassembly problem
            >>> db.problems.add(0x401000, ProblemType.DISASM, "Invalid opcode bytes: FF FF FF")
            >>> # Record a stack tracing problem
            >>> db.problems.add(0x401500, ProblemType.BADSTACK, "ESP modified in unexpected way")
            >>> # Record attention marker (silent)
            >>> db.problems.add(0x402000, ProblemType.ATTN)
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        ida_problems.remember_problem(problem_type, ea, description)

    def remove(self, ea: ea_t, problem_type: ProblemType) -> bool:
        """
        Remove a problem from the list.

        Args:
            ea: Linear address.
            problem_type: Type of problem to remove.

        Returns:
            True if problem was removed, False if it didn't exist.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Remove a resolved problem
            >>> if db.problems.remove(0x401000, ProblemType.DISASM):
            ...     print("Removed disassembly problem at 0x401000")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(bool, ida_problems.forget_problem(problem_type, ea))

    def remove_at(self, ea: ea_t) -> int:
        """
        Remove all problems at a specific address.

        Args:
            ea: Linear address.

        Returns:
            Number of problems removed.

        Raises:
            InvalidEAError: If address is invalid.

        Example:
            >>> db = Database.open_current()
            >>> # Clear all problems at address
            >>> removed = db.problems.remove_at(0x401000)
            >>> print(f"Removed {removed} problem(s) at 0x401000")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        count = 0
        for ptype in ProblemType:
            if ida_problems.forget_problem(ptype, ea):
                count += 1
        return count

    def clear(self, problem_type: ProblemType) -> int:
        """
        Clear all problems of a specific type.

        Args:
            problem_type: Type of problems to clear.

        Returns:
            Number of problems removed.

        Example:
            >>> db = Database.open_current()
            >>> # Clear all disassembly problems
            >>> count = db.problems.clear(ProblemType.DISASM)
            >>> print(f"Cleared {count} disassembly problems")
        """
        # Collect all addresses first (can't modify during iteration)
        addresses = []
        for problem in self._iterate_type(problem_type):
            addresses.append(problem.address)

        # Remove all
        count = 0
        for ea in addresses:
            if ida_problems.forget_problem(problem_type, ea):
                count += 1

        return count

    def clear_all(self) -> int:
        """
        Clear all problems of all types.

        Returns:
            Total number of problems removed.

        Example:
            >>> db = Database.open_current()
            >>> # Clear all problems
            >>> total = db.problems.clear_all()
            >>> print(f"Cleared {total} problems")
        """
        total = 0
        for ptype in ProblemType:
            total += self.clear(ptype)
        return total
