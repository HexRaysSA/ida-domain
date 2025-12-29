"""
Call graph traversal for inter-procedural analysis.

This module provides multi-hop call relationship traversal,
complementing the single-hop xref methods.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator, List, Optional, Set

from ida_idaapi import ea_t

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


@dataclass
class CallPath:
    """A path of function calls from source to destination."""

    path: List[ea_t]
    """List of function addresses in call order."""

    def __len__(self) -> int:
        return len(self.path)

    def __iter__(self) -> Iterator[ea_t]:
        return iter(self.path)

    def __repr__(self) -> str:
        path_str = " -> ".join(f"0x{ea:x}" for ea in self.path)
        return f"CallPath({path_str})"


@decorate_all_methods(check_db_open)
class CallGraph(DatabaseEntity):
    """
    Inter-procedural call graph traversal.

    Provides multi-hop traversal of function call relationships,
    building on the single-hop primitives in the Xrefs module.

    Example:
        >>> # Find all functions that eventually call dangerous_func
        >>> for caller in db.callgraph.callers_of(dangerous_func_ea, depth=5):
        ...     print(f"Caller: 0x{caller:x}")
        >>>
        >>> # Find call path from main to target
        >>> for path in db.callgraph.paths_between(main_ea, target_ea):
        ...     print(path)
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def callers_of(self, ea: ea_t, depth: int = 1) -> Iterator[ea_t]:
        """
        Get transitive callers of a function.

        Args:
            ea: Function address to find callers of.
            depth: Maximum call depth to traverse (default: 1 = direct callers only).

        Yields:
            Function start addresses that (transitively) call this function.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        visited: Set[ea_t] = set()
        visited.add(ea)

        current_level: Set[ea_t] = {ea}

        for _ in range(depth):
            next_level: Set[ea_t] = set()

            for func_ea in current_level:
                for call_site in self.database.xrefs.calls_to_ea(func_ea):
                    caller_func = self.database.functions.get_at(call_site)
                    if caller_func and caller_func.start_ea not in visited:
                        visited.add(caller_func.start_ea)
                        next_level.add(caller_func.start_ea)
                        yield caller_func.start_ea

            if not next_level:
                break
            current_level = next_level

    def callees_of(self, ea: ea_t, depth: int = 1) -> Iterator[ea_t]:
        """
        Get transitive callees (functions called by) a function.

        Args:
            ea: Function address to find callees of.
            depth: Maximum call depth to traverse (default: 1 = direct callees only).

        Yields:
            Function start addresses that are (transitively) called.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        func = self.database.functions.get_at(ea)
        if func is None:
            return

        visited: Set[ea_t] = set()
        visited.add(func.start_ea)

        current_level: Set[ea_t] = {func.start_ea}

        for _ in range(depth):
            next_level: Set[ea_t] = set()

            for func_ea in current_level:
                f = self.database.functions.get_at(func_ea)
                if f is None:
                    continue

                for insn in self.database.instructions.get_between(f.start_ea, f.end_ea):
                    for target in self.database.xrefs.calls_from_ea(insn.ea):
                        target_func = self.database.functions.get_at(target)
                        if target_func and target_func.start_ea not in visited:
                            visited.add(target_func.start_ea)
                            next_level.add(target_func.start_ea)
                            yield target_func.start_ea

            if not next_level:
                break
            current_level = next_level

    def paths_between(
        self,
        src: ea_t,
        dst: ea_t,
        max_depth: int = 10
    ) -> Iterator[CallPath]:
        """
        Find call paths from source function to destination function.

        Uses BFS to find paths, yielding shorter paths first.

        Args:
            src: Source function address.
            dst: Destination function address.
            max_depth: Maximum path length (default: 10).

        Yields:
            CallPath objects representing call chains from src to dst.

        Raises:
            InvalidEAError: If either address is invalid.
        """
        if not self.database.is_valid_ea(src):
            raise InvalidEAError(src)
        if not self.database.is_valid_ea(dst):
            raise InvalidEAError(dst)

        src_func = self.database.functions.get_at(src)
        dst_func = self.database.functions.get_at(dst)

        if src_func is None or dst_func is None:
            return

        src_ea = src_func.start_ea
        dst_ea = dst_func.start_ea

        if src_ea == dst_ea:
            yield CallPath([src_ea])
            return

        queue: deque = deque()
        queue.append([src_ea])

        while queue:
            path = queue.popleft()

            if len(path) > max_depth:
                continue

            current = path[-1]
            current_func = self.database.functions.get_at(current)
            if current_func is None:
                continue

            for insn in self.database.instructions.get_between(
                current_func.start_ea, current_func.end_ea
            ):
                for target in self.database.xrefs.calls_from_ea(insn.ea):
                    target_func = self.database.functions.get_at(target)
                    if target_func is None:
                        continue

                    target_ea = target_func.start_ea

                    if target_ea in path:
                        continue

                    new_path = path + [target_ea]

                    if target_ea == dst_ea:
                        yield CallPath(new_path)
                    elif len(new_path) < max_depth:
                        queue.append(new_path)

    def reachable_from(self, ea: ea_t, max_depth: int = 100) -> Set[ea_t]:
        """
        Get all functions reachable from the given function.

        Args:
            ea: Function address to start from.
            max_depth: Maximum call depth to traverse (default: 100).

        Returns:
            Set of function start addresses reachable from the given function.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        return set(self.callees_of(ea, depth=max_depth))

    def reaches(self, ea: ea_t, max_depth: int = 100) -> Set[ea_t]:
        """
        Get all functions that can reach the given function.

        Args:
            ea: Function address to find callers of.
            max_depth: Maximum call depth to traverse (default: 100).

        Returns:
            Set of function start addresses that can reach the given function.

        Raises:
            InvalidEAError: If the address is invalid.
        """
        return set(self.callers_of(ea, depth=max_depth))
