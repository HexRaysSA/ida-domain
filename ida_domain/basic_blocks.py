from __future__ import annotations

import logging
from enum import IntFlag
from typing import Any

import ida_gdl
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import (
    DatabaseEntity,
    DatabaseNotLoadedError,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from ida_funcs import func_t
    from ida_idaapi import ea_t

    from .database import Database


logger = logging.getLogger(__name__)


class FlowChartFlags(IntFlag):
    """Flags for flowchart generation from IDA SDK."""

    NONE = 0  # Default flags
    NOEXT = ida_gdl.FC_NOEXT  # Don't compute external blocks (blocks outside the function)
    PREDS = ida_gdl.FC_PREDS  # Compute predecessor information


class BasicBlock(ida_gdl.BasicBlock):
    """
    Basic block class wrapper around ida_gdl.BasicBlock.
    Provides access to basic block properties and navigation.
    """

    def __init__(self, database: Optional[Database], id: int, bb: Any, fc: Any) -> None:
        """
        Initialize basic block.

        Args:
            id: Block ID within the flowchart
            bb: The underlying qbasic_block_t object
            fc: Parent flowchart
        """
        self.m_database = database
        super().__init__(id, bb, fc)

    def get_successors(self) -> Iterator[BasicBlock]:
        """Iterator over successor blocks."""
        return self.succs()

    def get_predecessors(self) -> Iterator[BasicBlock]:
        """Iterator over predecessor blocks."""
        return self.preds()

    def count_successors(self) -> int:
        """Count the number of successor blocks."""
        return sum(1 for _ in self.succs())

    def count_predecessors(self) -> int:
        """Count the number of predecessor blocks."""
        return sum(1 for _ in self.preds())

    def get_instructions(self) -> Optional[Iterator[insn_t]]:
        """
        Retrieves all instructions within this basic block.

        Returns:
            An instruction iterator for this block.
        """
        if not self.m_database:
            raise DatabaseNotLoadedError('Database is not loaded. Please open a database first.')
        return self.m_database.instructions.get_between(self.start_ea, self.end_ea)


class FlowChart(ida_gdl.FlowChart):
    """
    Flowchart class wrapper around ida_gdl.FlowChart.
    Used to analyze and iterate through basic blocks within
    functions or address ranges.
    """

    def __init__(
        self,
        database: Optional[Database],
        f: func_t = None,
        bounds: Optional[tuple[ea_t, ea_t]] = None,
        flags: FlowChartFlags = FlowChartFlags.NONE,
    ) -> None:
        self.m_database = database
        super().__init__(f, bounds, int(flags))

    def __getitem__(self, index: int) -> BasicBlock:
        """
        Access flowchart items by index.

        Args:
            index: The index of the basic block to retrieve.

        Returns:
            The basic block at the specified index.

        Raises:
            IndexError: If index is out of range.
        """
        if not (0 <= index < self.size):
            raise IndexError(f'Basic block index {index} out of range (0-{self.size - 1})')

        base_block = super().__getitem__(index)
        return BasicBlock(self.m_database, base_block.id, base_block, self)

    def __iter__(self) -> Iterator[BasicBlock]:
        """
        Iterator protocol support for iteration.

        Yields:
            BasicBlock: Basic blocks in the flowchart.
        """
        for i in range(self.size):
            yield self[i]

    def __len__(self) -> int:
        """
        Return number of basic blocks in flowchart.

        Returns:
            int: Number of basic blocks.
        """
        return self.size


@decorate_all_methods(check_db_open)
class BasicBlocks(DatabaseEntity):
    """
    Interface for working with basic blocks in functions.

    Basic blocks are sequences of instructions with a single entry point and single exit point,
    used for control flow analysis and optimization.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def get_from_function(
        self, func: func_t, flags: FlowChartFlags = FlowChartFlags.NONE
    ) -> FlowChart:
        """
        Retrieves the basic blocks within a given function.

        Args:
            func: The function to retrieve basic blocks from.
            flags: Optional flowchart generation flags (default: FlowChartFlags.NONE).

        Returns:
            An iterable flowchart containing the basic blocks of the function.
        """
        return FlowChart(self.m_database, func, None, flags)

    def get_between(
        self, start_ea: ea_t, end_ea: ea_t, flags: FlowChartFlags = FlowChartFlags.NONE
    ) -> FlowChart:
        """
        Retrieves the basic blocks within a given address range.

        Args:
            start_ea: The start address of the range.
            end_ea: The end address of the range.
            flags: Optional flowchart generation flags (default: FlowChartFlags.NONE).

        Returns:
            An iterable flowchart containing the basic blocks within the specified range.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
            InvalidParameterError: If the input range is invalid.
        """

        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        return FlowChart(self.m_database, None, (start_ea, end_ea), flags)
