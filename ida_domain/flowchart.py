from __future__ import annotations

import logging
from enum import IntFlag
from typing import Any

import ida_gdl
from ida_gdl import qbasic_block_t, qflow_chart_t
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import (
    DatabaseEntity,
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


@decorate_all_methods(check_db_open)
class BasicBlock(ida_gdl.BasicBlock, DatabaseEntity):
    """
    Provides access to basic block properties and navigation
    between connected blocks within a control flow graph.
    """

    def __init__(
        self,
        database: Optional[Database],
        id: int,
        block: qbasic_block_t,
        flowchart: qflow_chart_t,
    ) -> None:
        """
        Initialize basic block.

        Args:
            id: Block ID within the flowchart
            block: The underlying qbasic_block_t object
            flowchart: Parent flowchart
        """
        DatabaseEntity.__init__(self, database)
        ida_gdl.BasicBlock.__init__(self, id, block, flowchart)

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
        return self.database.instructions.get_between(self.start_ea, self.end_ea)


@decorate_all_methods(check_db_open)
class FlowChart(ida_gdl.FlowChart, DatabaseEntity):
    """
    Provides analysis and iteration over basic blocks within
    functions or address ranges.
    """

    def __init__(
        self,
        database: Optional[Database],
        func: func_t = None,
        bounds: Optional[tuple[ea_t, ea_t]] = None,
        flags: FlowChartFlags = FlowChartFlags.NONE,
    ) -> None:
        """
        Initialize FlowChart for analyzing basic blocks within functions or address ranges.

        Args:
            database: Database instance to associate with this flowchart. Can be None.
            func: IDA function object (func_t) to analyze. Defaults to None.
            bounds: Address range tuple (start_ea, end_ea) defining the analysis scope.
                Defaults to None.
            flags: FlowChart creation flags controlling analysis behavior.
                Defaults to FlowChartFlags.NONE.

        Note:
            At least one of `func` or `bounds` must be specified.
        """
        DatabaseEntity.__init__(self, database)
        if bounds:
            if not self.database.is_valid_ea(bounds[0], strict_check=False):
                raise InvalidEAError(bounds[0])
            if not self.database.is_valid_ea(bounds[1], strict_check=False):
                raise InvalidEAError(bounds[1])
            if bounds[0] >= bounds[1]:
                raise InvalidParameterError('bounds', bounds, 'must be a valid range')

        ida_gdl.FlowChart.__init__(self, func, bounds, int(flags))

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
