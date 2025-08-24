from __future__ import annotations

import logging
from typing import Any

import ida_gdl
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
    from ida_gdl import qbasic_block_t
    from ida_idaapi import ea_t

    from .database import Database


logger = logging.getLogger(__name__)


class FlowChart(ida_gdl.FlowChart):
    """
    Flowchart class used to analyze and iterate through basic blocks within
    functions or address ranges.
    """

    def __init__(
        self, f: func_t = None, bounds: Optional[tuple[ea_t, ea_t]] = None, flags: int = 0
    ):
        super().__init__(f, bounds, flags)

    def __getitem__(self, index: int) -> qbasic_block_t:
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

        block = self._q[index]
        # Store reference to parent flowchart for successor/predecessor access
        if not hasattr(block, '_parent_flowchart'):
            block._parent_flowchart = self._q
        if not hasattr(block, '_block_index'):
            block._block_index = index
        return block

    def __iter__(self) -> Iterator[qbasic_block_t]:
        """
        Iterator protocol support for iteration.

        Yields:
            qbasic_block_t: Basic blocks in the flowchart.
        """
        size = self.size
        if size == 0:
            return  # Empty flowchart
        for i in range(size):
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

    def get_instructions(self, block: qbasic_block_t) -> Optional[Iterator[insn_t]]:
        """
        Retrieves the instructions within a given basic block.

        Args:
            block: The basic block to analyze.

        Returns:
            An instruction iterator for the block.
        """
        return self.database.instructions.get_between(block.start_ea, block.end_ea)

    def get_from_function(self, func: func_t, flags: int = 0) -> FlowChart:
        """
        Retrieves the basic blocks within a given function.

        Args:
            func: The function to retrieve basic blocks from.
            flags: Optional qflow_chart_t flags for flowchart generation (default: 0).

        Returns:
            An iterable flowchart containing the basic blocks of the function.
        """
        return FlowChart(func, None, flags)

    def get_between(self, start_ea: ea_t, end_ea: ea_t, flags: int = 0) -> FlowChart:
        """
        Retrieves the basic blocks within a given address range.

        Args:
            start_ea: The start address of the range.
            end_ea: The end address of the range.
            flags: Optional qflow_chart_t flags for flowchart generation (default: 0).

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

        return FlowChart(None, (start_ea, end_ea), flags)

    def get_successors(self, block: qbasic_block_t) -> Iterator[qbasic_block_t]:
        """
        Get the successor blocks of a given basic block.

        Args:
            block: The basic block to get successors for.

        Returns:
            Iterator of successor basic blocks.

        Raises:
            InvalidParameterError: If the block doesn't have parent flowchart information.
        """
        if not hasattr(block, '_parent_flowchart') or not hasattr(block, '_block_index'):
            raise InvalidParameterError(
                'block',
                block,
                'must be obtained from BasicBlocks.get_from_function() or get_between()',
            )

        flowchart = block._parent_flowchart
        block_id = block._block_index

        # Use the qflow_chart_t API to get successor indices
        for i in range(flowchart.nsucc(block_id)):
            succ_id = flowchart.succ(block_id, i)
            succ_block = flowchart[succ_id]
            # Add parent references to successor blocks
            if not hasattr(succ_block, '_parent_flowchart'):
                succ_block._parent_flowchart = flowchart
            if not hasattr(succ_block, '_block_index'):
                succ_block._block_index = succ_id
            yield succ_block

    def get_predecessors(self, block: qbasic_block_t) -> Iterator[qbasic_block_t]:
        """
        Get the predecessor blocks of a given basic block.

        Args:
            block: The basic block to get predecessors for.

        Returns:
            Iterator of predecessor basic blocks.

        Raises:
            InvalidParameterError: If the block doesn't have parent flowchart information.
        """
        if not hasattr(block, '_parent_flowchart') or not hasattr(block, '_block_index'):
            raise InvalidParameterError(
                'block',
                block,
                'must be obtained from BasicBlocks.get_from_function() or get_between()',
            )

        flowchart = block._parent_flowchart
        block_id = block._block_index

        # Use the qflow_chart_t API to get predecessor indices
        for i in range(flowchart.npred(block_id)):
            pred_id = flowchart.pred(block_id, i)
            pred_block = flowchart[pred_id]
            # Add parent references to predecessor blocks
            if not hasattr(pred_block, '_parent_flowchart'):
                pred_block._parent_flowchart = flowchart
            if not hasattr(pred_block, '_block_index'):
                pred_block._block_index = pred_id
            yield pred_block

    def count_successors(self, block: qbasic_block_t) -> int:
        """
        Count the number of successor blocks for a given basic block.

        Args:
            block: The basic block to count successors for.

        Returns:
            Number of successor blocks.

        Raises:
            InvalidParameterError: If the block doesn't have parent flowchart information.
        """
        if not hasattr(block, '_parent_flowchart') or not hasattr(block, '_block_index'):
            raise InvalidParameterError(
                'block',
                block,
                'must be obtained from BasicBlocks.get_from_function() or get_between()',
            )

        flowchart = block._parent_flowchart
        block_id = block._block_index
        return flowchart.nsucc(block_id)

    def count_predecessors(self, block: qbasic_block_t) -> int:
        """
        Count the number of predecessor blocks for a given basic block.

        Args:
            block: The basic block to count predecessors for.

        Returns:
            Number of predecessor blocks.

        Raises:
            InvalidParameterError: If the block doesn't have parent flowchart information.
        """
        if not hasattr(block, '_parent_flowchart') or not hasattr(block, '_block_index'):
            raise InvalidParameterError(
                'block',
                block,
                'must be obtained from BasicBlocks.get_from_function() or get_between()',
            )

        flowchart = block._parent_flowchart
        block_id = block._block_index
        return flowchart.npred(block_id)
