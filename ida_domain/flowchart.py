from __future__ import annotations

import logging
import warnings
from enum import IntEnum, IntFlag

import ida_gdl
from ida_gdl import qbasic_block_t, qflow_chart_t
from ida_idaapi import BADADDR
from ida_ua import insn_t
from typing_extensions import TYPE_CHECKING, Iterator, List, Optional

from ._graph import BlockGraph
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


class BlockType(IntEnum):
    """Basic block types corresponding to fcb_* constants."""

    NORMAL = ida_gdl.fcb_normal
    INDIRECT_JUMP = ida_gdl.fcb_indjump
    RETURN = ida_gdl.fcb_ret
    CONDITIONAL_RETURN = ida_gdl.fcb_cndret
    NORETURN = ida_gdl.fcb_noret
    EXTERNAL_NORETURN = ida_gdl.fcb_enoret
    EXTERNAL = ida_gdl.fcb_extern
    ERROR = ida_gdl.fcb_error


@decorate_all_methods(check_db_open)
class BasicBlock(DatabaseEntity):
    """
    Provides access to basic block properties and navigation
    between connected blocks within a control flow graph.
    """

    def __init__(
        self,
        database: Optional[Database],
        id: int,
        block: qbasic_block_t,
        flowchart: FlowChart,
    ) -> None:
        """
        Initialize basic block.

        Args:
            id: Block ID within the flowchart
            block: The underlying qbasic_block_t object
            flowchart: Parent flowchart
        """
        super().__init__(database)
        self._id = id
        self._raw = block
        self._flowchart = flowchart

    # -- raw access --------------------------------------------------------

    @property
    def raw_block(self) -> qbasic_block_t:
        """Get the underlying ``qbasic_block_t`` object."""
        return self._raw

    # -- basic properties --------------------------------------------------

    @property
    def id(self) -> int:
        """Block ID within the flowchart (same as its index)."""
        return self._id

    @property
    def start_ea(self) -> ea_t:
        """Start address of the block."""
        return self._raw.start_ea

    @property
    def end_ea(self) -> ea_t:
        """End address of the block (exclusive)."""
        return self._raw.end_ea

    @property
    def block_type(self) -> BlockType:
        """Block type as a :class:`BlockType` enum."""
        return BlockType(self._flowchart.raw_flowchart.calc_block_type(self._id))

    @property
    def is_return(self) -> bool:
        """True if the block returns from the function (conditionally or not)."""
        return self._flowchart.raw_flowchart.is_ret_block(self._id)

    @property
    def is_noreturn(self) -> bool:
        """True if the block does not return."""
        return self._flowchart.raw_flowchart.is_noret_block(self._id)

    @property
    def flowchart(self) -> FlowChart:
        """Parent flowchart."""
        return self._flowchart

    # -- navigation --------------------------------------------------------

    @property
    def successor_ids(self) -> List[int]:
        """List of successor block IDs."""
        return self._flowchart._successor_ids(self._id)

    @property
    def predecessor_ids(self) -> List[int]:
        """List of predecessor block IDs."""
        return self._flowchart._predecessor_ids(self._id)

    def get_successors(self) -> Iterator[BasicBlock]:
        """Iterator over successor blocks."""
        for i in self.successor_ids:
            yield self._flowchart[i]

    def get_predecessors(self) -> Iterator[BasicBlock]:
        """Iterator over predecessor blocks."""
        for i in self.predecessor_ids:
            yield self._flowchart[i]

    def count_successors(self) -> int:
        """Count the number of successor blocks."""
        return self._flowchart.raw_flowchart.nsucc(self._id)

    def count_predecessors(self) -> int:
        """Count the number of predecessor blocks."""
        return self._flowchart.raw_flowchart.npred(self._id)

    def get_instructions(self) -> Optional[Iterator[insn_t]]:
        """
        Retrieves all instructions within this basic block.

        Returns:
            An instruction iterator for this block.
        """
        return self.database.instructions.get_between(self.start_ea, self.end_ea)

    # -- deprecated --------------------------------------------------------

    @property
    def type(self) -> int:
        warnings.warn('BasicBlock.type deprecated, use block_type instead', DeprecationWarning)
        return int(self.block_type)

    def succs(self) -> Iterator[BasicBlock]:
        warnings.warn('succs deprecated, use get_successors instead', DeprecationWarning)
        return self.get_successors()

    def preds(self) -> Iterator[BasicBlock]:
        warnings.warn('preds deprecated, use get_predecessors instead', DeprecationWarning)
        return self.get_predecessors()

    # -- dunder ------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BasicBlock):
            return self._flowchart is other._flowchart and self._id == other._id
        return NotImplemented

    def __hash__(self) -> int:
        return hash((id(self._flowchart), self._id))

    def __repr__(self) -> str:
        return f'BasicBlock(id={self._id}, start_ea={self.start_ea:#x}, end_ea={self.end_ea:#x})'


@decorate_all_methods(check_db_open)
class FlowChart(BlockGraph[BasicBlock], DatabaseEntity):
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

        Raises:
            InvalidParameterError: If neither `func` nor `bounds` is specified,
                or `bounds` is not a valid range.
            InvalidEAError: If `bounds` contains an invalid address.

        Note:
            At least one of `func` or `bounds` must be specified.
        """
        DatabaseEntity.__init__(self, database)
        if func is None and bounds is None:
            raise InvalidParameterError('bounds', bounds, 'func or bounds must be specified')
        if bounds:
            if not self.database.is_valid_ea(bounds[0], strict_check=False):
                raise InvalidEAError(bounds[0])
            if not self.database.is_valid_ea(bounds[1], strict_check=False):
                raise InvalidEAError(bounds[1])
            if bounds[0] >= bounds[1]:
                raise InvalidParameterError('bounds', bounds, 'must be a valid range')

        start_ea, end_ea = bounds if bounds else (BADADDR, BADADDR)
        self._raw = qflow_chart_t('', func, start_ea, end_ea, int(flags))

    # -- raw access --------------------------------------------------------

    @property
    def raw_flowchart(self) -> qflow_chart_t:
        """Get the underlying ``qflow_chart_t`` object."""
        return self._raw

    def refresh(self) -> None:
        """Recompute the flowchart. Blocks obtained before the call are stale."""
        self._raw.refresh()

    # -- BlockGraph --------------------------------------------------------

    def _node_count(self) -> int:
        return self._raw.size()

    def _node(self, index: int) -> BasicBlock:
        return BasicBlock(self.m_database, index, self._raw[index], self)

    def _successor_ids(self, index: int) -> List[int]:
        return [self._raw.succ(index, j) for j in range(self._raw.nsucc(index))]

    def _predecessor_ids(self, index: int) -> List[int]:
        return [self._raw.pred(index, j) for j in range(self._raw.npred(index))]

    # -- deprecated --------------------------------------------------------

    @property
    def size(self) -> int:
        warnings.warn('FlowChart.size deprecated, use len() instead', DeprecationWarning)
        return len(self)
