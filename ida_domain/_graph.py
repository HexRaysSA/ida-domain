from __future__ import annotations

from abc import ABC, abstractmethod

from typing_extensions import Generic, Iterator, List, TypeVar

N = TypeVar('N')


class BlockGraph(ABC, Generic[N]):
    """
    Base class for graphs of basic blocks identified by index (0..len-1).

    Subclasses provide node construction and adjacency; iteration and
    traversal are implemented here once.
    """

    @abstractmethod
    def _node_count(self) -> int: ...

    @abstractmethod
    def _node(self, index: int) -> N: ...

    @abstractmethod
    def _successor_ids(self, index: int) -> List[int]: ...

    @abstractmethod
    def _predecessor_ids(self, index: int) -> List[int]: ...

    # -- iteration ---------------------------------------------------------

    def __iter__(self) -> Iterator[N]:
        """Iterate over all blocks."""
        for i in range(self._node_count()):
            yield self._node(i)

    def __getitem__(self, index: int) -> N:
        """
        Access a block by index.

        Args:
            index: The index of the block to retrieve.

        Returns:
            The block at the specified index.

        Raises:
            IndexError: If index is out of range.
        """
        count = self._node_count()
        if not (0 <= index < count):
            raise IndexError(f'Basic block index {index} out of range (0-{count - 1})')
        return self._node(index)

    def __len__(self) -> int:
        return self._node_count()

    # -- traversal ---------------------------------------------------------

    def dfs_preorder(self, start: int = 0) -> Iterator[N]:
        """
        Depth-first traversal following successor edges.

        Args:
            start: Index of the block to start from.

        Returns:
            An iterator over the blocks reachable from `start`, in pre-order.
        """
        if not (0 <= start < self._node_count()):
            return
        seen = {start}
        stack = [start]
        while stack:
            i = stack.pop()
            yield self._node(i)
            for s in reversed(self._successor_ids(i)):
                if s not in seen:
                    seen.add(s)
                    stack.append(s)

    def reverse_postorder(self, start: int = 0) -> List[N]:
        """
        Blocks reachable from `start` in reverse post-order.

        Args:
            start: Index of the block to start from.

        Returns:
            The reachable blocks in reverse post-order (a topological order
            if the graph is acyclic).
        """
        if not (0 <= start < self._node_count()):
            return []
        order: List[int] = []
        seen = {start}
        stack = [(start, iter(self._successor_ids(start)))]
        while stack:
            i, it = stack[-1]
            for s in it:
                if s not in seen:
                    seen.add(s)
                    stack.append((s, iter(self._successor_ids(s))))
                    break
            else:
                stack.pop()
                order.append(i)
        return [self._node(i) for i in reversed(order)]
