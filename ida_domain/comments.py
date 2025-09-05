from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from itertools import repeat

import ida_bytes
import ida_funcs
import ida_lines
import ida_segment
import ida_typeinf
from ida_funcs import func_t
from ida_ida import inf_get_max_ea, inf_get_min_ea
from ida_idaapi import BADADDR, ea_t
from ida_segment import segment_t
from ida_typeinf import tinfo_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

from .base import DatabaseEntity, InvalidEAError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger(__name__)


class CommentKind(Enum):
    """
    Enumeration for IDA comment types.
    """

    REGULAR = 'regular'
    REPEATABLE = 'repeatable'
    ALL = 'all'


class ExtraCommentKind(Enum):
    """
    Enumeration for extra comment positions.
    """

    ANTERIOR = 'anterior'  # Comments before the line (E_PREV)
    POSTERIOR = 'posterior'  # Comments after the line (E_NEXT)


@dataclass(frozen=True)
class CommentInfo:
    """
    Represents information about a Comment.
    """

    ea: ea_t
    comment: str
    repeatable: bool


@decorate_all_methods(check_db_open)
class Comments(DatabaseEntity):
    """
    Provides access to user-defined comments in the IDA database.

    Can be used to iterate over all comments in the opened database.

    IDA supports two types of comments:
    - Regular comments: Displayed at specific addresses
    - Repeatable comments: Displayed at all references to the same address

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[CommentInfo]:
        return self.get_all()

    def get_at(
        self, ea: ea_t, comment_kind: CommentKind = CommentKind.REGULAR
    ) -> Optional[CommentInfo]:
        """
        Retrieves the comment at the specified address.

        Args:
            ea: The effective address.
            comment_kind: Type of comment to retrieve (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            The comment string, or None if no comment exists.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        if comment_kind == CommentKind.ALL:
            # Try regular comment first, then repeatable
            for is_repeatable in [False, True]:
                comment = ida_bytes.get_cmt(ea, is_repeatable)
                if comment:
                    return CommentInfo(ea, comment, is_repeatable)
            return None

        # Handle REGULAR and REPEATABLE cases
        is_repeatable = comment_kind == CommentKind.REPEATABLE
        comment = ida_bytes.get_cmt(ea, is_repeatable)
        return CommentInfo(ea, comment, is_repeatable) if comment else None

    def set_at(
        self, ea: int, comment: str, comment_kind: CommentKind = CommentKind.REGULAR
    ) -> bool:
        """
        Sets a comment at the specified address.

        Args:
            ea: The effective address.
            comment: The comment text to assign.
            comment_kind: Type of comment to set (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if the comment was successfully set, False otherwise.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        repeatable = comment_kind == CommentKind.REPEATABLE
        return ida_bytes.set_cmt(ea, comment, repeatable)

    def delete_at(self, ea: int, comment_kind: CommentKind = CommentKind.REGULAR) -> None:
        """
        Deletes a comment at the specified address.

        Args:
            ea: The effective address.
            comment_kind: Type of comment to delete (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        comment_types = (
            [False, True]
            if comment_kind == CommentKind.ALL
            else [comment_kind == CommentKind.REPEATABLE]
        )
        for is_repeatable in comment_types:
            ida_bytes.set_cmt(ea, '', is_repeatable)

    def get_all(self, comment_kind: CommentKind = CommentKind.REGULAR) -> Iterator[CommentInfo]:
        """
        Creates an iterator for comments in the database.

        Args:
            comment_kind: Type of comments to retrieve:
                - CommentKind.REGULAR: Only regular comments
                - CommentKind.REPEATABLE: Only repeatable comments
                - CommentKind.ALL: Both regular and repeatable comments

        Yields:
            Tuples of (address, comment_text, is_repeatable) for each comment found.
        """
        current = inf_get_min_ea()
        max_ea = inf_get_max_ea()

        comment_types = (
            [False, True]
            if comment_kind == CommentKind.ALL
            else [comment_kind == CommentKind.REPEATABLE]
        )
        while current < max_ea:
            # Check for regular comment
            for is_repeatable in comment_types:
                comment = ida_bytes.get_cmt(current, is_repeatable)
                if comment:
                    yield CommentInfo(current, comment, is_repeatable)

            # Move to next head (instruction or data)
            next_addr = ida_bytes.next_head(current, max_ea)
            if next_addr == current or next_addr == BADADDR:
                break
            current = next_addr

    def set_extra_at(self, ea: int, index: int, comment: str, kind: ExtraCommentKind) -> bool:
        """
        Sets an extra comment at the specified address and index.

        Args:
            ea: The effective address.
            index: The comment index (0-based).
            comment: The comment text.
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if successful.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        base_idx = ida_lines.E_PREV if kind == ExtraCommentKind.ANTERIOR else ida_lines.E_NEXT
        return ida_lines.update_extra_cmt(ea, base_idx + index, comment)

    def get_extra_at(self, ea: int, index: int, kind: ExtraCommentKind) -> Optional[str]:
        """
        Gets a specific extra comment.

        Args:
            ea: The effective address.
            index: The comment index (0-based).
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            The comment text or None if not found.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        base_idx = ida_lines.E_PREV if kind == ExtraCommentKind.ANTERIOR else ida_lines.E_NEXT
        return ida_lines.get_extra_cmt(ea, base_idx + index)

    def get_all_extra_at(self, ea: int, kind: ExtraCommentKind) -> Iterator[str]:
        """
        Gets all extra comments of a specific kind.

        Args:
            ea: The effective address.
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Yields:
            Comment strings in order.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        base_idx = ida_lines.E_PREV if kind == ExtraCommentKind.ANTERIOR else ida_lines.E_NEXT
        index = 0
        while True:
            comment = ida_lines.get_extra_cmt(ea, base_idx + index)
            if comment is None:
                break
            yield comment
            index += 1

    def delete_extra_at(self, ea: int, index: int, kind: ExtraCommentKind) -> bool:
        """
        Deletes a specific extra comment.

        Args:
            ea: The effective address.
            index: The comment index (0-based).
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if successful.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        base_idx = ida_lines.E_PREV if kind == ExtraCommentKind.ANTERIOR else ida_lines.E_NEXT
        return ida_lines.del_extra_cmt(ea, base_idx + index)
