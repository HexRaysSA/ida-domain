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

    def get_any(self, ea: ea_t) -> Optional[CommentInfo]:
        """
        Retrieves any comment at the specified address, checking both regular and repeatable.

        Args:
            ea: The effective address.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            A tuple (success, comment string). If no comment exists, success is False.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return self.get_at(ea, CommentKind.ALL)

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

    def delete_at(self, ea: int, comment_kind: CommentKind = CommentKind.REGULAR) -> bool:
        """
        Deletes a comment at the specified address.

        Args:
            ea: The effective address.
            comment_kind: Type of comment to delete (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if the comment was successfully deleted, False otherwise.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        repeatable = comment_kind == CommentKind.REPEATABLE
        return ida_bytes.set_cmt(ea, '', repeatable)

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

        while current < max_ea:
            # Check for regular comment
            if comment_kind in [CommentKind.REGULAR, CommentKind.ALL]:
                regular_comment = ida_bytes.get_cmt(current, False)
                if regular_comment:
                    yield CommentInfo(current, regular_comment, False)

            # Check for repeatable comment
            if comment_kind in [CommentKind.REPEATABLE, CommentKind.ALL]:
                repeatable_comment = ida_bytes.get_cmt(current, True)
                if repeatable_comment:
                    yield CommentInfo(current, repeatable_comment, True)

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
        ida_lines.update_extra_cmt(ea, base_idx + index, comment)
        return True

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

    def get_extra_all(self, ea: int, kind: ExtraCommentKind) -> Iterator[str]:
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
        ida_lines.del_extra_cmt(ea, base_idx + index)
        return True

    def set_function_comment(self, func: func_t, comment: str, repeatable: bool = False) -> bool:
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

    def get_function_comment(self, func: func_t, repeatable: bool = False) -> str:
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

    def set_segment_comment(
        self, segment: segment_t, comment: str, repeatable: bool = False
    ) -> bool:
        """
        Set comment for segment.

        Args:
            segment: The segment to set comment for.
            comment: Comment text to set.
            repeatable: If True, creates a repeatable comment (shows at all identical operands).
                        If False, creates a non-repeatable comment (shows only at this segment).

        Returns:
            True if successful, False otherwise.
        """
        try:
            ida_segment.set_segment_cmt(segment, comment, repeatable)
            return True
        except Exception:
            return False

    def get_segment_comment(self, segment: segment_t, repeatable: bool = False) -> str:
        """
        Get comment for segment.

        Args:
            segment: The segment to get comment from.
            repeatable: If True, retrieves repeatable comment (shows at all identical operands).
                        If False, retrieves non-repeatable comment (shows only at this segment).

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return ida_segment.get_segment_cmt(segment, repeatable) or ''

    def set_type_comment(self, type_info: tinfo_t, comment: str) -> bool:
        """
        Set comment for type.
        This function works only for non-trivial types

        Args:
            type_info: The type info object to set comment for.
            comment: Comment text to set.

        Returns:
            True if successful, False otherwise.
        """
        if type_info.set_type_cmt(comment) == 0:
            return True
        else:
            return False

    def get_type_comment(self, type_info: tinfo_t) -> str:
        """
        Get comment for type.

        Args:
            type_info: The type info object to get comment from.

        Returns:
            Comment text, or empty string if no comment exists.
        """
        return type_info.get_type_cmt() or ''
