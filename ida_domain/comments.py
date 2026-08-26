from __future__ import annotations

import logging
from collections.abc import Iterable
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


_EXTRA_COMMENT_SLOT_COUNTS = {
    ExtraCommentKind.ANTERIOR: ida_lines.E_NEXT - ida_lines.E_PREV - 1,
    ExtraCommentKind.POSTERIOR: ida_lines.E_NEXT - ida_lines.E_PREV,
}


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

        comment_types = (
            [False, True]
            if comment_kind == CommentKind.ALL
            else [comment_kind == CommentKind.REPEATABLE]
        )
        return all(
            ida_bytes.set_cmt(ea, comment, is_repeatable) for is_repeatable in comment_types
        )

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

    def append_at(
        self, ea: ea_t, comment: str, comment_kind: CommentKind = CommentKind.REGULAR
    ) -> bool:
        """
        Appends text to a comment at the specified address.

        If the selected comment does not exist, it is created with the given
        text. Otherwise, a newline followed by the supplied text is appended.
        This method always works on the item comment. Function comments are
        managed by the functions API.

        Args:
            ea: The effective address. Must not be a tail byte of a multi-byte
                item.
            comment: The comment text to append.
            comment_kind: Type of comment to append to (REGULAR or REPEATABLE).

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If ``ea`` is a tail byte or ``comment_kind``
                is ``ALL``.

        Returns:
            True if the comment was successfully appended, False otherwise.

        Warning:
            IDA caps regular and repeatable comments at 1024 bytes of UTF-8
            and silently truncates longer text, so appending to a comment
            near that limit drops the excess even though True is returned.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        if self.database.bytes.is_tail_at(ea):
            raise InvalidParameterError('ea', ea, 'the address must not be an item tail byte')
        if comment_kind == CommentKind.ALL:
            raise InvalidParameterError(
                'comment_kind',
                comment_kind,
                'appending to both comment kinds at once is not supported',
            )
        is_repeatable = comment_kind == CommentKind.REPEATABLE
        existing = ida_bytes.get_cmt(ea, is_repeatable)
        combined = f'{existing}\n{comment}' if existing else comment
        return ida_bytes.set_cmt(ea, combined, is_repeatable)

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

    def set_extra_lines_at(self, ea: ea_t, lines: Iterable[str], kind: ExtraCommentKind) -> bool:
        """
        Replaces all extra comment lines of one kind at the specified address.

        Passing an empty iterable deletes all lines of that kind. The input
        iterable is consumed before the existing comments are changed. A line
        containing line breaks is split into separate comment lines.

        Args:
            ea: The effective address.
            lines: Comment lines in display order, at most 999 for ANTERIOR
                and 1000 for POSTERIOR.
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.
            InvalidParameterError: If ``lines`` is a single string instead of
                an iterable of strings, contains a non-string element, or
                exceeds the supported line count. The existing comment lines
                are left unchanged in this case.

        Returns:
            True if the existing lines were deleted and every new line was
            successfully set, False otherwise.

        Note:
            IDA does not provide a transactional bulk update. The existing
            lines are deleted before the new ones are written, so if setting
            a line fails, the original lines are already lost and only a
            partial replacement remains stored.

        Warning:
            IDA caps each line at 1024 bytes of UTF-8 and silently truncates
            longer lines even though True is returned.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        if isinstance(lines, str):
            raise InvalidParameterError(
                'lines', lines, 'must be an iterable of strings, not a single string'
            )

        materialized_lines: list[str] = []
        for line in lines:
            if not isinstance(line, str):
                raise InvalidParameterError('lines', line, 'every comment line must be a string')
            materialized_lines.extend(line.replace('\r\n', '\n').replace('\r', '\n').split('\n'))

        slot_count = _EXTRA_COMMENT_SLOT_COUNTS[kind]
        if len(materialized_lines) > slot_count:
            raise InvalidParameterError(
                'lines',
                len(materialized_lines),
                f'at most {slot_count} {kind.value} comment lines are supported '
                f'(counted after splitting embedded line breaks)',
            )

        if not self.delete_extra_lines_at(ea, kind):
            return False
        for index, comment in enumerate(materialized_lines):
            if not self.set_extra_at(ea, index, comment, kind):
                return False
        return True

    def delete_extra_lines_at(self, ea: ea_t, kind: ExtraCommentKind) -> bool:
        """
        Deletes all extra comment lines of one kind at the specified address.

        Lines stored after a gap, which are invisible in the listing, are
        deleted as well.

        Args:
            ea: The effective address.
            kind: ANTERIOR or POSTERIOR.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if every line was successfully deleted, False otherwise.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        base_idx = ida_lines.E_PREV if kind == ExtraCommentKind.ANTERIOR else ida_lines.E_NEXT
        success = True
        for index in range(base_idx, base_idx + _EXTRA_COMMENT_SLOT_COUNTS[kind]):
            if ida_lines.get_extra_cmt(ea, index) is not None:
                success = ida_lines.del_extra_cmt(ea, index) and success
        return success

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

    def get_combined_at(
        self,
        ea: ea_t,
        *,
        include_regular: bool = True,
        include_repeatable: bool = True,
        include_anterior: bool = True,
        include_posterior: bool = True,
    ) -> Optional[str]:
        """
        Combines the selected comments at an address into one text block.

        Lines are returned in listing order: anterior comments, the regular
        or repeatable comment, and posterior comments. Matching the listing
        behavior, the repeatable comment is used only when no regular comment
        is included. Extra comment lines stored after a missing index are
        omitted. On a tail byte, the regular and repeatable comments are read
        from the item head.

        Args:
            ea: The effective address.
            include_regular: Include the regular comment.
            include_repeatable: Include the repeatable comment.
            include_anterior: Include anterior comment lines.
            include_posterior: Include posterior comment lines.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            The selected comments joined by newlines, or None if none exist.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        comments: list[str] = []
        if include_anterior:
            comments.extend(self.get_all_extra_at(ea, ExtraCommentKind.ANTERIOR))

        displayed = self.get_at(ea, CommentKind.REGULAR) if include_regular else None
        if displayed is None and include_repeatable:
            displayed = self.get_at(ea, CommentKind.REPEATABLE)
        if displayed is not None:
            comments.append(displayed.comment)

        if include_posterior:
            comments.extend(self.get_all_extra_at(ea, ExtraCommentKind.POSTERIOR))

        return '\n'.join(comments) if comments else None

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
