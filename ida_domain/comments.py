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
        self, ea: ea_t, comment: str, comment_kind: CommentKind = CommentKind.REGULAR
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
        return cast(bool, ida_bytes.set_cmt(ea, comment, repeatable))

    def delete_at(self, ea: ea_t, comment_kind: CommentKind = CommentKind.REGULAR) -> bool:
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

        comment_types = (
            [False, True]
            if comment_kind == CommentKind.ALL
            else [comment_kind == CommentKind.REPEATABLE]
        )
        for is_repeatable in comment_types:
            ida_bytes.set_cmt(ea, '', is_repeatable)
        return True

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

    def set_extra_at(self, ea: ea_t, index: int, comment: str, kind: ExtraCommentKind) -> bool:
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
        return cast(bool, ida_lines.update_extra_cmt(ea, base_idx + index, comment))

    def get_extra_at(self, ea: ea_t, index: int, kind: ExtraCommentKind) -> Optional[str]:
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
        return cast(Optional[str], ida_lines.get_extra_cmt(ea, base_idx + index))

    def get_all_extra_at(self, ea: ea_t, kind: ExtraCommentKind) -> Iterator[str]:
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

    def delete_extra_at(self, ea: ea_t, index: int, kind: ExtraCommentKind) -> bool:
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
        return cast(bool, ida_lines.del_extra_cmt(ea, base_idx + index))

    def delete_all_extra_at(self, ea: ea_t, kind: ExtraCommentKind) -> int:
        """
        Delete all extra comments of a specific kind at an address.

        Args:
            ea: The effective address of the extra comments.
            kind: Position of comments to delete (ANTERIOR or POSTERIOR).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Number of comments deleted.

        Example:
            >>> db = Database.open_current()
            >>> count = db.comments.delete_all_extra_at(0x401000, ExtraCommentKind.ANTERIOR)
            >>> print(f"Deleted {count} comment lines")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        count = 0
        # Keep deleting index 0 until no more comments exist
        # (deleting shifts subsequent comments down)
        while True:
            comment = self.get_extra_at(ea, 0, kind)
            if comment is None:
                break
            if self.delete_extra_at(ea, 0, kind):
                count += 1
            else:
                break  # Deletion failed, stop trying

        return count

    def get_first_free_extra_index(
        self, ea: ea_t, kind: ExtraCommentKind, start_index: int = 0
    ) -> int:
        """
        Find the first available (unused) extra comment index at an address.

        Args:
            ea: Effective address to check.
            kind: Position of comments (ANTERIOR or POSTERIOR).
            start_index: Starting index for the search (default: 0).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            First available index where no comment exists.

        Example:
            >>> db = Database.open_current()
            >>> free_idx = db.comments.get_first_free_extra_index(
            ...     0x401000, ExtraCommentKind.ANTERIOR
            ... )
            >>> db.comments.set_extra_at(
            ...     0x401000, free_idx, "New comment line", ExtraCommentKind.ANTERIOR
            ... )
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        index = start_index
        while True:
            comment = self.get_extra_at(ea, index, kind)
            if comment is None:
                return index
            index += 1

    def generate_disasm_line(self, ea: ea_t, remove_tags: bool = False) -> str:
        """
        Generate a single disassembly line for the specified address.

        Args:
            ea: Effective address to disassemble.
            remove_tags: If True, remove color tags from the output (default: False).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Disassembly line as a string (may contain color tags unless remove_tags=True).

        Example:
            >>> db = Database.open_current()
            >>> line = db.comments.generate_disasm_line(0x401000)
            >>> print(line)  # May contain color escape codes
            >>> plain_line = db.comments.generate_disasm_line(0x401000, remove_tags=True)
            >>> print(plain_line)  # Clean text, no color codes
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Generate disassembly with appropriate flags
        flags = ida_lines.GENDSM_REMOVE_TAGS if remove_tags else 0
        line = ida_lines.generate_disasm_line(ea, flags)

        return line if line else ''

    def generate_disassembly(
        self, ea: ea_t, max_lines: int, as_stack: bool = False, remove_tags: bool = False
    ) -> tuple[int, list[str]]:
        """
        Generate multiple disassembly lines with importance ranking.

        Args:
            ea: Starting effective address.
            max_lines: Maximum number of lines to generate.
            as_stack: If True, treat address as stack location (default: False).
            remove_tags: If True, remove color tags from output (default: False).

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Tuple of (important_line_index, list_of_disassembly_lines).
            The important_line_index indicates which line is most relevant
            (typically the one at ea).

        Example:
            >>> db = Database.open_current()
            >>> important_idx, lines = db.comments.generate_disassembly(
            ...     0x401000, max_lines=5, remove_tags=True
            ... )
            >>> for i, line in enumerate(lines):
            ...     marker = ">>>" if i == important_idx else "   "
            ...     print(f"{marker} {line}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Set flags based on parameters
        flags = 0
        if as_stack:
            flags |= ida_lines.GENDSM_FORCE_CODE  # Treat as code even if stack
        if remove_tags:
            flags |= ida_lines.GENDSM_REMOVE_TAGS

        # Generate disassembly lines
        lines = []
        current_ea = ea
        max_ea = inf_get_max_ea()

        for _ in range(max_lines):
            line = ida_lines.generate_disasm_line(current_ea, flags)
            if line:
                lines.append(line)
            else:
                break

            # Move to next address
            next_ea = ida_bytes.next_head(current_ea, max_ea)
            if next_ea == BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        # Important line is typically the first one (index 0)
        important_idx = 0

        return (important_idx, lines)

    def strip_color_tags(self, text: str) -> str:
        """
        Remove all color tags from a string.

        Args:
            text: String potentially containing color tags.

        Returns:
            String with all color tags removed.

        Example:
            >>> db = Database.open_current()
            >>> colored = db.comments.generate_disasm_line(0x401000, remove_tags=False)
            >>> clean = db.comments.strip_color_tags(colored)
            >>> print(clean)  # Plain text without color codes
        """
        return cast(str, ida_lines.tag_remove(text))

    def calculate_visual_length(self, text: str) -> int:
        """
        Calculate the visual (display) length of a string, excluding color tags.

        Args:
            text: String potentially containing color tags.

        Returns:
            Visual length (number of visible characters).

        Example:
            >>> db = Database.open_current()
            >>> colored = db.comments.generate_disasm_line(0x401000)
            >>> visual_len = db.comments.calculate_visual_length(colored)
            >>> actual_len = len(colored)
            >>> print(f"Visual length: {visual_len}, Actual length: {actual_len}")
        """
        return cast(int, ida_lines.tag_strlen(text))

    def skip_color_tags(self, text: str, start_offset: int = 0) -> int:
        """
        Skip past all color tags starting at the given offset.

        Args:
            text: String containing color tags.
            start_offset: Starting position in the string (default: 0).

        Returns:
            Offset past all consecutive color tags.

        Example:
            >>> db = Database.open_current()
            >>> colored = db.comments.generate_disasm_line(0x401000)
            >>> offset = db.comments.skip_color_tags(colored)
            >>> print(f"First visible character at offset {offset}")
        """
        # tag_skipcodes only takes the string, returns offset to first non-tag char
        # We need to handle start_offset manually by slicing
        if start_offset > 0:
            substring = text[start_offset:]
            result = ida_lines.tag_skipcodes(substring)
            return start_offset + result if result is not None else start_offset
        return ida_lines.tag_skipcodes(text) if ida_lines.tag_skipcodes(text) is not None else 0

    def advance_in_colored_string(self, text: str, count: int, start_offset: int = 0) -> int:
        """
        Advance a position in a colored string by a given number of visible characters.

        Args:
            text: String containing color tags.
            count: Number of visible characters to advance.
            start_offset: Starting position in the string (default: 0).

        Returns:
            New offset after advancing count visible characters (accounting for color tags).

        Example:
            >>> db = Database.open_current()
            >>> colored = db.comments.generate_disasm_line(0x401000)
            >>> offset = db.comments.advance_in_colored_string(colored, 10)
            >>> substring = colored[:offset]
        """
        # tag_advance takes (string, count) and advances from beginning
        # We need to handle start_offset manually
        if start_offset > 0:
            substring = text[start_offset:]
            result = ida_lines.tag_advance(substring, count)
            return start_offset + result if result is not None else start_offset
        result = ida_lines.tag_advance(text, count)
        return result if result is not None else 0

    def colorize(self, text: str, color_code: int) -> str:
        """
        Create a colored string by wrapping text with color tags.

        Args:
            text: Text to colorize.
            color_code: IDA color code (SCOLOR_* constant from ida_lines).

        Returns:
            String with color tags applied.

        Example:
            >>> db = Database.open_current()
            >>> import ida_lines
            >>> colored = db.comments.colorize("mov eax, 1", ida_lines.SCOLOR_INSN)
            >>> colored_reg = db.comments.colorize("eax", ida_lines.SCOLOR_REG)
            >>> print(f"Instruction: {colored}")
            >>> print(f"Register: {colored_reg}")
        """
        return cast(str, ida_lines.COLSTR(text, color_code))

    def requires_color_escape(self, char: str) -> bool:
        """
        Check if a character requires escaping in colored strings.

        Args:
            char: Single character to check.

        Returns:
            True if the character needs escaping, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> if db.comments.requires_color_escape('\\x01'):
            ...     print("Character needs escaping in colored strings")
        """
        if len(char) != 1:
            return False
        return cast(bool, ida_lines.requires_color_esc(ord(char)))

    def get_prefix_color(self, ea: ea_t) -> int:
        """
        Get the line prefix color for an address.

        Args:
            ea: Effective address.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Color code for the line prefix.

        Example:
            >>> db = Database.open_current()
            >>> color = db.comments.get_prefix_color(0x401000)
            >>> print(f"Prefix color code: {color:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(int, ida_lines.calc_prefix_color(ea))

    def get_background_color(self, ea: ea_t) -> int:
        """
        Get the background color for an address.

        Args:
            ea: Effective address.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Background color code.

        Example:
            >>> db = Database.open_current()
            >>> bg_color = db.comments.get_background_color(0x401000)
            >>> print(f"Background color code: {bg_color:#x}")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(int, ida_lines.calc_bg_color(ea))

    def add_sourcefile(self, start_ea: ea_t, end_ea: ea_t, filename: str) -> bool:
        """
        Map an address range to a source file.

        Args:
            start_ea: Starting effective address of the range.
            end_ea: Ending effective address of the range.
            filename: Path to the source file.

        Raises:
            InvalidEAError: If either address is invalid.
            InvalidParameterError: If start_ea >= end_ea.

        Returns:
            True if the mapping was successfully added, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> success = db.comments.add_sourcefile(0x401000, 0x401200, "main.c")
            >>> if success:
            ...     print("Source file mapping created")
        """
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        return cast(bool, ida_lines.add_sourcefile(start_ea, end_ea, filename))

    def get_sourcefile(self, ea: ea_t) -> Optional[tuple[str, int, int]]:
        """
        Get the source file mapping for an address.

        Args:
            ea: Effective address to query.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            Tuple of (filename, start_ea, end_ea) if a mapping exists, or None if no mapping found.

        Example:
            >>> db = Database.open_current()
            >>> mapping = db.comments.get_sourcefile(0x401000)
            >>> if mapping:
            ...     filename, start, end = mapping
            ...     print(f"Address {0x401000:#x} maps to {filename} ({start:#x}-{end:#x})")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Get filename
        filename = ida_lines.get_sourcefile(ea)
        if filename is None:
            return None

        # Note: IDA's API doesn't expose a direct way to get bounds
        # We return the filename with the query address as both start and end
        # This is a known limitation of the legacy API
        return (filename, ea, ea)

    def delete_sourcefile(self, ea: ea_t) -> bool:
        """
        Delete the source file mapping containing the specified address.

        Args:
            ea: Effective address within the mapping to delete.

        Raises:
            InvalidEAError: If the effective address is invalid.

        Returns:
            True if a mapping was deleted, False if no mapping existed.

        Example:
            >>> db = Database.open_current()
            >>> if db.comments.delete_sourcefile(0x401000):
            ...     print("Source file mapping removed")
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        return cast(bool, ida_lines.del_sourcefile(ea))
