from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum, IntEnum

import ida_bytes
import ida_nalt
import ida_strlist
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional, Pattern, Tuple, Union

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


class StringType(IntEnum):
    """String type constants."""

    C = ida_nalt.STRTYPE_C  # C-style null-terminated string
    C_16 = ida_nalt.STRTYPE_C_16  # C-style 16-bit string
    C_32 = ida_nalt.STRTYPE_C_32  # C-style 32-bit string
    PASCAL = ida_nalt.STRTYPE_PASCAL  # Pascal-style string
    PASCAL_16 = ida_nalt.STRTYPE_PASCAL_16  # Pascal-style 16-bit string
    PASCAL_32 = ida_nalt.STRTYPE_PASCAL_32  # Pascal-style 32-bit string
    LEN2 = ida_nalt.STRTYPE_LEN2  # String with 2-byte length prefix
    LEN2_16 = ida_nalt.STRTYPE_LEN2_16  # 16-bit string with 2-byte length prefix
    LEN2_32 = ida_nalt.STRTYPE_LEN2_32  # 32-bit string with 2-byte length prefix


class StringEncoding(Enum):
    """Common string encodings."""
    ASCII = "ascii"
    UTF8 = "utf-8"
    UTF16 = "utf-16"
    UTF16LE = "utf-16-le"
    UTF16BE = "utf-16-be"
    UTF32 = "utf-32"
    LATIN1 = "latin-1"

    @classmethod
    def from_string_type(cls, string_type: StringType) -> 'StringEncoding':
        """Convert StringType to appropriate encoding."""
        mapping = {
            StringType.C: cls.UTF8,
            StringType.C_16: cls.UTF16LE,
            StringType.C_32: cls.UTF32,
            StringType.PASCAL: cls.UTF8,
            StringType.PASCAL_16: cls.UTF16LE,
            StringType.PASCAL_32: cls.UTF32,
            StringType.LEN2: cls.UTF8,
            StringType.LEN2_16: cls.UTF16LE,
            StringType.LEN2_32: cls.UTF32,
        }
        return mapping.get(string_type, cls.ASCII)


@dataclass(frozen=True)
class StringInfo:
    """
    Represents detailed information about a string in the IDA database.
    """

    address: ea_t
    content: str
    length: int
    type: StringType

    def is_c_string(self) -> bool:
        """Check if this is a C-style null-terminated string."""
        return self.type in (StringType.C, StringType.C_16, StringType.C_32)

    def is_pascal_string(self) -> bool:
        """Check if this is a Pascal-style string."""
        return self.type in (StringType.PASCAL, StringType.PASCAL_16, StringType.PASCAL_32)

    def is_unicode(self) -> bool:
        """Check if this is a Unicode string."""
        return self.type in (
            StringType.C_16,
            StringType.C_32,
            StringType.PASCAL_16,
            StringType.PASCAL_32,
            StringType.LEN2_16,
            StringType.LEN2_32,
        )

    def get_encoding_info(self) -> str:
        """Get a human-readable description of the string encoding."""
        if self.type in (StringType.C_16, StringType.PASCAL_16, StringType.LEN2_16):
            return 'UTF-16'
        elif self.type in (StringType.C_32, StringType.PASCAL_32, StringType.LEN2_32):
            return 'UTF-32'
        else:
            return 'ASCII/UTF-8'

    def get_content(self, encoding: Optional[Union[str, StringEncoding]] = None,
                    errors: str = 'strict') -> str:
        """
        Get string content with flexible encoding support.

        Args:
            encoding: Encoding to use (defaults to auto-detection based on type)
            errors: How to handle encoding errors ('strict', 'ignore', 'replace')

        Returns:
            Decoded string content
        """
        if encoding is None:
            encoding = StringEncoding.from_string_type(self.type).value
        elif isinstance(encoding, StringEncoding):
            encoding = encoding.value

        # Get raw bytes from the address
        raw_bytes = ida_bytes.get_bytes(self.address, self.length)
        if raw_bytes:
            return raw_bytes.decode(encoding, errors=errors)
        return self.content

    def get_raw_content(self) -> bytes:
        """Get raw bytes of the string without decoding."""
        return ida_bytes.get_bytes(self.address, self.length) or b''


@dataclass(frozen=True)
class StringSearchResult:
    """Result of a string search operation."""
    address: ea_t
    content: str
    raw_bytes: bytes
    length: int
    string_type: Optional[StringType]
    match_start: int  # Offset within string where match starts
    match_end: int    # Offset within string where match ends

    def get_match_text(self) -> str:
        """Get the matched portion of the string."""
        return self.content[self.match_start:self.match_end]


@decorate_all_methods(check_db_open)
class Strings(DatabaseEntity):
    """
    Provides access to string-related operations in the IDA database.

    Can be used to iterate over all strings in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[Tuple[ea_t, str]]:
        return self.get_all()

    def __getitem__(self, index: int) -> Tuple[ea_t, str] | None:
        return self.get_at_index(index)

    def __len__(self) -> int:
        """
        Returns the total number of extracted strings.

        Returns:
            The number of stored strings.
        """
        return ida_strlist.get_strlist_qty()

    def get_count(self) -> int:
        """
        Retrieves the total number of extracted strings.

        Returns:
            The number of stored strings.
        """
        return ida_strlist.get_strlist_qty()

    def get_at_index(self, index: int) -> Tuple[ea_t, str] | None:
        """
        Retrieves the string at the specified index.

        Args:
            index: Index of the string to retrieve.

        Returns:
            A pair (effective address, string content) at the given index.
            In case of error, returns None.
        """
        if index >= 0 and index < ida_strlist.get_strlist_qty():
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, index):
                return si.ea, ida_bytes.get_strlit_contents(si.ea, -1, ida_nalt.STRTYPE_C).decode(
                    'utf-8'
                )
        raise IndexError(f'String index {index} out of range [0, {self.get_count()})')

    def get_at(self, ea: ea_t) -> StringInfo | None:
        """
        Retrieves detailed string information at the specified address.

        Args:
            ea: The effective address.

        Returns:
            A StringInfo object if found, None otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)
        # Find the string in the list
        for index in range(ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, index) and si.ea == ea:
                content = ida_bytes.get_strlit_contents(si.ea, -1, ida_nalt.STRTYPE_C)
                if content:
                    return StringInfo(
                        address=si.ea,
                        content=content.decode('utf-8', errors='replace'),
                        length=si.length,
                        type=StringType(si.type),
                    )
        return None

    def get_all(self) -> Iterator[Tuple[ea_t, str]]:
        """
        Retrieves an iterator over all extracted strings in the database.

        Returns:
            An iterator over all strings.
        """
        for current_index in range(0, ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, current_index):
                yield (
                    si.ea,
                    ida_bytes.get_strlit_contents(si.ea, -1, ida_nalt.STRTYPE_C).decode('utf-8'),
                )

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[Tuple[ea_t, str]]:
        """
        Retrieves strings within the specified address range.

        Args:
            start_ea: Start address of the range (inclusive).
            end_ea: End address of the range (exclusive).

        Returns:
            An iterator over strings in the range.

        Raises:
            InvalidEAError: If start_ea or end_ea are not within database bounds.
            InvalidParameterError: If start_ea >= end_ea.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        for index in range(ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, index):
                if start_ea <= si.ea < end_ea:
                    content = ida_bytes.get_strlit_contents(si.ea, -1, ida_nalt.STRTYPE_C)
                    if content:
                        yield si.ea, content.decode('utf-8', errors='replace')

    def build_string_list(self) -> None:
        """
        Rebuild the string list from scratch.
        This should be called to get an up-to-date string list.
        """
        ida_strlist.build_strlist()

    def clear_string_list(self) -> None:
        """
        Clear the string list.
        """
        ida_strlist.clear_strlist()

    def get_length(self, ea: ea_t) -> int:
        """
        Get the length at the specified address.

        Args:
            ea: The effective address.

        Returns:
            String length or -1 if not a string.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        result = self.get_at(ea)
        return result.length if result else -1

    def get_type(self, ea: ea_t) -> Union[StringType, int]:
        """
        Get the type at the specified address.

        Args:
            ea: The effective address.

        Returns:
            String type (StringType enum) or -1 if not a string.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        result = self.get_at(ea)
        return result.type if result else -1

    def exists_at(self, ea: ea_t) -> bool:
        """
        Check if the specified address contains a string.

        Args:
            ea: The effective address.

        Returns:
            True if address contains a string, False otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        return self.get_at(ea) is not None

    def find(
        self,
        pattern: Union[str, bytes, Pattern],
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
        encoding: Optional[Union[str, StringType, StringEncoding]] = None,
        case_sensitive: bool = True,
        whole_words: bool = False
    ) -> Optional[StringSearchResult]:
        """
        Find the first occurrence of a string pattern.

        Args:
            pattern: String, bytes, or compiled regex pattern to search for
            start_ea: Start address for search (default: database start)
            end_ea: End address for search (default: database end)
            encoding: String encoding or StringType to use
            case_sensitive: Whether search is case-sensitive
            whole_words: Match whole words only

        Returns:
            StringSearchResult with match details, or None if not found
        """
        for result in self.find_all(pattern, start_ea, end_ea, encoding, case_sensitive,
                                    whole_words, max_results=1):
            return result
        return None

    def find_all(
        self,
        pattern: Union[str, bytes, Pattern],
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
        encoding: Optional[Union[str, StringType, StringEncoding]] = None,
        case_sensitive: bool = True,
        whole_words: bool = False,
        max_results: Optional[int] = None
    ) -> Iterator[StringSearchResult]:
        """
        Find all occurrences of a string pattern.

        Args:
            pattern: String, bytes, or compiled regex pattern
            start_ea: Start address for search
            end_ea: End address for search
            encoding: String encoding or StringType
            case_sensitive: Whether search is case-sensitive
            whole_words: Match whole words only
            max_results: Maximum number of results to return

        Yields:
            StringSearchResult objects for each match
        """
        # Set defaults
        start_ea = start_ea or self.database.minimum_ea
        end_ea = end_ea or self.database.maximum_ea

        # Validate addresses
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        # Determine encoding
        if isinstance(encoding, StringType):
            encoding = StringEncoding.from_string_type(encoding)
        elif encoding is None:
            encoding = StringEncoding.UTF8
        elif isinstance(encoding, str):
            encoding = StringEncoding(encoding)

        # Prepare pattern
        compiled_pattern: Optional[Pattern[str]] = None
        pattern_str: str = ""

        if isinstance(pattern, bytes):
            pattern_str = pattern.decode(encoding.value, errors='replace')
            is_regex = False
        elif isinstance(pattern, str):
            pattern_str = pattern
            is_regex = False
        else:  # Pattern object
            compiled_pattern = pattern
            is_regex = True
            if not case_sensitive and not pattern.flags & re.IGNORECASE:
                # Recompile with IGNORECASE
                compiled_pattern = re.compile(pattern.pattern, pattern.flags | re.IGNORECASE)

        # For non-regex patterns, handle case sensitivity
        if not is_regex and not case_sensitive:
            pattern_str = pattern_str.lower()

        # Word boundary regex if needed
        if whole_words and not is_regex:
            compiled_pattern = re.compile(r'\b' + re.escape(pattern_str) + r'\b',
                                        re.IGNORECASE if not case_sensitive else 0)
            is_regex = True

        # Build string list if needed
        self.build_string_list()

        # Search through strings
        results_count = 0
        for index in range(ida_strlist.get_strlist_qty()):
            if max_results is not None and results_count >= max_results:
                break

            si = ida_strlist.string_info_t()
            if not ida_strlist.get_strlist_item(si, index):
                continue

            # Check address range
            if not (start_ea <= si.ea < end_ea):
                continue

            # Get string content
            str_info = self.get_at(si.ea)
            if not str_info:
                continue

            content = str_info.get_content(encoding, errors='replace')
            search_content = content if case_sensitive or is_regex else content.lower()

            # Find matches
            if is_regex and compiled_pattern:
                matches = list(compiled_pattern.finditer(search_content))
            else:
                # Simple string search
                matches = []
                start_pos = 0
                while True:
                    pos = search_content.find(pattern_str, start_pos)
                    if pos == -1:
                        break
                    matches.append(type('Match', (), {
                        'start': lambda: pos,
                        'end': lambda: pos + len(pattern_str)
                    })())
                    start_pos = pos + 1

            # Yield results
            for match in matches:
                if max_results is not None and results_count >= max_results:
                    break

                raw_bytes = ida_bytes.get_bytes(si.ea, si.length) or b''

                yield StringSearchResult(
                    address=si.ea,
                    content=content,
                    raw_bytes=raw_bytes,
                    length=si.length,
                    string_type=str_info.type,
                    match_start=match.start(),
                    match_end=match.end()
                )
                results_count += 1

    def find_next(
        self,
        pattern: Union[str, bytes, Pattern],
        current_ea: ea_t,
        encoding: Optional[Union[str, StringType, StringEncoding]] = None,
        case_sensitive: bool = True,
        whole_words: bool = False,
        wrap_around: bool = False
    ) -> Optional[StringSearchResult]:
        """
        Find next occurrence starting from current address.

        Args:
            pattern: Pattern to search for
            current_ea: Current address to start search after
            encoding: String encoding
            case_sensitive: Case sensitivity flag
            whole_words: Whole word matching
            wrap_around: Wrap to beginning if end reached

        Returns:
            Next match or None
        """
        # First search from current position to end
        result = self.find(pattern, current_ea + 1, None, encoding, case_sensitive, whole_words)

        # If not found and wrap_around, search from beginning
        if result is None and wrap_around and current_ea > self.database.minimum_ea:
            result = self.find(pattern, None, current_ea, encoding, case_sensitive, whole_words)

        return result
