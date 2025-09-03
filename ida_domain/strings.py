from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum

import ida_bytes
import ida_nalt
import ida_strlist
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional, Tuple, Union

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


@dataclass(frozen=True)
class StringInfo:
    """
    Represents detailed information about a string in the IDA database.
    """

    address: ea_t
    content: str
    length: int
    type: StringType


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

    def get_at(self, ea: ea_t) -> Optional[StringInfo]:
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
