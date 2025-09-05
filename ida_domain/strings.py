from __future__ import annotations

import logging
from dataclasses import dataclass, field
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
    LEN4 = ida_nalt.STRTYPE_LEN4  # Pascal-style, four-byte length prefix
    LEN4_16 = ida_nalt.STRTYPE_LEN4_16  # Pascal-style, 16bit chars, four-byte length prefix
    LEN4_32 = ida_nalt.STRTYPE_LEN4_32  # Pascal-style, 32bit chars, four-byte length prefix


@dataclass(frozen=True)
class StringItem:
    """
    Represents detailed information about a string in the IDA database.
    """

    address: ea_t
    length: int
    type: StringType

    @property
    def contents(self) -> bytes:
        return ida_bytes.get_strlit_contents(self.address, self.length, self.type)

    def __str__(self) -> str:
        return self.contents.decode('UTF-8')

    def __bytes__(self) -> bytes:
        return self.contents


@dataclass()
class StringListConfig:
    """
    Configuration for building the internal string list.
    """

    string_types: list[StringType] = field(default_factory=lambda: [StringType.C])
    min_len: int = 5
    only_ascii_7bit: bool = True
    only_existing: bool = False
    ignore_instructions: bool = False


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
        self._si = ida_strlist.string_info_t()

    def __iter__(self) -> Iterator[StringItem]:
        return self.get_all()

    def __getitem__(self, index: int) -> StringItem:
        return self.get_at_index(index)

    def __len__(self) -> int:
        """
        Returns the total number of extracted strings.
        """
        return ida_strlist.get_strlist_qty()

    def get_at_index(self, index: int) -> StringItem:
        """
        Retrieves the string at the specified index.

        Args:
            index: Index of the string to retrieve.

        Returns:
            A StringItem object at the given index.
            In case of error, returns None.
        """
        if 0 <= index < len(self):
            if ida_strlist.get_strlist_item(self._si, index):
                return StringItem(
                    address=self._si.ea, length=self._si.length, type=StringType(self._si.type)
                )
        raise IndexError(f'String index {index} out of range [0, {len(self)})')

    def get_at(self, ea: ea_t) -> Optional[StringItem]:
        """
        Retrieves detailed string information at the specified address.

        Args:
            ea: The effective address.

        Returns:
            A StringItem object if found, None otherwise.

        Raises:
            InvalidEAError: If the effective address is invalid.
        """
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Find the string in the list
        for item in self:
            if item.address == ea:
                return item

        return None

    def get_all(self) -> Iterator[StringItem]:
        """
        Retrieves an iterator over all extracted strings in the database.

        Returns:
            An iterator over all strings.
        """
        return (self.get_at_index(index) for index in range(0, ida_strlist.get_strlist_qty()))

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[StringItem]:
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

        for item in self:
            if start_ea <= item.address < end_ea:
                yield item

    def rebuild(self, config: StringListConfig = StringListConfig()) -> None:
        """
        Rebuild the string list from scratch.
        This should be called to get an up-to-date string list.
        """
        opts = ida_strlist.get_strlist_options()
        opts.strtypes = config.string_types
        opts.minlen = config.min_len
        opts.only_7bit = config.only_ascii_7bit
        opts.display_only_existing_strings = config.only_existing
        opts.ignore_heads = config.ignore_instructions
        ida_strlist.build_strlist()

    def clear(self) -> None:
        """
        Clear the string list, strings will not be saved in the database.
        """
        ida_strlist.clear_strlist()
