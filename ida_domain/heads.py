from __future__ import annotations

import logging

import ida_bytes
import ida_ida
import ida_idaapi
import idc
from ida_idaapi import ea_t
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


@decorate_all_methods(check_db_open)
class Heads(DatabaseEntity):
    """
    Provides access to heads (instructions or data items) in the IDA database.

    Can be used to iterate over all heads in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database):
        super().__init__(database)

    def __iter__(self) -> Iterator[ea_t]:
        return self.get_all()

    def get_all(self) -> Iterator[ea_t]:
        """
        Retrieves an iterator over all heads in the database.

        Returns:
            An iterator over the heads.
        """
        return self.get_between(self.database.minimum_ea, self.database.maximum_ea)

    def get_between(self, start_ea: ea_t, end_ea: ea_t) -> Iterator[ea_t]:
        """
        Retrieves all basic heads between two addresses.

        Args:
            start_ea: Start address of the range.
            end_ea: End address of the range.

        Returns:
            An iterator over the heads.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(start_ea, strict_check=False):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError('start_ea', start_ea, 'must be less than end_ea')

        ea = start_ea
        if not idc.is_head(ida_bytes.get_flags(ea)):
            ea = ida_bytes.next_head(ea, end_ea)
        while ea < end_ea and ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_head(ea, end_ea)

    def get_next(self, ea: ea_t) -> Optional[ea_t]:
        """
        Get the next head address.

        Args:
            ea: Current address.

        Returns:
            Next head address, or None if no next head exists.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        ea = ida_bytes.next_head(ea, self.database.maximum_ea)
        return ea if ea != ida_idaapi.BADADDR else None

    def get_previous(self, ea: ea_t) -> Optional[ea_t]:
        """
        Get the previous head address.

        Args:
            ea: Current address.

        Returns:
            Previous head address, or None if no previous head exists.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        ea = ida_bytes.prev_head(ea, self.database.minimum_ea)
        return ea if ea != ida_idaapi.BADADDR else None

    def is_head(self, ea: ea_t) -> bool:
        """
        Check if the given address is a head (start of an item).

        Args:
            ea: Address to check.

        Returns:
            True if the address is a head, False otherwise.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        return idc.is_head(ida_bytes.get_flags(ea))

    def is_tail(self, ea: ea_t) -> bool:
        """
        Check if the given address is a tail (part of an item but not the start).

        Args:
            ea: Address to check.

        Returns:
            True if the address is a tail, False otherwise.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        return idc.is_tail(ida_bytes.get_flags(ea))

    def size(self, ea: ea_t) -> int:
        """
        Get the size of the item at the given address.

        Args:
            ea: Address of the item.

        Returns:
            Size of the item in bytes.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
            InvalidParameterError: If the address is not a head.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        if not self.is_head(ea):
            raise InvalidParameterError('ea', ea, 'must be a head address')

        return ida_bytes.get_item_size(ea)

    def bounds(self, ea: ea_t) -> tuple[ea_t, ea_t]:
        """
        Get the bounds (start and end addresses) of the item containing the given address.

        Args:
            ea: Address within the item.

        Returns:
            Tuple of (start_address, end_address) of the item.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        # Find the head of the item containing this address
        head_ea = ida_bytes.get_item_head(ea)
        if head_ea == ida_idaapi.BADADDR:
            # If no item at this address, return single-byte bounds
            return (ea, ea + 1)

        size = ida_bytes.get_item_size(head_ea)
        return (head_ea, head_ea + size)

    def is_code(self, ea: ea_t) -> bool:
        """
        Check if the item at the given address is code.

        Args:
            ea: Address to check.

        Returns:
            True if the item is code, False otherwise.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        return idc.is_code(ida_bytes.get_flags(ea))

    def is_data(self, ea: ea_t) -> bool:
        """
        Check if the item at the given address is data.

        Args:
            ea: Address to check.

        Returns:
            True if the item is data, False otherwise.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        if not self.database.is_valid_ea(ea, strict_check=False):
            raise InvalidEAError(ea)

        return idc.is_data(ida_bytes.get_flags(ea))

    def is_unknown(self, ea: ea_t) -> bool:
        """
        Check if the item at the given address is unknown.

        Args:
            ea: Address to check.

        Returns:
            True if the item is data, False otherwise.

        Raises:
            InvalidEAError: If the effective address is not in the database range.
        """
        return self.database.bytes.is_unknown_at(ea)
