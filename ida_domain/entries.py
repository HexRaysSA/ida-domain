from __future__ import annotations

from dataclasses import dataclass

import ida_entry
import ida_idaapi
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:
    from .database import Database

from .base import DatabaseEntity, check_db_open, decorate_all_methods


@dataclass(frozen=True)
class ForwarderInfo:
    """
    Represents information about an entry point forwarder.
    """

    ordinal: int
    name: str

    def __post_init__(self) -> None:
        if self.ordinal < 0:
            raise ValueError(f'Invalid ordinal number: {self.ordinal}')
        if not self.name or not self.name.strip():
            raise ValueError('Forwarder name cannot be empty')


@dataclass(frozen=True)
class EntryInfo:
    """
    Represents a program entry point.
    Exported functions are considered entry points as well.
    """

    ordinal: int
    address: ea_t
    name: str
    forwarder_name: str

    def has_forwarder(self) -> bool:
        """Check if this entry point has a forwarder."""
        return self.forwarder_name is not None and len(self.forwarder_name) > 0


@decorate_all_methods(check_db_open)
class Entries(DatabaseEntity):
    """
    Provides access to entries in the IDA database.

    Can be used to iterate over all entries in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[EntryInfo]:
        return self.get_all()

    def __getitem__(self, index: int) -> EntryInfo:
        return self.get_at_index(index)

    def __len__(self) -> int:
        """Return the total number of entry points.

        Returns:
            int: The number of entry points in the program.
        """
        return self.get_count()

    def get_count(self) -> int:
        """Get the total number of entry points.

        Returns:
            int: Number of entry points in the program
        """
        return ida_entry.get_entry_qty()

    def get_at_index(self, index: int) -> EntryInfo:
        """Get entry point by its index in the entry table.

        Args:
            index: Internal index (0 to get_count()-1)

        Returns:
            Entry: The entry point at the specified index

        Raises:
            IndexError: If index is out of range
        """
        if index < 0 or index >= self.get_count():
            raise IndexError(f'Entry index {index} out of range [0, {self.get_count()})')

        ordinal = ida_entry.get_entry_ordinal(index)
        address = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        forwarder = ida_entry.get_entry_forwarder(ordinal)

        return EntryInfo(
            ordinal=ordinal,
            address=address,
            name=name if name else f'entry_{ordinal}',
            forwarder_name=forwarder,
        )

    def get_by_ordinal(self, ordinal: int) -> Optional[EntryInfo]:
        """Get entry point by its ordinal number.

        Args:
            ordinal: Ordinal number of the entry point

        Returns:
            Entry: The entry point with the specified ordinal, or None if not found
        """
        address = ida_entry.get_entry(ordinal)
        if address == ida_idaapi.BADADDR:
            return None

        name = ida_entry.get_entry_name(ordinal)
        forwarder = ida_entry.get_entry_forwarder(ordinal)

        return EntryInfo(
            ordinal=ordinal,
            address=address,
            name=name if name else f'entry_{ordinal}',
            forwarder_name=forwarder,
        )

    def get_at(self, ea: ea_t) -> Optional[EntryInfo]:
        """Get entry point by its address.

        Args:
            ea: Linear address to search for

        Returns:
            Entry: The entry point at the specified address, or None if not found
        """
        for entry in self.get_all():
            if entry.address == ea:
                return entry
        return None

    def get_all(self) -> Iterator[EntryInfo]:
        """Get all entry points.

        Yields:
            Entry: Each entry point in the program
        """
        count = self.get_count()
        for i in range(count):
            yield self.get_at_index(i)

    def add(
        self, address: ea_t, name: str, ordinal: Optional[int] = None, make_code: bool = True
    ) -> bool:
        """Add a new entry point.

        Args:
            address: Linear address of the entry point
            name: Name for the entry point
            ordinal: Ordinal number (if None, uses address as ordinal)
            make_code: Whether to convert bytes to instructions

        Returns:
            bool: True if successful
        """
        ord_num = ordinal if ordinal is not None else address
        return ida_entry.add_entry(ord_num, address, name, make_code)

    def rename(self, ordinal: int, new_name: str) -> bool:
        """Rename an existing entry point.

        Args:
            ordinal: Ordinal number of the entry point
            new_name: New name for the entry point

        Returns:
            bool: True if successful
        """
        return ida_entry.rename_entry(ordinal, new_name)

    def set_forwarder(self, ordinal: int, forwarder_name: str) -> bool:
        """Set forwarder name for an entry point.

        Args:
            ordinal: Ordinal number of the entry point
            forwarder_name: Forwarder name to set

        Returns:
            bool: True if successful
        """
        return ida_entry.set_entry_forwarder(ordinal, forwarder_name)

    def get_forwarders(self) -> Iterator[ForwarderInfo]:
        """Get all entry points that have forwarders.

        Yields:
            ForwarderInfo: Information about each entry with a forwarder
        """
        for entry in self.get_all():
            if entry.has_forwarder():
                yield ForwarderInfo(ordinal=entry.ordinal, name=entry.forwarder_name)

    def get_by_name(self, name: str) -> Optional[EntryInfo]:
        """Find entry point by name.

        Args:
            name: Name to search for

        Returns:
            Entry: The entry point with the specified name, or None if not found
        """
        for entry in self.get_all():
            if entry.name == name:
                return entry
        return None

    def exists(self, ordinal: int) -> bool:
        """Check if an entry point with the given ordinal exists.

        Args:
            ordinal: Ordinal number to check

        Returns:
            bool: True if entry point exists
        """
        return ida_entry.get_entry(ordinal) != ida_idaapi.BADADDR

    def get_ordinals(self) -> Iterator[int]:
        """Get all ordinal numbers.

        Yields:
            int: Each ordinal number
        """
        for entry in self.get_all():
            yield entry.ordinal

    def get_addresses(self) -> Iterator[ea_t]:
        """Get all entry point addresses.

        Yields:
            int: Each entry point address
        """
        for entry in self.get_all():
            yield entry.address

    def get_names(self) -> Iterator[str]:
        """Get all entry point names.

        Yields:
            str: Each entry point name
        """
        for entry in self.get_all():
            yield entry.name
