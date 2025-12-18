from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Optional

import ida_nalt
from ida_idaapi import ea_t

from .base import DatabaseEntity, InvalidParameterError, check_db_open, decorate_all_methods

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Imports', 'ImportModule', 'ImportEntry']


@dataclass(frozen=True)
class ImportEntry:
    """
    Represents a single imported function or data item.

    Provides comprehensive information about an import including its address,
    name, ordinal, and module information.

    Attributes:
        address: Address where import is resolved (IAT entry)
        name: Import name (empty string if imported by ordinal)
        ordinal: Import ordinal (0 if imported by name)
        module_name: Name of the module providing this import
        module_index: Index of the module in the import table
    """

    address: ea_t
    name: str
    ordinal: int
    module_name: str
    module_index: int

    @property
    def is_ordinal_import(self) -> bool:
        """True if imported by ordinal rather than name."""
        return self.ordinal != 0 and (not self.name or self.name == "")

    @property
    def is_named_import(self) -> bool:
        """True if imported by name rather than ordinal."""
        return bool(self.name and self.name != "")

    @property
    def full_name(self) -> str:
        """Formatted as 'module.name' or 'module.#ordinal'."""
        if self.is_named_import:
            return f"{self.module_name}.{self.name}"
        else:
            return f"{self.module_name}.#{self.ordinal}"


@dataclass(frozen=True)
class ImportModule:
    """
    Represents an imported module (DLL/shared library) and its imports.

    Wraps information about a single module in the import table, providing
    access to the module's name, index, and all imports from that module.

    Attributes:
        name: Module name (e.g., "kernel32.dll", "libc.so.6")
        index: Module index (0-based position in import table)
        import_count: Number of imports from this module
    """

    name: str
    index: int
    import_count: int
    _imports_entity: Optional[Imports] = field(default=None, repr=False, compare=False)

    @property
    def imports(self) -> Iterator[ImportEntry]:
        """
        Lazy iterator over all imports from this module.

        Yields:
            ImportEntry: Each import from this module

        Example:
            >>> module = db.imports.get_module(0)
            >>> for entry in module.imports:
            ...     print(f"{entry.name} @ {hex(entry.address)}")
        """
        if self._imports_entity is None:
            return iter([])

        return self._imports_entity.get_entries_by_module(self.index)


@decorate_all_methods(check_db_open)
class Imports(DatabaseEntity):
    """
    Provides access to import table operations in the IDA database.

    The Imports entity enables enumeration of imported modules and their individual
    entries, dependency analysis, library function identification, and external
    reference tracking.

    Example:
        >>> db = Database.open_current()
        >>> # Iterate over all import modules
        >>> for module in db.imports:
        ...     print(f"Module: {module.name} ({module.import_count} imports)")
        ...     for entry in module.imports:
        ...         print(f"  {entry.name} @ {hex(entry.address)}")
        >>>
        >>> # Get specific import by address
        >>> entry = db.imports.get_at(0x401000)
        >>> if entry:
        ...     print(f"Import: {entry.full_name}")
    """

    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[ImportModule]:
        """
        Enables iteration over all imported modules in the database.

        Returns:
            Iterator over all ImportModule objects

        Example:
            >>> for module in db.imports:
            ...     print(module.name)
        """
        return self.get_all()

    def __len__(self) -> int:
        """
        Returns the total number of import modules in the database.

        Returns:
            The number of imported modules (DLLs/shared libraries)

        Example:
            >>> count = len(db.imports)
            >>> print(f"Imported modules: {count}")
        """
        result: int = ida_nalt.get_import_module_qty()
        return result

    def get_all(self) -> Iterator[ImportModule]:
        """
        Retrieves all import modules in the database.

        Returns:
            An iterator over all ImportModule objects

        Example:
            >>> for module in db.imports.get_all():
            ...     print(f"{module.index}: {module.name}")
        """
        count = ida_nalt.get_import_module_qty()

        for i in range(count):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                continue

            # Count imports in this module
            import_count = self._count_module_imports(i)

            yield ImportModule(
                name=module_name,
                index=i,
                import_count=import_count,
                _imports_entity=self
            )

    def get_module(self, index: int) -> Optional[ImportModule]:
        """
        Retrieves an import module by its index.

        Args:
            index: Module index (0-based, from import table order)

        Returns:
            ImportModule object at the specified index, or None if out of range

        Raises:
            InvalidParameterError: If index is negative

        Example:
            >>> module = db.imports.get_module(0)
            >>> if module:
            ...     print(f"First module: {module.name}")
        """
        if index < 0:
            raise InvalidParameterError("index", index, "Module index cannot be negative")

        count = ida_nalt.get_import_module_qty()
        if index >= count:
            return None

        module_name = ida_nalt.get_import_module_name(index)
        if not module_name:
            return None

        import_count = self._count_module_imports(index)

        return ImportModule(
            name=module_name,
            index=index,
            import_count=import_count,
            _imports_entity=self
        )

    def get_module_by_name(self, name: str) -> Optional[ImportModule]:
        """
        Retrieves an import module by its name.

        Args:
            name: Module name (case-insensitive, e.g., "kernel32.dll")

        Returns:
            ImportModule object with matching name, or None if module not found

        Example:
            >>> module = db.imports.get_module_by_name("kernel32.dll")
            >>> if module:
            ...     print(f"Kernel32 imports: {module.import_count}")
        """
        name_lower = name.lower()

        for module in self.get_all():
            if module.name.lower() == name_lower:
                return module

        return None

    def get_entries_by_module(self, module_index: int) -> Iterator[ImportEntry]:
        """
        Retrieves all import entries from a specific module.

        Args:
            module_index: Module index (0-based)

        Returns:
            Iterator over all ImportEntry objects from the specified module

        Raises:
            InvalidParameterError: If module_index is invalid

        Example:
            >>> for entry in db.imports.get_entries_by_module(0):
            ...     print(entry.name)
        """
        if module_index < 0:
            raise InvalidParameterError(
                "module_index", module_index, "Module index cannot be negative"
            )

        count = ida_nalt.get_import_module_qty()
        if module_index >= count:
            raise InvalidParameterError(
                "module_index", module_index, f"Module index out of range [0, {count})"
            )

        module_name = ida_nalt.get_import_module_name(module_index)
        if not module_name:
            return iter([])

        # Collect entries via callback
        entries = []

        def callback(ea: ea_t, name: str | None, ordinal: int | None) -> int:
            """Callback for ida_nalt.enum_import_names."""
            entry = ImportEntry(
                address=ea,
                name=name if name else "",
                ordinal=ordinal if ordinal else 0,
                module_name=module_name,
                module_index=module_index
            )
            entries.append(entry)
            return 1  # Continue enumeration

        ida_nalt.enum_import_names(module_index, callback)

        return iter(entries)

    def get_all_entries(self) -> Iterator[ImportEntry]:
        """
        Retrieves all import entries across all modules (flattened view).

        Returns:
            Iterator over all ImportEntry objects from all modules

        Example:
            >>> # Get all imports (flat list)
            >>> for entry in db.imports.get_all_entries():
            ...     print(f"{entry.full_name} @ {hex(entry.address)}")
            >>>
            >>> # Count total imports
            >>> total = sum(1 for _ in db.imports.get_all_entries())
            >>> print(f"Total imports: {total}")
        """
        count = ida_nalt.get_import_module_qty()

        for module_idx in range(count):
            module_name = ida_nalt.get_import_module_name(module_idx)
            if not module_name:
                continue

            # Enumerate all imports from this module
            for entry in self.get_entries_by_module(module_idx):
                yield entry

    def get_at(self, ea: ea_t) -> Optional[ImportEntry]:
        """
        Retrieves the import entry at the specified address (IAT entry).

        Args:
            ea: Effective address of the import stub or IAT entry

        Returns:
            ImportEntry object if an import exists at the address, None otherwise

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> # Get import at address
            >>> entry = db.imports.get_at(0x401000)
            >>> if entry:
            ...     print(f"Import: {entry.full_name} @ {hex(entry.address)}")
            ...     # Navigate to callers
            ...     for xref in db.xrefs.to_ea(entry.address):
            ...         print(f"  Called from: {hex(xref.frm)}")
            ... else:
            ...     print("No import at this address")
        """
        from .base import InvalidEAError

        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Search through all modules
        count = ida_nalt.get_import_module_qty()

        for module_idx in range(count):
            module_name = ida_nalt.get_import_module_name(module_idx)
            if not module_name:
                continue

            # Search imports in this module
            result = []

            def callback(import_ea: ea_t, name: str | None, ordinal: int | None) -> int:
                """Callback for enum_import_names."""
                if import_ea == ea:
                    # Found matching import
                    entry = ImportEntry(
                        address=import_ea,
                        name=name if name else "",
                        ordinal=ordinal if ordinal else 0,
                        module_name=module_name,
                        module_index=module_idx
                    )
                    result.append(entry)
                    return 0  # Stop enumeration
                return 1  # Continue enumeration

            # Enumerate imports from this module
            ida_nalt.enum_import_names(module_idx, callback)

            if result:
                return result[0]

        return None

    def find_by_name(self, name: str, module_name: Optional[str] = None) -> Optional[ImportEntry]:
        """
        Finds an import entry by name, optionally filtering by module.

        Args:
            name: Import function/symbol name to search for
            module_name: Optional module name to restrict search (e.g., "kernel32.dll")

        Returns:
            First matching ImportEntry object, or None if no import with that name exists

        Example:
            >>> # Find import by name across all modules
            >>> entry = db.imports.find_by_name("VirtualAlloc")
            >>> if entry:
            ...     print(f"Found: {entry.full_name} @ {hex(entry.address)}")
            >>>
            >>> # Find import in specific module
            >>> entry = db.imports.find_by_name("CreateFileW", "kernel32.dll")
            >>> if entry:
            ...     print(f"Found: {entry.full_name}")
            ... else:
            ...     print("Import not found")
        """
        count = ida_nalt.get_import_module_qty()
        module_name_lower = module_name.lower() if module_name else None

        for module_idx in range(count):
            current_module = ida_nalt.get_import_module_name(module_idx)
            if not current_module:
                continue

            # If module_name specified, check if this is the right module
            if module_name_lower and current_module.lower() != module_name_lower:
                continue

            # Search imports in this module
            result = []

            def callback(import_ea: ea_t, import_name: str | None, ordinal: int | None) -> int:
                """Callback for enum_import_names."""
                if import_name and import_name == name:
                    entry = ImportEntry(
                        address=import_ea,
                        name=import_name,
                        ordinal=ordinal if ordinal else 0,
                        module_name=current_module,
                        module_index=module_idx
                    )
                    result.append(entry)
                    return 0  # Stop enumeration
                return 1  # Continue enumeration

            ida_nalt.enum_import_names(module_idx, callback)

            if result:
                return result[0]

        return None

    def _count_module_imports(self, module_index: int) -> int:
        """
        Count the number of imports in a module.

        Args:
            module_index: Module index to count imports for

        Returns:
            Number of imports in the module
        """
        count = [0]

        def callback(ea: ea_t, name: str | None, ordinal: int | None) -> int:
            """Callback for ida_nalt.enum_import_names."""
            count[0] += 1
            return 1  # Continue enumeration

        ida_nalt.enum_import_names(module_index, callback)

        return count[0]
