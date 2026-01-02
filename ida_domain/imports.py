from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterator, Optional, Union

import ida_nalt
from ida_idaapi import ea_t

from .base import DatabaseEntity, InvalidParameterError, check_db_open, decorate_all_methods, deprecated

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Imports', 'ImportModule', 'ImportEntry', 'ImportStatistics']


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
        return self.ordinal != 0 and (not self.name or self.name == '')

    @property
    def is_named_import(self) -> bool:
        """True if imported by name rather than ordinal."""
        return bool(self.name and self.name != '')

    @property
    def full_name(self) -> str:
        """Formatted as 'module.name' or 'module.#ordinal'."""
        if self.is_named_import:
            return f'{self.module_name}.{self.name}'
        else:
            return f'{self.module_name}.#{self.ordinal}'


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


@dataclass(frozen=True)
class ImportStatistics:
    """
    Statistical information about imports in the database.

    Provides aggregate metrics about import table usage, module distribution,
    and import naming conventions.

    Attributes:
        module_count: Total number of imported modules
        total_imports: Total number of import entries
        named_imports: Number of imports by name
        ordinal_imports: Number of imports by ordinal
        most_imported_module: Module with most imports
        most_imported_count: Number of imports from most-imported module
    """

    module_count: int
    total_imports: int
    named_imports: int
    ordinal_imports: int
    most_imported_module: str
    most_imported_count: int


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
                name=module_name, index=i, import_count=import_count, _imports_entity=self
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
            raise InvalidParameterError('index', index, 'Module index cannot be negative')

        count = ida_nalt.get_import_module_qty()
        if index >= count:
            return None

        module_name = ida_nalt.get_import_module_name(index)
        if not module_name:
            return None

        import_count = self._count_module_imports(index)

        return ImportModule(
            name=module_name, index=index, import_count=import_count, _imports_entity=self
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

    def get_module_names(self) -> list[str]:
        """
        Retrieves a list of all import module names.

        Returns:
            List of module name strings in import table order

        Example:
            >>> modules = db.imports.get_module_names()
            >>> print("Dependencies:", ", ".join(modules))
            >>> # Check for specific modules
            >>> if "ntdll.dll" in modules:
            ...     print("Uses native NT APIs")
        """
        names = []
        count = ida_nalt.get_import_module_qty()

        for i in range(count):
            module_name = ida_nalt.get_import_module_name(i)
            if module_name:
                names.append(module_name)

        return names

    def get_entries_by_module(
        self, module: Union[str, int, ImportModule]
    ) -> Iterator[ImportEntry]:
        """
        Retrieves all import entries from a specific module.

        Args:
            module: Module to get entries from (can be index, name, or ImportModule object)

        Returns:
            Iterator over all ImportEntry objects from the specified module

        Raises:
            InvalidParameterError: If module is invalid

        Example:
            >>> # By index
            >>> for entry in db.imports.get_entries_by_module(0):
            ...     print(entry.name)
            >>>
            >>> # By name
            >>> for entry in db.imports.get_entries_by_module("kernel32.dll"):
            ...     print(entry.name)
            >>>
            >>> # By module object
            >>> module = db.imports.get_module(0)
            >>> for entry in db.imports.get_entries_by_module(module):
            ...     print(entry.name)
        """
        # Convert to module index
        if isinstance(module, ImportModule):
            module_index = module.index
        elif isinstance(module, str):
            # Find module by name
            found_module = self.get_module_by_name(module)
            if not found_module:
                raise InvalidParameterError('module', module, f"Module '{module}' not found")
            module_index = found_module.index
        elif isinstance(module, int):
            module_index = module
        else:
            raise InvalidParameterError(
                'module', module, 'Must be int (index), str (name), or ImportModule'
            )

        # Validate index
        if module_index < 0:
            raise InvalidParameterError('module', module_index, 'Module index cannot be negative')

        count = ida_nalt.get_import_module_qty()
        if module_index >= count:
            raise InvalidParameterError(
                'module', module_index, f'Module index out of range [0, {count})'
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
                name=name if name else '',
                ordinal=ordinal if ordinal else 0,
                module_name=module_name,
                module_index=module_index,
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
                        name=name if name else '',
                        ordinal=ordinal if ordinal else 0,
                        module_name=module_name,
                        module_index=module_idx,
                    )
                    result.append(entry)
                    return 0  # Stop enumeration
                return 1  # Continue enumeration

            # Enumerate imports from this module
            ida_nalt.enum_import_names(module_idx, callback)

            if result:
                return result[0]

        return None

    def get_by_name(self, name: str, module_name: Optional[str] = None) -> Optional[ImportEntry]:
        """
        Get import entry by name, optionally filtering by module.

        Args:
            name: Import function/symbol name to search for.
            module_name: Optional module name to restrict search (e.g., "kernel32.dll").

        Returns:
            First matching ImportEntry object, or None if no import with that name exists.

        Example:
            >>> # Get import by name across all modules
            >>> entry = db.imports.get_by_name("VirtualAlloc")
            >>> if entry:
            ...     print(f"Found: {entry.full_name} @ {hex(entry.address)}")
            >>>
            >>> # Get import in specific module
            >>> entry = db.imports.get_by_name("CreateFileW", "kernel32.dll")
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
                        module_index=module_idx,
                    )
                    result.append(entry)
                    return 0  # Stop enumeration
                return 1  # Continue enumeration

            ida_nalt.enum_import_names(module_idx, callback)

            if result:
                return result[0]

        return None

    @deprecated("Use get_by_name() instead")
    def find_by_name(self, name: str, module_name: Optional[str] = None) -> Optional[ImportEntry]:
        """Deprecated: Use get_by_name() instead."""
        return self.get_by_name(name, module_name)

    def find_all_by_name(
        self, name: str, module_name: Optional[str] = None
    ) -> Iterator[ImportEntry]:
        """
        Finds all import entries matching the given name (handles duplicate imports).

        Unlike find_by_name which returns only the first match, this method
        returns all imports with the specified name. This is useful for detecting
        duplicate imports which can occur in malformed binaries or certain linking scenarios.

        Args:
            name: Import function/symbol name to search for
            module_name: Optional module name to restrict search (e.g., "kernel32.dll")

        Returns:
            Iterator over all matching ImportEntry objects

        Example:
            >>> # Find all imports with same name (rare but possible)
            >>> entries = list(db.imports.find_all_by_name("LoadLibraryA"))
            >>> if len(entries) > 1:
            ...     name = entries[0].name
            ...     print(f"WARNING: Duplicate import {name} found {len(entries)} times")
            ...     for entry in entries:
            ...         print(f"  @ 0x{entry.address:x} from {entry.module_name}")
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
            entries = []

            def callback(import_ea: ea_t, import_name: str | None, ordinal: int | None) -> int:
                """Callback for enum_import_names."""
                if import_name and import_name == name:
                    entry = ImportEntry(
                        address=import_ea,
                        name=import_name,
                        ordinal=ordinal if ordinal else 0,
                        module_name=current_module,
                        module_index=module_idx,
                    )
                    entries.append(entry)
                return 1  # Continue enumeration (don't stop at first match)

            ida_nalt.enum_import_names(module_idx, callback)

            # Yield all matches from this module
            for entry in entries:
                yield entry

    def filter_entries(self, predicate: Callable[[ImportEntry], bool]) -> Iterator[ImportEntry]:
        """
        Filters import entries using a custom predicate function.

        This method provides flexible filtering of imports based on arbitrary criteria.
        The predicate function receives each import entry and should return True to
        include it in the results.

        Args:
            predicate: Function that takes an ImportEntry and returns True to include it

        Returns:
            Iterator over matching ImportEntry objects

        Example:
            >>> # Find all memory allocation imports
            >>> mem_funcs = ['VirtualAlloc', 'VirtualAllocEx', 'HeapAlloc', 'malloc']
            >>> mem_imports = db.imports.filter_entries(
            ...     lambda e: e.name in mem_funcs
            ... )
            >>> for entry in mem_imports:
            ...     print(f"Memory API: {entry.full_name} @ 0x{entry.address:x}")
            >>>
            >>> # Find all imports with addresses in specific range
            >>> code_section = db.segments.get_by_name(".text")
            >>> if code_section:
            ...     imports_in_code = db.imports.filter_entries(
            ...         lambda e: code_section.start_ea <= e.address < code_section.end_ea
            ...     )
            ...     print("Imports in .text section:", list(imports_in_code))
        """
        for entry in self.get_all_entries():
            if predicate(entry):
                yield entry

    def search_by_pattern(
        self, pattern: str, case_sensitive: bool = False
    ) -> Iterator[ImportEntry]:
        """
        Searches import names using a regular expression pattern.

        This method enables powerful pattern-based searching of import names,
        supporting full regex syntax for complex queries. Useful for finding
        API families, naming patterns, or security-relevant function groups.

        Args:
            pattern: Regular expression pattern to match against import names
            case_sensitive: Whether to perform case-sensitive matching (default: False)

        Returns:
            Iterator over matching ImportEntry objects

        Example:
            >>> # Find all Create* APIs
            >>> for entry in db.imports.search_by_pattern(r'^Create'):
            ...     print(entry.full_name)
            >>>
            >>> # Find all socket-related imports
            >>> socket_imports = db.imports.search_by_pattern(
            ...     r'(socket|send|recv|connect|bind|listen)'
            ... )
            >>> for entry in socket_imports:
            ...     print(f"Network API: {entry.full_name}")
            >>>
            >>> # Find crypto APIs (case-insensitive)
            >>> crypto_imports = db.imports.search_by_pattern(
            ...     r'(crypt|hash|cipher|aes|rsa)'
            ... )
            >>> for entry in crypto_imports:
            ...     print(f"Crypto API: {entry.full_name}")
        """
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile(pattern, flags)

        for entry in self.get_all_entries():
            if entry.name and regex.search(entry.name):
                yield entry

    def has_imports(self) -> bool:
        """
        Checks whether the database contains any import information.

        This is a quick check to determine if the binary has an import table.
        Statically linked binaries, shellcode, and some packed executables may
        have no imports.

        Returns:
            True if imports exist, False otherwise

        Example:
            >>> if db.imports.has_imports():
            ...     print(f"Binary imports {len(db.imports)} modules")
            ... else:
            ...     print("No imports found (statically linked binary?)")
        """
        count: int = ida_nalt.get_import_module_qty()
        return count > 0

    def is_import(self, ea: ea_t) -> bool:
        """
        Checks whether the specified address is an import entry.

        This is a fast existence check that avoids creating full ImportEntry objects.
        Useful for filtering addresses or validating cross-references.

        Args:
            ea: Effective address to check

        Returns:
            True if address is an import, False otherwise

        Raises:
            InvalidEAError: If the effective address is invalid

        Example:
            >>> # Check if address is an import
            >>> if db.imports.is_import(0x401000):
            ...     entry = db.imports.get_at(0x401000)
            ...     print(f"Import: {entry.full_name}")
            ... else:
            ...     print("Not an import address")
            >>>
            >>> # Check all call targets
            >>> func = db.functions.get_at(0x401000)
            >>> if func:
            ...     for xref in db.xrefs.from_function(func):
            ...         if db.imports.is_import(xref.to):
            ...             entry = db.imports.get_at(xref.to)
            ...             print(f"Calls import: {entry.full_name}")
        """
        from .base import InvalidEAError

        # Validate address
        if not self.database.is_valid_ea(ea):
            raise InvalidEAError(ea)

        # Quick check: search through all modules
        return self.get_at(ea) is not None

    def get_statistics(self) -> ImportStatistics:
        """
        Retrieves statistical information about imports in the database.

        Analyzes the import table to provide aggregate metrics useful for
        understanding dependencies, detecting patterns, and profiling binary
        characteristics.

        Returns:
            ImportStatistics dataclass with module count, import counts,
            named vs ordinal ratios, and most-imported module information

        Example:
            >>> # Get import statistics
            >>> stats = db.imports.get_statistics()
            >>> print(f"Modules: {stats.module_count}")
            >>> print(f"Total imports: {stats.total_imports}")
            >>> print(f"Named: {stats.named_imports}, Ordinal: {stats.ordinal_imports}")
            >>> most_imp = stats.most_imported_module
            >>> print(f"Most imported: {most_imp} ({stats.most_imported_count} imports)")
        """
        module_count = len(self)
        total_imports = 0
        named_imports = 0
        ordinal_imports = 0
        most_imported_module = ''
        most_imported_count = 0

        for module in self.get_all():
            # Count imports in this module
            module_import_count = module.import_count
            total_imports += module_import_count

            # Track most-imported module
            if module_import_count > most_imported_count:
                most_imported_count = module_import_count
                most_imported_module = module.name

            # Count named vs ordinal imports
            for entry in module.imports:
                if entry.is_named_import:
                    named_imports += 1
                else:
                    ordinal_imports += 1

        return ImportStatistics(
            module_count=module_count,
            total_imports=total_imports,
            named_imports=named_imports,
            ordinal_imports=ordinal_imports,
            most_imported_module=most_imported_module,
            most_imported_count=most_imported_count,
        )

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
