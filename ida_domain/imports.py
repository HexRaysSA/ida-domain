from __future__ import annotations

from dataclasses import dataclass

import ida_nalt
from ida_idaapi import ea_t
from typing_extensions import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:
    from .database import Database

from .base import DatabaseEntity, check_db_open, decorate_all_methods


@dataclass(frozen=True)
class ImportModuleInfo:
    """Represents an imported module (DLL/shared library)."""

    index: int
    name: str


@dataclass(frozen=True)
class ImportInfo:
    """Represents an imported function/symbol."""

    address: ea_t
    name: Optional[str]
    ordinal: int
    module_index: int
    module_name: str

    def has_name(self) -> bool:
        """Check if this import has a name (not ordinal-only)."""
        return self.name is not None and len(self.name) > 0


@decorate_all_methods(check_db_open)
class Imports(DatabaseEntity):
    """
    Provides access to imports in the IDA database.

    Can be used to iterate over all import modules in the opened database.

    Args:
        database: Reference to the active IDA database.
    """

    def __init__(self, database: Database) -> None:
        super().__init__(database)

    def __iter__(self) -> Iterator[ImportModuleInfo]:
        return self.get_all_modules()

    def __getitem__(self, index: int) -> ImportModuleInfo:
        return self.get_module_at_index(index)

    def __len__(self) -> int:
        return self.get_module_count()

    def get_module_count(self) -> int:
        """Get the total number of import modules.

        Returns:
            Number of import modules in the program.
        """
        return ida_nalt.get_import_module_qty()

    def get_module_at_index(self, index: int) -> ImportModuleInfo:
        """Get import module by its index.

        Args:
            index: Module index (0 to get_module_count()-1)

        Returns:
            The import module at the specified index.

        Raises:
            IndexError: If index is out of range.
        """
        if index < 0 or index >= self.get_module_count():
            raise IndexError(f'Module index {index} out of range [0, {self.get_module_count()})')

        name = ida_nalt.get_import_module_name(index)
        if not name:
            name = f'module_{index}'

        return ImportModuleInfo(index=index, name=name)

    def get_module_by_name(self, name: str) -> Optional[ImportModuleInfo]:
        """Find import module by name (case-insensitive).

        Args:
            name: Module name to search for.

        Returns:
            The import module with the specified name, or None if not found.
        """
        name_lower = name.lower()
        for module in self.get_all_modules():
            if module.name.lower() == name_lower:
                return module
        return None

    def get_all_modules(self) -> Iterator[ImportModuleInfo]:
        """Get all import modules.

        Yields:
            Each import module in the program.
        """
        count = self.get_module_count()
        for i in range(count):
            yield self.get_module_at_index(i)

    def get_imports_for_module(self, module_index: int) -> Iterator[ImportInfo]:
        """Get all imports from a specific module.

        Args:
            module_index: Index of the module.

        Yields:
            Each import from the specified module.

        Raises:
            IndexError: If module_index is out of range.
        """
        if module_index < 0 or module_index >= self.get_module_count():
            raise IndexError(
                f'Module index {module_index} out of range [0, {self.get_module_count()})'
            )

        module_name = ida_nalt.get_import_module_name(module_index)
        if not module_name:
            module_name = f'module_{module_index}'

        results: list[ImportInfo] = []

        def callback(ea: ea_t, name: Optional[str], ordinal: int) -> bool:
            results.append(
                ImportInfo(
                    address=ea,
                    name=name,
                    ordinal=ordinal,
                    module_index=module_index,
                    module_name=module_name,
                )
            )
            return True

        ida_nalt.enum_import_names(module_index, callback)
        yield from results

    def get_all_imports(self) -> Iterator[ImportInfo]:
        """Get all imports from all modules (flattened).

        Yields:
            Each import in the program.
        """
        for module in self.get_all_modules():
            yield from self.get_imports_for_module(module.index)

    def get_import_by_name(self, name: str) -> Optional[ImportInfo]:
        """Find import by qualified name (case-insensitive).

        Args:
            name: Import name in 'module!symbol' format (e.g., 'kernel32.dll!CreateFileW')
                  or 'module!#ordinal' format (e.g., 'kernel32.dll!#42').

        Returns:
            The import with the specified name, or None if not found.
        """
        if '!' not in name:
            return None

        module_part, symbol_part = name.split('!', 1)
        module_lower = module_part.lower()
        symbol_lower = symbol_part.lower()

        for imp in self.get_all_imports():
            if imp.module_name.lower() != module_lower:
                continue

            if symbol_lower.startswith('#'):
                try:
                    ordinal = int(symbol_lower[1:])
                    if imp.ordinal == ordinal:
                        return imp
                except ValueError:
                    continue
            elif imp.name and imp.name.lower() == symbol_lower:
                return imp

        return None

    def get_import_at(self, ea: ea_t) -> Optional[ImportInfo]:
        """Get import at a specific address.

        Args:
            ea: Linear address to search for.

        Returns:
            The import at the specified address, or None if not found.
        """
        for imp in self.get_all_imports():
            if imp.address == ea:
                return imp
        return None

    def get_module_names(self) -> Iterator[str]:
        """Get all module names.

        Yields:
            Each module name.
        """
        for module in self.get_all_modules():
            yield module.name

    def get_import_names(self) -> Iterator[str]:
        """Get all import names in qualified format.

        Yields:
            Each import in 'module!symbol' or 'module!#ordinal' format.
        """
        for imp in self.get_all_imports():
            if imp.name:
                yield f'{imp.module_name}!{imp.name}'
            else:
                yield f'{imp.module_name}!#{imp.ordinal}'

    def get_import_addresses(self) -> Iterator[ea_t]:
        """Get all import addresses.

        Yields:
            Each import address.
        """
        for imp in self.get_all_imports():
            yield imp.address

    def get_import_count(self) -> int:
        """Get the total number of imports across all modules.

        Returns:
            Total number of imports.
        """
        return sum(1 for _ in self.get_all_imports())

    def exists(self, name: str) -> bool:
        """Check if an import with the given qualified name exists (case-insensitive).

        Args:
            name: Import name in 'module!symbol' or 'module!#ordinal' format.

        Returns:
            True if import exists.
        """
        return self.get_import_by_name(name) is not None
