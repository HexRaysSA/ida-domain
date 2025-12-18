"""
Decompiler entity for IDA Domain API.

Provides access to the Hex-Rays decompiler functionality for generating
pseudocode from binary code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

import ida_funcs
import ida_hexrays
import ida_lines
from ida_idaapi import ea_t

from .base import (
    DatabaseEntity,
    InvalidEAError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Decompiler']


# ============================================================================
# Entity Class
# ============================================================================


@decorate_all_methods(check_db_open)
class Decompiler(DatabaseEntity):
    """
    Provides access to Hex-Rays decompiler functionality.

    This entity enables decompilation of binary code to C-like pseudocode,
    providing a high-level view of program functionality.
    """

    def __init__(self, database: Database) -> None:
        """Initialize the Decompiler entity."""
        super().__init__(database)

    @property
    def is_available(self) -> bool:
        """
        Check if the Hex-Rays decompiler is available and loaded.

        Returns:
            True if the decompiler plugin is loaded and functional, False otherwise.

        Example:
            >>> db = Database.open_current()
            >>> if db.decompiler.is_available:
            ...     print("Decompiler is available")
            ... else:
            ...     print("Decompiler not available")
        """
        return bool(ida_hexrays.init_hexrays_plugin())

    def decompile_at(self, address: ea_t, remove_tags: bool = True) -> Optional[List[str]]:
        """
        Decompile binary code at the specified address and return pseudocode lines.

        This method decompiles the function containing the given address and returns
        the resulting pseudocode as a list of text lines.

        Args:
            address: Address within the function to decompile (typically function start)
            remove_tags: If True, removes IDA color/formatting tags from output

        Returns:
            List of pseudocode line strings, or None if decompilation fails

        Raises:
            InvalidEAError: If address is invalid
            RuntimeError: If decompiler is not available

        Example:
            >>> db = Database.open_current()
            >>> lines = db.decompiler.decompile_at(0x401000)
            >>> if lines:
            ...     for line in lines:
            ...         print(line)
        """
        # Check availability
        if not self.is_available:
            raise RuntimeError("Hex-Rays decompiler not available")

        # Validate address
        if not self.database.is_valid_ea(address):
            raise InvalidEAError(address)

        # Get function at address
        func = ida_funcs.get_func(address)
        if not func:
            return None

        # Decompile
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return None

            # Extract pseudocode lines
            pseudocode_lines: List[str] = []
            sv = cfunc.get_pseudocode()

            for i in range(len(sv)):
                line = sv[i].line
                if remove_tags:
                    line = ida_lines.tag_remove(line)
                pseudocode_lines.append(line)

            return pseudocode_lines

        except ida_hexrays.DecompilationFailure as e:
            # Decompilation failed - return None instead of raising
            # This matches the behavior of returning None when no function exists
            return None
