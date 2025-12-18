"""
Exporter entity for IDA Domain API.

Provides methods for exporting analysis results and database contents to
various file formats including MAP files, assembly listings, reconstructed
executables, and other standard output formats.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag
from typing import TYPE_CHECKING, Optional

import ida_ida
import ida_loader
from ida_idaapi import ea_t

from .base import (
    DatabaseEntity,
    InvalidEAError,
    InvalidParameterError,
    check_db_open,
    decorate_all_methods,
)

if TYPE_CHECKING:
    from .database import Database

__all__ = ['Exporter', 'ExportFormat', 'ExportFlags']


# ============================================================================
# Enumerations
# ============================================================================


class ExportFormat(IntEnum):
    """
    Output file format types.

    Maps to ida_loader.OFILE_* constants for file export operations.
    """

    MAP = ida_loader.OFILE_MAP
    """MAP file (address map with symbols)"""
    EXE = ida_loader.OFILE_EXE
    """Executable file (reconstructed binary)"""
    IDC = ida_loader.OFILE_IDC
    """IDC script (analysis annotations)"""
    LST = ida_loader.OFILE_LST
    """Listing file (formatted disassembly)"""
    ASM = ida_loader.OFILE_ASM
    """Assembly file (disassembled code)"""
    DIF = ida_loader.OFILE_DIF
    """Difference file (changes from original)"""


class ExportFlags(IntFlag):
    """
    Flags controlling export behavior.

    Maps to ida_loader.GENFLG_* constants. These flags control what
    elements are included in generated output files.
    """

    NONE = 0
    """No special flags"""
    GEN_VOID = getattr(ida_loader, 'GENFLG_VOID', 0x0001)
    """Generate for void marks"""
    GEN_EXTRA = getattr(ida_loader, 'GENFLG_EXTRA', 0x0002)
    """Generate extra lines"""
    GEN_ASSUME = getattr(ida_loader, 'GENFLG_ASSUME', 0x0004)
    """Generate assume directives"""
    GEN_ORG = getattr(ida_loader, 'GENFLG_GENORG', 0x0008)
    """Generate org directives"""
    GEN_XREF = getattr(ida_loader, 'GENFLG_XREFGEN', 0x0010)
    """Generate cross-reference comments"""
    GEN_CREF_ONLY = getattr(ida_loader, 'GENFLG_GENCREF', 0x0020)
    """Generate only code cross-references"""
    GEN_DATA_XREF = getattr(ida_loader, 'GENFLG_GENDREF', 0x0040)
    """Generate data cross-references"""


# ============================================================================
# Entity Class
# ============================================================================


@decorate_all_methods(check_db_open)
class Exporter(DatabaseEntity):
    """
    Provides file export operations for IDA databases.

    This entity encapsulates functionality for exporting analysis results
    and database contents to various standard file formats commonly used
    in reverse engineering workflows.
    """

    def __init__(self, database: Database) -> None:
        """Initialize the Exporter entity."""
        super().__init__(database)

    def generate_map_file(
        self,
        output_path: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
    ) -> bool:
        """
        Generate a MAP file containing address mappings for symbols.

        MAP files provide a mapping between symbol names and their addresses,
        useful for debugging and external tool integration.

        Args:
            output_path: Path where the MAP file will be written
            start_ea: Starting address for export range (None = database minimum)
            end_ea: Ending address for export range (None = database maximum)

        Returns:
            True if MAP file was successfully generated, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Generate MAP file for entire database
            >>> success = db.exporter.generate_map_file("program.map")
            >>> if success:
            ...     print("MAP file generated successfully")
        """
        # Default to full database range
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        # Validate addresses (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            # Open file for writing
            with open(output_path, 'w') as fp:
                # Generate MAP file
                result = ida_loader.gen_file(
                    ida_loader.OFILE_MAP, fp, start_ea, end_ea, 0
                )
                return result >= 0  # Positive or zero = success
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write MAP file: {e}") from e

    def generate_assembly(
        self,
        output_path: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
        flags: ExportFlags = ExportFlags.NONE,
    ) -> bool:
        """
        Generate an assembly listing file with disassembled code and data.

        Assembly files contain human-readable disassembly with optional
        annotations like cross-references and assume directives.

        Args:
            output_path: Path where the assembly file will be written
            start_ea: Starting address for export range (None = database minimum)
            end_ea: Ending address for export range (None = database maximum)
            flags: Flags controlling assembly generation (xrefs, assumes, etc.)

        Returns:
            True if assembly file was successfully generated, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Generate assembly with cross-references
            >>> flags = ExportFlags.GEN_XREF | ExportFlags.GEN_ASSUME
            >>> success = db.exporter.generate_assembly("program.asm", flags=flags)
        """
        # Default to full database range
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            with open(output_path, 'w') as fp:
                result = ida_loader.gen_file(
                    ida_loader.OFILE_ASM, fp, start_ea, end_ea, int(flags)
                )
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write assembly file: {e}") from e

    def generate_listing(
        self,
        output_path: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
        flags: ExportFlags = ExportFlags.NONE,
    ) -> bool:
        """
        Generate a listing file with formatted disassembly output.

        Listing files provide formatted disassembly including comments
        and annotations. Similar to assembly files but with different
        formatting.

        Args:
            output_path: Path where the listing file will be written
            start_ea: Starting address for export range (None = database minimum)
            end_ea: Ending address for export range (None = database maximum)
            flags: Flags controlling listing generation

        Returns:
            True if listing file was successfully generated, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Generate complete listing with all annotations
            >>> flags = ExportFlags.GEN_XREF | ExportFlags.GEN_EXTRA
            >>> success = db.exporter.generate_listing("program.lst", flags=flags)
        """
        # Default to full database range
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            with open(output_path, 'w') as fp:
                result = ida_loader.gen_file(
                    ida_loader.OFILE_LST, fp, start_ea, end_ea, int(flags)
                )
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write listing file: {e}") from e

    def generate_executable(self, output_path: str) -> bool:
        """
        Reconstruct an executable file from the database.

        This operation recreates the executable file format based on the
        original loader and current database state, applying any modifications
        made during analysis (e.g., patches).

        Args:
            output_path: Path where the executable will be written

        Returns:
            True if executable was successfully generated, False otherwise

        Raises:
            IOError: If file cannot be written
            RuntimeError: If database format doesn't support executable generation

        Example:
            >>> db = Database.open("program.idb")
            >>> # Apply patches
            >>> db.bytes.patch_byte(0x401234, 0x90)  # NOP out instruction
            >>> # Reconstruct executable with patches applied
            >>> success = db.exporter.generate_executable("program_patched.exe")
            >>> if success:
            ...     print("Patched executable created")

        Note:
            Not all file formats support executable reconstruction. This
            depends on the original binary format and loader capabilities.
        """
        try:
            with open(output_path, 'wb') as fp:
                # gen_exe_file reconstructs the executable
                result = ida_loader.gen_exe_file(fp)
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write executable: {e}") from e
        except Exception as e:
            # Some formats may not support executable generation
            raise RuntimeError(f"Executable generation not supported: {e}") from e

    def generate_idc_script(
        self,
        output_path: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
    ) -> bool:
        """
        Generate an IDC script that can recreate the current analysis state.

        The generated IDC script contains commands to set names, comments,
        types, and other analysis information. Useful for transferring
        annotations between databases.

        Args:
            output_path: Path where the IDC script will be written
            start_ea: Starting address for export range (None = database minimum)
            end_ea: Ending address for export range (None = database maximum)

        Returns:
            True if IDC script was successfully generated, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Generate IDC script to save analysis annotations
            >>> success = db.exporter.generate_idc_script("annotations.idc")
            >>> # Can be applied to a fresh database with ida_idc.exec_idc_file()
        """
        # Default to full database range
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            with open(output_path, 'w') as fp:
                result = ida_loader.gen_file(
                    ida_loader.OFILE_IDC, fp, start_ea, end_ea, 0
                )
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write IDC script: {e}") from e

    def generate_diff(
        self,
        output_path: str,
        start_ea: Optional[ea_t] = None,
        end_ea: Optional[ea_t] = None,
    ) -> bool:
        """
        Generate a difference file showing changes from the original file.

        Diff files show modifications made to the binary during analysis,
        useful for tracking changes or generating binary patches.

        Args:
            output_path: Path where the diff file will be written
            start_ea: Starting address for export range (None = database minimum)
            end_ea: Ending address for export range (None = database maximum)

        Returns:
            True if diff file was successfully generated, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Apply some patches
            >>> db.bytes.patch_byte(0x401000, 0x90)
            >>> db.bytes.patch_byte(0x401001, 0x90)
            >>> # Generate diff showing what changed
            >>> success = db.exporter.generate_diff("changes.dif")
        """
        # Default to full database range
        if start_ea is None:
            start_ea = ida_ida.inf_get_min_ea()
        if end_ea is None:
            end_ea = ida_ida.inf_get_max_ea()

        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            with open(output_path, 'w') as fp:
                result = ida_loader.gen_file(
                    ida_loader.OFILE_DIF, fp, start_ea, end_ea, 0
                )
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to write diff file: {e}") from e

    def export_bytes(
        self, output_path: str, start_ea: ea_t, end_ea: ea_t
    ) -> int:
        """
        Export raw bytes from a database address range to a binary file.

        This exports the raw binary content of a memory range without any
        formatting or annotations.

        Args:
            output_path: Path where the binary file will be written
            start_ea: Starting address of data to export
            end_ea: Ending address of data to export (exclusive)

        Returns:
            Number of bytes written, or -1 on error

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Export a specific section as binary
            >>> num_bytes = db.exporter.export_bytes(
            ...     "code_section.bin",
            ...     start_ea=0x401000,
            ...     end_ea=0x405000
            ... )
            >>> print(f"Exported {num_bytes} bytes")
        """
        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        try:
            with open(output_path, 'wb') as fp:
                # base2file exports raw bytes from database
                # Returns number of bytes written or -1 on error
                num_bytes = ida_loader.base2file(fp, 0, start_ea, end_ea)
                return num_bytes
        except (IOError, OSError) as e:
            raise IOError(f"Failed to export bytes: {e}") from e

    def import_bytes(
        self,
        input_path: str,
        dest_ea: ea_t,
        file_offset: int = 0,
        size: Optional[int] = None,
    ) -> int:
        """
        Import raw bytes from a binary file into the database.

        This operation loads binary data into the database without format
        parsing. For loading complete binary files with proper segment setup,
        use Database.open() or lower-level loader functions.

        Args:
            input_path: Path to the binary file to read
            dest_ea: Destination address in the database
            file_offset: Offset in the file to start reading from (default: 0)
            size: Number of bytes to import (None = entire file from offset)

        Returns:
            Number of bytes imported, or -1 on error

        Raises:
            InvalidEAError: If dest_ea is not a valid address
            IOError: If file cannot be read
            InvalidParameterError: If file_offset or size are invalid

        Example:
            >>> db = Database.open("program.idb")
            >>> # Import binary data to specific address
            >>> num_bytes = db.exporter.import_bytes("data.bin", dest_ea=0x600000)
            >>> print(f"Imported {num_bytes} bytes")
        """
        # Validate
        if not self.database.is_valid_ea(dest_ea):
            raise InvalidEAError(dest_ea)
        if file_offset < 0:
            raise InvalidParameterError(
                "file_offset", file_offset, "must be non-negative"
            )

        try:
            # Read file data
            with open(input_path, 'rb') as f:
                f.seek(file_offset)
                if size is not None:
                    if size < 0:
                        raise InvalidParameterError("size", size, "must be non-negative")
                    data = f.read(size)
                else:
                    data = f.read()

            # Import into database using patch_bytes
            import ida_bytes

            for i, byte_val in enumerate(data):
                ida_bytes.patch_byte(dest_ea + i, byte_val)

            return len(data)

        except (IOError, OSError) as e:
            raise IOError(f"Failed to import bytes: {e}") from e

    def export_range(
        self,
        output_path: str,
        start_ea: ea_t,
        end_ea: ea_t,
        format: ExportFormat,
        flags: ExportFlags = ExportFlags.NONE,
    ) -> bool:
        """
        Export a specific address range in the specified format.

        This is a generalized export method. Format-specific methods
        (generate_assembly, generate_map_file, etc.) are often more convenient.

        Args:
            output_path: Path where the output will be written
            start_ea: Starting address of range to export
            end_ea: Ending address of range to export (exclusive)
            format: Output format (MAP, ASM, LST, etc.)
            flags: Format-specific flags

        Returns:
            True if export was successful, False otherwise

        Raises:
            InvalidEAError: If start_ea or end_ea are invalid addresses
            InvalidParameterError: If start_ea >= end_ea or invalid format
            IOError: If file cannot be written

        Example:
            >>> db = Database.open("program.idb")
            >>> # Export specific range as assembly
            >>> success = db.exporter.export_range(
            ...     "range.asm",
            ...     start_ea=0x401000,
            ...     end_ea=0x402000,
            ...     format=ExportFormat.ASM,
            ...     flags=ExportFlags.GEN_XREF | ExportFlags.GEN_ASSUME
            ... )
        """
        # Validate (end_ea is exclusive, so strict_check=False)
        if not self.database.is_valid_ea(start_ea):
            raise InvalidEAError(start_ea)
        if not self.database.is_valid_ea(end_ea, strict_check=False):
            raise InvalidEAError(end_ea)
        if start_ea >= end_ea:
            raise InvalidParameterError(
                "start_ea",
                start_ea,
                f"must be less than end_ea ({end_ea:#x})",
            )

        # Special handling for EXE format (uses different API)
        if format == ExportFormat.EXE:
            return self.generate_executable(output_path)

        # Standard formats use gen_file (text mode)
        try:
            with open(output_path, 'w') as fp:
                result = ida_loader.gen_file(
                    int(format), fp, start_ea, end_ea, int(flags)
                )
                return result >= 0
        except (IOError, OSError) as e:
            raise IOError(f"Failed to export range: {e}") from e
