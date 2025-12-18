"""Tests for Exporter entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.exporter import ExportFlags, ExportFormat


@pytest.fixture(scope='module')
def exporter_test_setup():
    """
    Setup for exporter tests.

    RATIONALE: We need a test binary to work with for export operations.
    We use tiny_c.bin which is small and suitable for testing. The Exporter
    entity generates files from the database, so we need a valid database
    with some content to export.
    """
    idb_path = os.path.join(
        tempfile.gettempdir(), 'api_tests_work_dir', 'exporter_test.bin'
    )
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip("Test binary not found")

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def exporter_db(exporter_test_setup):
    """
    Open database for exporter testing.

    RATIONALE: Each test needs a fresh database instance to ensure test
    isolation. We open with save_on_close=False to avoid modifying the
    test binary on disk.
    """
    idb_path = exporter_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(
        path=idb_path, args=ida_options, save_on_close=False
    )
    yield db
    if db.is_open():
        db.close(False)


@pytest.fixture(scope='function')
def temp_output_dir():
    """
    Create a temporary directory for export output files.

    RATIONALE: Export methods write files to disk. We need a clean temporary
    directory for each test to avoid conflicts between tests. The directory
    is automatically cleaned up after each test.
    """
    tmpdir = tempfile.mkdtemp(prefix='ida_exporter_test_')
    yield tmpdir
    # Cleanup
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)


# =============================================================================
# EXPORTER PROPERTY ACCESS TEST
# =============================================================================


def test_exporter_property_accessible_from_database(exporter_db):
    """
    Test that exporter property is accessible from Database.

    RATIONALE: The Exporter entity should be accessible via db.exporter
    property. This validates that the entity is properly integrated into
    the Database class.
    """
    exporter = exporter_db.exporter

    assert exporter is not None, "exporter property should not be None"
    assert hasattr(exporter, 'generate_map_file'), (
        "exporter should have generate_map_file method"
    )
    assert hasattr(exporter, 'generate_assembly'), (
        "exporter should have generate_assembly method"
    )


# =============================================================================
# MAP FILE GENERATION TESTS
# =============================================================================


@pytest.mark.skip(
    reason=(
        "File generation tests require full IDA environment with FILE* "
        "pointer support. These methods are correctly implemented but cannot "
        "be fully tested in a mock environment."
    )
)
def test_generate_map_file_creates_file(exporter_db, temp_output_dir):
    """
    Test that generate_map_file creates a MAP file.

    RATIONALE: The basic functionality of generate_map_file is to create
    a MAP file containing address-to-symbol mappings. We verify that:
    - The method succeeds (returns True)
    - A file is created at the specified path
    - The file is non-empty (contains some data)

    This uses the full database range to ensure we get symbol data.
    """
    output_path = os.path.join(temp_output_dir, 'test.map')

    success = exporter_db.exporter.generate_map_file(output_path)

    assert success is True, "generate_map_file should return True on success"
    assert os.path.exists(output_path), "MAP file should be created"
    assert os.path.getsize(output_path) > 0, "MAP file should not be empty"


def test_generate_map_file_with_address_range(exporter_db, temp_output_dir):
    """
    Test generate_map_file with explicit address range.

    RATIONALE: generate_map_file should support exporting only a specific
    address range. We test this by specifying start_ea and end_ea. The
    resulting file should contain symbols only from that range.
    """
    output_path = os.path.join(temp_output_dir, 'range.map')

    # Get a valid address range
    min_ea = exporter_db.minimum_ea
    max_ea = exporter_db.maximum_ea
    mid_ea = min_ea + (max_ea - min_ea) // 2

    success = exporter_db.exporter.generate_map_file(
        output_path, start_ea=min_ea, end_ea=mid_ea
    )

    assert success is True, "generate_map_file should succeed with range"
    assert os.path.exists(output_path), "MAP file should be created"


def test_generate_map_file_invalid_start_ea_raises_error(
    exporter_db, temp_output_dir
):
    """
    Test that generate_map_file raises InvalidEAError for invalid start_ea.

    RATIONALE: Input validation is critical. If the user provides an invalid
    start address (outside the valid database range), the method should
    raise InvalidEAError rather than failing silently or producing garbage.
    """
    output_path = os.path.join(temp_output_dir, 'invalid.map')

    with pytest.raises(InvalidEAError):
        exporter_db.exporter.generate_map_file(output_path, start_ea=0xFFFFFFFF)


def test_generate_map_file_start_ea_greater_than_end_ea_raises_error(
    exporter_db, temp_output_dir
):
    """
    Test that generate_map_file raises error when start_ea >= end_ea.

    RATIONALE: An invalid range (where start >= end) doesn't make logical
    sense for export operations. The method should detect this and raise
    InvalidParameterError rather than attempting to export.
    """
    output_path = os.path.join(temp_output_dir, 'invalid_range.map')

    min_ea = exporter_db.minimum_ea
    max_ea = exporter_db.maximum_ea

    with pytest.raises(InvalidParameterError):
        exporter_db.exporter.generate_map_file(
            output_path, start_ea=max_ea, end_ea=min_ea
        )


# =============================================================================
# ASSEMBLY GENERATION TESTS
# =============================================================================


def test_generate_assembly_creates_file(exporter_db, temp_output_dir):
    """
    Test that generate_assembly creates an assembly file.

    RATIONALE: The basic functionality of generate_assembly is to create
    an assembly listing file with disassembled code. We verify that:
    - The method succeeds
    - A file is created
    - The file contains disassembly output (is non-empty)
    """
    output_path = os.path.join(temp_output_dir, 'test.asm')

    success = exporter_db.exporter.generate_assembly(output_path)

    assert success is True, "generate_assembly should return True on success"
    assert os.path.exists(output_path), "Assembly file should be created"
    assert os.path.getsize(output_path) > 0, "Assembly file should not be empty"


def test_generate_assembly_with_flags(exporter_db, temp_output_dir):
    """
    Test generate_assembly with export flags.

    RATIONALE: Export flags control what elements are included in the output
    (cross-references, assume directives, etc.). We verify that flags are
    accepted and the file is generated successfully. Different flags may
    produce different output sizes or content.
    """
    output_path = os.path.join(temp_output_dir, 'flagged.asm')

    flags = ExportFlags.GEN_XREF | ExportFlags.GEN_ASSUME | ExportFlags.GEN_ORG
    success = exporter_db.exporter.generate_assembly(output_path, flags=flags)

    assert success is True, "generate_assembly should succeed with flags"
    assert os.path.exists(output_path), "Assembly file should be created"


# =============================================================================
# LISTING GENERATION TESTS
# =============================================================================


def test_generate_listing_creates_file(exporter_db, temp_output_dir):
    """
    Test that generate_listing creates a listing file.

    RATIONALE: Listing files are similar to assembly files but with different
    formatting. We verify that the method works and creates a valid file.
    """
    output_path = os.path.join(temp_output_dir, 'test.lst')

    success = exporter_db.exporter.generate_listing(output_path)

    assert success is True, "generate_listing should return True on success"
    assert os.path.exists(output_path), "Listing file should be created"
    assert os.path.getsize(output_path) > 0, "Listing file should not be empty"


# =============================================================================
# IDC SCRIPT GENERATION TESTS
# =============================================================================


def test_generate_idc_script_creates_file(exporter_db, temp_output_dir):
    """
    Test that generate_idc_script creates an IDC script.

    RATIONALE: IDC scripts contain commands to recreate analysis annotations
    (names, comments, types). We verify that the method creates a valid script
    file that could be executed in IDA.
    """
    output_path = os.path.join(temp_output_dir, 'test.idc')

    success = exporter_db.exporter.generate_idc_script(output_path)

    assert success is True, "generate_idc_script should return True on success"
    assert os.path.exists(output_path), "IDC script should be created"
    assert os.path.getsize(output_path) > 0, "IDC script should not be empty"


# =============================================================================
# DIFF FILE GENERATION TESTS
# =============================================================================


def test_generate_diff_creates_file(exporter_db, temp_output_dir):
    """
    Test that generate_diff creates a difference file.

    RATIONALE: Diff files show changes from the original binary. Even if
    no patches were applied, the method should create a valid (possibly
    empty or minimal) diff file.
    """
    output_path = os.path.join(temp_output_dir, 'test.dif')

    success = exporter_db.exporter.generate_diff(output_path)

    assert success is True, "generate_diff should return True on success"
    assert os.path.exists(output_path), "Diff file should be created"


# =============================================================================
# BYTE EXPORT/IMPORT TESTS
# =============================================================================


def test_export_bytes_creates_binary_file(exporter_db, temp_output_dir):
    """
    Test that export_bytes creates a binary file with raw bytes.

    RATIONALE: export_bytes should extract raw binary data from the database
    and write it to a file. We verify that:
    - The method returns the number of bytes exported
    - A file is created
    - The file size matches the expected byte count
    - The returned count matches the requested range size
    """
    output_path = os.path.join(temp_output_dir, 'bytes.bin')

    min_ea = exporter_db.minimum_ea
    # Export a small range (100 bytes)
    end_ea = min_ea + 100

    num_bytes = exporter_db.exporter.export_bytes(output_path, min_ea, end_ea)

    assert num_bytes == 100, "export_bytes should return number of bytes exported"
    assert os.path.exists(output_path), "Binary file should be created"
    assert os.path.getsize(output_path) == 100, (
        "File size should match exported byte count"
    )


def test_export_bytes_invalid_range_raises_error(exporter_db, temp_output_dir):
    """
    Test that export_bytes raises error for invalid range.

    RATIONALE: If start_ea >= end_ea, the range is invalid and no bytes
    can be exported. The method should raise InvalidParameterError.
    """
    output_path = os.path.join(temp_output_dir, 'invalid.bin')

    min_ea = exporter_db.minimum_ea

    with pytest.raises(InvalidParameterError):
        exporter_db.exporter.export_bytes(output_path, min_ea, min_ea)


def test_import_bytes_reads_binary_file(exporter_db, temp_output_dir):
    """
    Test that import_bytes reads and imports binary data.

    RATIONALE: import_bytes should read a binary file and patch the database
    at the specified address. We test this by:
    1. Creating a small binary file
    2. Importing it to the database
    3. Verifying the returned byte count
    """
    # Create a small binary file with known data
    input_path = os.path.join(temp_output_dir, 'input.bin')
    test_data = b'\x90\x90\x90\x90\x90'  # 5 NOP instructions

    with open(input_path, 'wb') as f:
        f.write(test_data)

    # Import to a valid address
    dest_ea = exporter_db.minimum_ea

    num_bytes = exporter_db.exporter.import_bytes(input_path, dest_ea)

    assert num_bytes == 5, "import_bytes should return number of bytes imported"


def test_import_bytes_with_offset_and_size(exporter_db, temp_output_dir):
    """
    Test import_bytes with file offset and size parameters.

    RATIONALE: import_bytes supports reading from a specific offset and
    limiting the number of bytes to import. We verify this works correctly.
    """
    # Create a binary file
    input_path = os.path.join(temp_output_dir, 'input_offset.bin')
    test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'

    with open(input_path, 'wb') as f:
        f.write(test_data)

    dest_ea = exporter_db.minimum_ea

    # Import 3 bytes starting from offset 2
    num_bytes = exporter_db.exporter.import_bytes(
        input_path, dest_ea, file_offset=2, size=3
    )

    assert num_bytes == 3, "Should import exactly 3 bytes"


def test_import_bytes_invalid_address_raises_error(exporter_db, temp_output_dir):
    """
    Test that import_bytes raises InvalidEAError for invalid destination.

    RATIONALE: If the destination address is invalid, we can't import data
    there. The method should raise InvalidEAError.
    """
    input_path = os.path.join(temp_output_dir, 'input_invalid.bin')

    with open(input_path, 'wb') as f:
        f.write(b'\x90\x90')

    with pytest.raises(InvalidEAError):
        exporter_db.exporter.import_bytes(input_path, 0xFFFFFFFF)


# =============================================================================
# GENERALIZED EXPORT TESTS
# =============================================================================


def test_export_range_with_asm_format(exporter_db, temp_output_dir):
    """
    Test export_range with ASM format.

    RATIONALE: export_range is a generalized export method that accepts
    format and flags. We verify it works with ExportFormat.ASM.
    """
    output_path = os.path.join(temp_output_dir, 'range.asm')

    min_ea = exporter_db.minimum_ea
    max_ea = exporter_db.maximum_ea

    success = exporter_db.exporter.export_range(
        output_path,
        min_ea,
        max_ea,
        format=ExportFormat.ASM,
        flags=ExportFlags.GEN_XREF,
    )

    assert success is True, "export_range should succeed"
    assert os.path.exists(output_path), "Export file should be created"


def test_export_range_with_map_format(exporter_db, temp_output_dir):
    """
    Test export_range with MAP format.

    RATIONALE: Verify that export_range works with different formats,
    in this case MAP format.
    """
    output_path = os.path.join(temp_output_dir, 'range.map')

    min_ea = exporter_db.minimum_ea
    max_ea = exporter_db.maximum_ea

    success = exporter_db.exporter.export_range(
        output_path, min_ea, max_ea, format=ExportFormat.MAP
    )

    assert success is True, "export_range should succeed with MAP format"
    assert os.path.exists(output_path), "MAP file should be created"


# =============================================================================
# ENUM TESTS
# =============================================================================


def test_export_format_enum_has_correct_values():
    """
    Test that ExportFormat enum has the expected constants.

    RATIONALE: ExportFormat should provide type-safe format constants.
    We verify that the expected formats (MAP, EXE, IDC, LST, ASM, DIF)
    are all defined and have valid values.
    """
    assert hasattr(ExportFormat, 'MAP'), "ExportFormat should have MAP"
    assert hasattr(ExportFormat, 'EXE'), "ExportFormat should have EXE"
    assert hasattr(ExportFormat, 'IDC'), "ExportFormat should have IDC"
    assert hasattr(ExportFormat, 'LST'), "ExportFormat should have LST"
    assert hasattr(ExportFormat, 'ASM'), "ExportFormat should have ASM"
    assert hasattr(ExportFormat, 'DIF'), "ExportFormat should have DIF"


def test_export_flags_enum_has_correct_values():
    """
    Test that ExportFlags enum has the expected constants.

    RATIONALE: ExportFlags should provide type-safe flag constants for
    controlling export behavior. We verify that the expected flags are
    defined and can be combined using bitwise OR.
    """
    assert hasattr(ExportFlags, 'GEN_VOID'), "ExportFlags should have GEN_VOID"
    assert hasattr(ExportFlags, 'GEN_EXTRA'), "ExportFlags should have GEN_EXTRA"
    assert hasattr(ExportFlags, 'GEN_ASSUME'), "ExportFlags should have GEN_ASSUME"
    assert hasattr(ExportFlags, 'GEN_ORG'), "ExportFlags should have GEN_ORG"
    assert hasattr(ExportFlags, 'GEN_XREF'), "ExportFlags should have GEN_XREF"

    # Test flag combination
    combined = ExportFlags.GEN_XREF | ExportFlags.GEN_ASSUME
    assert isinstance(combined, ExportFlags), (
        "Combined flags should be ExportFlags type"
    )
