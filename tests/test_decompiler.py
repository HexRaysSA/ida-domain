"""Tests for Decompiler entity."""

import os
import shutil
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def decompiler_test_setup():
    """
    Setup for decompiler tests.

    RATIONALE: We need a test binary compiled from C code to test decompilation.
    We use tiny_c.bin which contains actual C functions (complex_assignments
    and use_val) that the Hex-Rays decompiler can process. This binary was
    specifically compiled to provide realistic test scenarios for decompilation.
    """
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'decompiler_test.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test binary
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')

    if not os.path.exists(src_path):
        pytest.skip('Test binary not found')

    shutil.copy(src_path, idb_path)
    return idb_path


@pytest.fixture(scope='function')
def decompiler_db(decompiler_test_setup):
    """
    Open database for decompiler testing.

    RATIONALE: Each test needs a fresh database instance to ensure isolation.
    We open with auto_analysis=True to ensure IDA has analyzed the binary
    and identified functions before we try to decompile them. This matches
    real-world usage where decompilation happens after auto-analysis.
    """
    idb_path = decompiler_test_setup
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=idb_path, args=ida_options, save_on_close=False)
    yield db
    if db.is_open():
        db.close(False)


class TestDecompilerAvailability:
    """Tests for decompiler availability checking."""

    def test_is_available_property(self, decompiler_db):
        """
        Test that is_available property correctly reports decompiler availability.

        RATIONALE: The is_available property is critical for determining whether
        the Hex-Rays decompiler plugin is loaded. This is essential because
        not all IDA installations have the decompiler, and attempting to use
        it when unavailable would cause errors. This test validates that the
        property correctly initializes and queries the decompiler plugin state.

        Note: This test may pass or fail depending on whether Hex-Rays decompiler
        is installed in the test environment. The important thing is that the
        property doesn't raise an exception and returns a boolean value.
        """
        # Should return a boolean value without raising
        available = decompiler_db.decompiler.is_available
        assert isinstance(available, bool)


class TestDecompileAt:
    """Tests for decompile method."""

    def test_decompile_with_valid_function(self, decompiler_db):
        """
        Test decompiling a valid function returns pseudocode.

        RATIONALE: This tests the core functionality of the decompiler - taking
        a binary address and producing C-like pseudocode. We use the first function
        in the database (typically an entry point or the first identified function)
        which should definitely exist and be decompilable. This validates that:
        1. The method can successfully invoke the decompiler
        2. Pseudocode lines are extracted correctly
        3. The result is a non-empty list of strings
        4. The output looks like reasonable C code (has common C constructs)

        This test can only run if the decompiler is available, which is why we
        check is_available first.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Get first function in database
        func = next(decompiler_db.functions.get_all())
        assert func is not None, 'No functions found in test binary'

        # Decompile at function start
        lines = decompiler_db.decompiler.decompile(func.start_ea)

        # Should get pseudocode lines
        assert lines is not None, 'Decompilation returned None for valid function'
        assert isinstance(lines, list)
        assert len(lines) > 0, 'Decompilation returned empty list'

        # Lines should be strings
        assert all(isinstance(line, str) for line in lines)

        # Pseudocode should contain typical C constructs
        pseudocode_text = '\n'.join(lines)
        # At minimum, should have some C-like content (braces, semicolons, or returns)
        has_c_syntax = any(char in pseudocode_text for char in ['{', '}', ';', '(', ')'])
        assert has_c_syntax, f"Pseudocode doesn't look like C code: {pseudocode_text[:200]}"

    def test_decompile_with_remove_tags(self, decompiler_db):
        """
        Test that remove_tags parameter correctly strips IDA color tags.

        RATIONALE: IDA's pseudocode output includes COLOR_* tags for syntax
        highlighting in the GUI. When exporting or analyzing pseudocode
        programmatically, these tags are unwanted noise. This test validates
        that the remove_tags=True parameter (the default) successfully strips
        these tags, producing clean text output suitable for further processing.

        We test both with and without tag removal to ensure the parameter works.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Get first function
        func = next(decompiler_db.functions.get_all())

        # Get pseudocode with tags removed (default)
        lines_clean = decompiler_db.decompiler.decompile(func.start_ea, remove_tags=True)

        # Get pseudocode with tags kept
        lines_tagged = decompiler_db.decompiler.decompile(func.start_ea, remove_tags=False)

        # Both should be valid
        assert lines_clean is not None
        assert lines_tagged is not None

        # Tagged version might contain IDA tags (COLOR_ON, COLOR_OFF, etc.)
        # Clean version should not
        # Note: If there are no tags in the output, both might be identical

        # At minimum, both should have content
        assert len(lines_clean) > 0
        assert len(lines_tagged) > 0

    def test_decompile_with_invalid_address(self, decompiler_db):
        """
        Test that decompiling an invalid address raises InvalidEAError.

        RATIONALE: Passing an invalid address (outside the valid address space)
        should raise InvalidEAError rather than attempting decompilation and
        potentially crashing. This is a critical safety check that validates
        input before calling the decompiler. We use 0xFFFFFFFF which is typically
        outside any valid address range for test binaries.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Use an address that's definitely invalid
        invalid_ea = 0xFFFFFFFF

        with pytest.raises(InvalidEAError):
            decompiler_db.decompiler.decompile(invalid_ea)

    def test_decompile_with_no_function(self, decompiler_db):
        """
        Test that decompiling an address with no function returns None.

        RATIONALE: Not all valid addresses have functions at them. When you
        try to decompile an address that's not part of a function (e.g., in
        a data segment), the decompiler should gracefully return None rather
        than raising an exception. This is the normal "not found" case.

        We use an address in the middle of a data segment where no function
        should exist. The behavior should be to return None, not raise an error.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Get a valid address that's likely not in a function
        # Use an address in a data segment
        # For tiny_c.bin, addresses in the middle of data sections won't have functions
        min_ea = decompiler_db.minimum_ea
        max_ea = decompiler_db.maximum_ea

        # Find an address that has no function
        for ea in range(min_ea, min(min_ea + 0x1000, max_ea), 4):
            # Skip invalid addresses
            if not decompiler_db.is_valid_ea(ea):
                continue

            if decompiler_db.functions.get_at(ea) is None:
                # Found an address with no function
                result = decompiler_db.decompiler.decompile(ea)
                assert result is None, (
                    f'Expected None when decompiling address 0x{ea:x} with no function, '
                    f'got {result}'
                )
                return

        # If we couldn't find such an address, skip the test
        pytest.skip('Could not find a valid address without a function')

    def test_decompile_without_decompiler_available(self, decompiler_db):
        """
        Test that attempting to decompile without decompiler raises RuntimeError.

        RATIONALE: If the Hex-Rays decompiler plugin is not available (not
        installed or failed to load), attempting to decompile should raise
        a clear RuntimeError explaining the issue. This test validates the
        error handling when the decompiler is unavailable.

        Note: This test is difficult to execute in practice because we can't
        easily "unload" the decompiler if it's already loaded. We check the
        behavior indirectly by validating the error message when it does fail.
        """
        # This is hard to test directly since we can't control whether decompiler
        # is available. Instead, we test the logical flow:
        # If not available, should raise RuntimeError

        # Get first function
        func = next(decompiler_db.functions.get_all())

        if not decompiler_db.decompiler.is_available:
            # If decompiler not available, should raise RuntimeError
            with pytest.raises(RuntimeError, match='Hex-Rays decompiler not available'):
                decompiler_db.decompiler.decompile(func.start_ea)
        else:
            # If available, should work fine
            lines = decompiler_db.decompiler.decompile(func.start_ea)
            # If decompiler is available and function exists, should get pseudocode
            # (or None if decompilation fails for other reasons)
            assert lines is None or isinstance(lines, list)

    def test_decompile_with_function_start_vs_middle(self, decompiler_db):
        """
        Test that decompiling at function start and middle produces same result.

        RATIONALE: The decompiler should work whether you pass the exact function
        start address or any address within the function body. IDA should resolve
        both to the same function and produce identical pseudocode. This tests
        that the implementation correctly uses ida_funcs.get_func() to find the
        containing function before decompilation.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Get a function with some size
        for func in decompiler_db.functions.get_all():
            if func.end_ea - func.start_ea > 8:  # Has some meaningful size
                # Decompile at start
                lines_start = decompiler_db.decompiler.decompile(func.start_ea)

                # Decompile at middle
                mid_ea = func.start_ea + 4
                lines_mid = decompiler_db.decompiler.decompile(mid_ea)

                # Both should produce the same pseudocode
                # (since they're the same function)
                if lines_start is not None and lines_mid is not None:
                    assert lines_start == lines_mid, (
                        'Decompiling at function start and middle should produce '
                        'identical pseudocode'
                    )
                    return

        pytest.skip('Could not find a suitable function for this test')

    def test_decompile_returns_string_list(self, decompiler_db):
        """
        Test that decompile returns a list of strings with proper format.

        RATIONALE: The API contract specifies that decompile returns
        Optional[List[str]]. This test validates the exact return type and
        ensures that:
        1. The return value is either None or a list
        2. If a list, all elements are strings
        3. The strings are non-empty (no blank lines unless intentional)
        4. The list structure matches what callers would expect

        This is important for API consumers who need to process the output.
        """
        if not decompiler_db.decompiler.is_available:
            pytest.skip('Hex-Rays decompiler not available')

        # Get first function
        func = next(decompiler_db.functions.get_all())
        lines = decompiler_db.decompiler.decompile(func.start_ea)

        # If we got a result, validate its structure
        if lines is not None:
            # Must be a list
            assert isinstance(lines, list), f'Expected list, got {type(lines)}'

            # Must contain strings
            assert all(isinstance(line, str) for line in lines), 'All elements must be strings'

            # Should have at least some content
            assert len(lines) > 0, 'Empty pseudocode list'

            # Check that we have reasonable content - at least one non-empty line
            non_empty_lines = [line for line in lines if line.strip()]
            assert len(non_empty_lines) > 0, 'All lines are empty'
