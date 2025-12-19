"""Tests for Functions entity - navigation methods."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def functions_test_setup():
    """Setup for Functions tests - prepares tiny_asm.bin database."""
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_asm.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy tiny_asm.bin from test resources
    import shutil

    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_asm.bin')
    shutil.copy2(src_path, idb_path)

    yield idb_path

    # Cleanup is handled by temp directory


@pytest.fixture(scope='function')
def test_env(functions_test_setup):
    """Opens tiny_asm database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=functions_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestFunctionsGetPrevious:
    """Tests for get_previous() method."""

    def test_get_previous_from_second_function_returns_first(self, test_env):
        """
        Test that get_previous() returns the previous function in the binary.

        RATIONALE: This validates that get_previous() correctly navigates backward
        through functions in the IDA database. In tiny_asm.bin, we have multiple
        functions in a known order (_start, test_all_operand_types, add_numbers,
        etc.). By finding a function and calling get_previous(), we should get the
        preceding function in memory order. This is essential for reverse iteration
        through function lists and analyzing call hierarchies.
        """
        db = test_env

        # Get all functions in order
        all_funcs = list(db.functions.get_all())
        assert len(all_funcs) >= 2, 'Need at least 2 functions for this test'

        # Take the second function and find its predecessor
        second_func = all_funcs[1]
        prev_func = db.functions.get_previous(second_func.start_ea)

        # The previous function should be the first function
        assert prev_func is not None
        assert prev_func.start_ea == all_funcs[0].start_ea

    def test_get_previous_from_first_function_returns_none(self, test_env):
        """
        Test that get_previous() returns None when called on the first function.

        RATIONALE: Boundary condition testing is critical for navigation methods.
        When we're at the first function in the database, there is no previous
        function, so get_previous() should return None rather than throwing an
        exception or returning invalid data. This ensures callers can reliably
        check for the start of the function list.
        """
        db = test_env

        # Get the first function
        all_funcs = list(db.functions.get_all())
        first_func = all_funcs[0]

        # Get previous from first function should be None
        prev_func = db.functions.get_previous(first_func.start_ea)
        assert prev_func is None

    def test_get_previous_with_invalid_ea_raises_error(self, test_env):
        """
        Test that get_previous() raises InvalidEAError for invalid addresses.

        RATIONALE: Input validation is crucial for API robustness. Passing an
        address outside the valid database range (like 0xFFFFFFFF) should be
        detected early and raise a clear exception. This prevents undefined
        behavior in the underlying IDA API and gives callers clear error feedback.
        """
        db = test_env

        with pytest.raises(InvalidEAError):
            db.functions.get_previous(0xFFFFFFFFFFFFFFFF)

    def test_get_previous_backward_iteration(self, test_env):
        """
        Test backward iteration through all functions using get_previous().

        RATIONALE: This validates that get_previous() can be used reliably for
        reverse iteration, which is a common pattern when analyzing functions
        from the end of a binary backwards. We start from the last function
        and walk backwards, verifying we visit all functions and end at None.
        This ensures the method integrates correctly with the database's
        function ordering.
        """
        db = test_env

        # Get all functions to know the expected order
        all_funcs = list(db.functions.get_all())

        # Start from the last function and iterate backwards
        current_ea = all_funcs[-1].end_ea
        visited_count = 0

        while True:
            func = db.functions.get_previous(current_ea)
            if func is None:
                break
            visited_count += 1
            current_ea = func.start_ea

        # Should have visited all functions
        assert visited_count == len(all_funcs)


class TestFunctionsReanalyze:
    """Tests for reanalyze() method."""

    def test_reanalyze_executes_without_error(self, test_env):
        """
        Test that reanalyze() successfully triggers complete function reanalysis.

        RATIONALE: reanalyze() performs a more comprehensive reanalysis than update(),
        including control flow, stack analysis, and type propagation. This is useful
        after significant code modifications or when IDA's initial analysis was
        incomplete. This test validates that reanalyze() can be called on a function
        and returns True, indicating the reanalysis was initiated. The method should
        handle the underlying IDA API call correctly and always return successfully.
        """
        db = test_env

        # Get a function
        all_funcs = list(db.functions.get_all())
        assert len(all_funcs) > 0, 'Need at least one function for test'

        func = all_funcs[0]

        # Call reanalyze
        result = db.functions.reanalyze(func)

        # Should return True (indicating reanalysis was initiated)
        assert result is True

    def test_reanalyze_on_multiple_functions(self, test_env):
        """
        Test that reanalyze() works correctly when called on multiple functions.

        RATIONALE: In practice, users may need to reanalyze multiple functions in
        a loop, for example after applying global patches or signature changes.
        This test validates that reanalyze() can be called sequentially on different
        functions without interference or errors. Each call should successfully
        initiate reanalysis for its target function independently.
        """
        db = test_env

        # Get multiple functions
        all_funcs = list(db.functions.get_all())
        assert len(all_funcs) >= 2, 'Need at least 2 functions for test'

        # Reanalyze first two functions
        for i in range(min(2, len(all_funcs))):
            func = all_funcs[i]
            result = db.functions.reanalyze(func)
            assert result is True

    def test_reanalyze_returns_boolean(self, test_env):
        """
        Test that reanalyze() consistently returns a boolean value.

        RATIONALE: API consistency requires that methods have predictable return
        types. reanalyze() is documented to return bool, indicating whether the
        reanalysis was initiated (always True in current implementation). This test
        validates the return type contract, ensuring callers can rely on getting
        a boolean result for status checking and flow control.
        """
        db = test_env

        # Get a function
        all_funcs = list(db.functions.get_all())
        func = all_funcs[0]

        # Call reanalyze and check return type
        result = db.functions.reanalyze(func)
        assert isinstance(result, bool)
        assert result is True  # Current implementation always returns True


class TestFunctionsCount:
    """Tests for count() method."""

    def test_functions_count(self, test_env):
        """Test count() returns total function count."""
        db = test_env
        count = db.functions.count()
        assert isinstance(count, int)
        assert count >= 0
        # Should match len()
        assert count == len(db.functions)


class TestFunctionsExistsAt:
    """Tests for exists_at() method."""

    def test_functions_exists_at(self, test_env):
        """Test exists_at() checks if function exists."""
        db = test_env
        # Get a known function address
        func = next(iter(db.functions.get_all()), None)
        if func:
            assert db.functions.exists_at(func.start_ea) is True
        # Non-function address should return False
        assert db.functions.exists_at(0xDEADBEEF) is False


class TestFunctionsGetInRange:
    """Tests for get_in_range() method."""

    def test_functions_get_in_range_alias(self, test_env):
        """Test get_in_range() is alias for get_between()."""
        db = test_env
        start = db.minimum_ea
        end = db.maximum_ea

        between_funcs = list(db.functions.get_between(start, end))
        range_funcs = list(db.functions.get_in_range(start, end))

        assert len(between_funcs) == len(range_funcs)
        for f1, f2 in zip(between_funcs, range_funcs):
            assert f1.start_ea == f2.start_ea


class TestFunctionsDelete:
    """Tests for delete() method."""

    def test_functions_delete_exists_and_is_callable(self, test_env):
        """Test delete() exists and is callable as alias for remove()."""
        db = test_env

        # Verify delete method exists
        assert hasattr(db.functions, 'delete')

        # Verify it's callable
        assert callable(db.functions.delete)
