"""Tests for CallGraph entity - inter-procedural call graph traversal."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.callgraph import CallGraph, CallPath
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def callgraph_test_setup():
    """Setup for CallGraph tests - prepares test_callgraph.bin database."""
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'test_callgraph.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy test_callgraph.bin from test resources
    import shutil

    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'test_callgraph.bin')
    shutil.copy2(src_path, idb_path)

    yield idb_path

    # Cleanup is handled by temp directory


@pytest.fixture(scope='function')
def test_env(callgraph_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=callgraph_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestCallGraphProperty:
    """Tests for callgraph property on Database."""

    def test_callgraph_property_exists(self, test_env):
        """
        Test that the callgraph property exists on Database.

        RATIONALE: The callgraph property provides access to call graph traversal
        functionality. This test verifies basic availability.
        """
        assert hasattr(test_env, 'callgraph'), 'Database should have callgraph property'

    def test_callgraph_returns_callgraph_instance(self, test_env):
        """
        Test that the callgraph property returns a CallGraph instance.

        RATIONALE: The property should return the correct type for type safety.
        """
        cg = test_env.callgraph
        assert isinstance(cg, CallGraph), 'callgraph should return CallGraph instance'

    def test_callgraph_property_is_cached(self, test_env):
        """
        Test that the callgraph property returns the same instance.

        RATIONALE: For performance, the CallGraph instance should be cached
        and reused across multiple property accesses.
        """
        cg1 = test_env.callgraph
        cg2 = test_env.callgraph
        assert cg1 is cg2, 'callgraph should return cached instance'


class TestCallersOf:
    """Tests for callers_of method."""

    def test_callers_of_returns_iterator(self, test_env):
        """
        Test that callers_of returns an iterator.

        RATIONALE: The method should return an iterator for memory efficiency
        when dealing with potentially large call graphs.
        """
        # Get first function
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found in test binary')

        result = test_env.callgraph.callers_of(func.start_ea)
        # Check it's iterable
        assert hasattr(result, '__iter__'), 'callers_of should return an iterator'
        assert hasattr(result, '__next__'), 'callers_of should return an iterator'

    def test_callers_of_depth_one_matches_direct_xrefs(self, test_env):
        """
        Test that callers_of with depth=1 matches direct call xrefs.

        RATIONALE: With depth=1, callers_of should return the same results
        as directly querying call xrefs, ensuring consistency.
        """
        # Find a function with callers
        func_with_callers = None
        for func in test_env.functions.get_all():
            # Check if function has call references
            has_callers = False
            for call_site in test_env.xrefs.calls_to_ea(func.start_ea):
                caller_func = test_env.functions.get_at(call_site)
                if caller_func:
                    has_callers = True
                    break
            if has_callers:
                func_with_callers = func
                break

        if func_with_callers is None:
            pytest.skip('No function with callers found in test binary')

        # Get callers using callgraph
        cg_callers = set(test_env.callgraph.callers_of(func_with_callers.start_ea, max_depth=1))

        # Get callers using direct xref query
        xref_callers = set()
        for call_site in test_env.xrefs.calls_to_ea(func_with_callers.start_ea):
            caller_func = test_env.functions.get_at(call_site)
            if caller_func:
                xref_callers.add(caller_func.start_ea)

        assert cg_callers == xref_callers, (
            f'callers_of(depth=1) should match direct xref callers: '
            f'got {len(cg_callers)}, expected {len(xref_callers)}'
        )

    def test_callers_of_with_invalid_ea_raises_error(self, test_env):
        """
        Test that callers_of raises InvalidEAError for invalid addresses.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            list(test_env.callgraph.callers_of(invalid_ea))

    def test_callers_of_with_higher_depth(self, test_env):
        """
        Test callers_of with depth > 1 finds transitive callers.

        RATIONALE: The method should traverse multiple levels of the call graph
        when depth > 1, finding callers of callers.
        """
        # Find a function that is called
        func_with_callers = None
        for func in test_env.functions.get_all():
            for call_site in test_env.xrefs.calls_to_ea(func.start_ea):
                caller_func = test_env.functions.get_at(call_site)
                if caller_func:
                    func_with_callers = func
                    break
            if func_with_callers:
                break

        if func_with_callers is None:
            pytest.skip('No function with callers found')

        # Get callers at depth 1
        depth1 = set(test_env.callgraph.callers_of(func_with_callers.start_ea, max_depth=1))

        # Get callers at depth 5 (should include depth 1 plus more)
        depth5 = set(test_env.callgraph.callers_of(func_with_callers.start_ea, max_depth=5))

        # Depth 5 should include all of depth 1
        assert depth1.issubset(depth5), (
            'callers at depth 5 should include all callers at depth 1'
        )


class TestCalleesOf:
    """Tests for callees_of method."""

    def test_callees_of_returns_iterator(self, test_env):
        """
        Test that callees_of returns an iterator.

        RATIONALE: The method should return an iterator for memory efficiency.
        """
        # Get first function
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found in test binary')

        result = test_env.callgraph.callees_of(func.start_ea)
        # Check it's iterable
        assert hasattr(result, '__iter__'), 'callees_of should return an iterator'
        assert hasattr(result, '__next__'), 'callees_of should return an iterator'

    def test_callees_of_finds_direct_calls(self, test_env):
        """
        Test that callees_of finds functions called by the given function.

        RATIONALE: With depth=1, callees_of should find all functions directly
        called by the given function.
        """
        # Find a function that makes calls
        func_with_calls = None
        for func in test_env.functions.get_all():
            # Check if function has any call instructions
            for insn in test_env.instructions.get_between(func.start_ea, func.end_ea):
                for target in test_env.xrefs.calls_from_ea(insn.ea):
                    target_func = test_env.functions.get_at(target)
                    if target_func:
                        func_with_calls = func
                        break
                if func_with_calls:
                    break
            if func_with_calls:
                break

        if func_with_calls is None:
            pytest.skip('No function with call instructions found')

        # Get callees using callgraph
        callees = list(test_env.callgraph.callees_of(func_with_calls.start_ea, max_depth=1))

        # Should have at least one callee
        assert len(callees) > 0, 'Function with calls should have at least one callee'

    def test_callees_of_with_invalid_ea_raises_error(self, test_env):
        """
        Test that callees_of raises InvalidEAError for invalid addresses.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            list(test_env.callgraph.callees_of(invalid_ea))


class TestPathsBetween:
    """Tests for paths_between method."""

    def test_paths_between_returns_iterator(self, test_env):
        """
        Test that paths_between returns an iterator.

        RATIONALE: The method should return an iterator of CallPath objects.
        """
        funcs = list(test_env.functions.get_all())
        if len(funcs) < 2:
            pytest.skip('Need at least 2 functions')

        result = test_env.callgraph.paths_between(funcs[0].start_ea, funcs[1].start_ea)
        # Check it's iterable
        assert hasattr(result, '__iter__'), 'paths_between should return an iterator'

    def test_paths_between_same_function_returns_single_path(self, test_env):
        """
        Test that paths_between with same src and dst returns single-element path.

        RATIONALE: When source and destination are the same function, the path
        should contain just that function.
        """
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found')

        paths = list(test_env.callgraph.paths_between(func.start_ea, func.start_ea))
        assert len(paths) == 1, 'Same src and dst should yield exactly one path'
        assert len(paths[0]) == 1, 'Path to self should have length 1'
        assert paths[0].path[0] == func.start_ea, 'Path should contain the function'

    def test_paths_between_with_invalid_src_raises_error(self, test_env):
        """
        Test that paths_between raises InvalidEAError for invalid source address.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found')

        with pytest.raises(InvalidEAError):
            list(test_env.callgraph.paths_between(invalid_ea, func.start_ea))

    def test_paths_between_with_invalid_dst_raises_error(self, test_env):
        """
        Test that paths_between raises InvalidEAError for invalid destination address.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found')

        with pytest.raises(InvalidEAError):
            list(test_env.callgraph.paths_between(func.start_ea, invalid_ea))


class TestReachabilityMethods:
    """Tests for reachable_from and reaches methods."""

    def test_reachable_from_returns_set(self, test_env):
        """
        Test that reachable_from returns a set.

        RATIONALE: The method should return a set for efficient membership testing.
        """
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found')

        result = test_env.callgraph.reachable_from(func.start_ea)
        assert isinstance(result, set), 'reachable_from should return a set'

    def test_reaches_returns_set(self, test_env):
        """
        Test that reaches returns a set.

        RATIONALE: The method should return a set for efficient membership testing.
        """
        func = next(test_env.functions.get_all(), None)
        if func is None:
            pytest.skip('No functions found')

        result = test_env.callgraph.reaches(func.start_ea)
        assert isinstance(result, set), 'reaches should return a set'

    def test_reachable_from_with_invalid_ea_raises_error(self, test_env):
        """
        Test that reachable_from raises InvalidEAError for invalid addresses.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.callgraph.reachable_from(invalid_ea)

    def test_reaches_with_invalid_ea_raises_error(self, test_env):
        """
        Test that reaches raises InvalidEAError for invalid addresses.

        RATIONALE: All methods should validate addresses and raise appropriate errors.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.callgraph.reaches(invalid_ea)


class TestCallPathDataclass:
    """Tests for CallPath dataclass."""

    def test_callpath_len(self):
        """
        Test CallPath __len__ returns path length.

        RATIONALE: CallPath should support len() for convenient path length checking.
        """
        path = CallPath([0x1000, 0x2000, 0x3000])
        assert len(path) == 3

    def test_callpath_iter(self):
        """
        Test CallPath __iter__ allows iteration over addresses.

        RATIONALE: CallPath should be iterable for convenient traversal.
        """
        addresses = [0x1000, 0x2000, 0x3000]
        path = CallPath(addresses)
        assert list(path) == addresses

    def test_callpath_repr(self):
        """
        Test CallPath __repr__ shows hex addresses.

        RATIONALE: CallPath repr should show addresses in hex for debugging.
        """
        path = CallPath([0x1000, 0x2000])
        repr_str = repr(path)

        assert 'CallPath' in repr_str
        assert '0x1000' in repr_str
        assert '0x2000' in repr_str
        assert '->' in repr_str
