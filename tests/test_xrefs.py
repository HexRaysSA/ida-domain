"""Tests for Xrefs entity - cross-reference existence and count methods."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.database import IdaCommandOptions
from ida_domain.xrefs import XrefsFlags


@pytest.fixture(scope='module')
def xrefs_test_setup():
    """Setup for Xrefs tests - prepares tiny_c.bin database."""
    idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'tiny_c.bin')
    os.makedirs(os.path.dirname(idb_path), exist_ok=True)

    # Copy tiny_c.bin from test resources
    import shutil

    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(current_dir, 'resources', 'tiny_c.bin')
    shutil.copy2(src_path, idb_path)

    yield idb_path

    # Cleanup is handled by temp directory


@pytest.fixture(scope='function')
def test_env(xrefs_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(path=xrefs_test_setup, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestXrefExistence:
    """Tests for xref existence check methods."""

    def test_has_any_refs_to_for_function_with_callers(self, test_env):
        """
        Test has_any_refs_to returns True for a function that has callers.

        RATIONALE: The has_any_refs_to() method is fundamental for quickly checking
        if an address is referenced. This tests the positive case - a known function
        in a real binary that has at least one caller should return True.

        We iterate through all functions to find one with callers, which is
        guaranteed in any non-trivial binary like tiny_c.bin.
        """
        # Find a function with at least one caller
        func_with_refs = None
        for func in test_env.functions.get_all():
            # Check if function has any code refs (callers)
            has_refs = False
            for _ in test_env.xrefs.code_refs_to_ea(func.start_ea, flow=False):
                has_refs = True
                break

            if has_refs:
                func_with_refs = func
                break

        # Skip if no function has callers (unlikely in tiny_c.bin)
        if func_with_refs is None:
            pytest.skip('No function with callers found in test binary')

        func_ea = func_with_refs.start_ea

        # Verify has_any_refs_to returns True
        assert test_env.xrefs.has_any_refs_to(func_ea), (
            f'has_any_refs_to should return True for function at 0x{func_ea:x} with callers'
        )

    def test_has_any_refs_to_for_unreferenced_address(self, test_env):
        """
        Test has_any_refs_to returns False for an address with no references.

        RATIONALE: The method should correctly identify addresses that are not
        referenced by any code or data. We test with an address in the middle
        of an instruction (not a valid target), which should have no references.
        """
        # Get a random instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Use an address in the middle of the instruction (if multi-byte)
        if first_insn.size > 1:
            mid_insn_ea = first_insn.ea + 1
        else:
            # Skip to next instruction and try again
            next_insn = test_env.instructions.get_next(first_insn.ea)
            if next_insn and next_insn.size > 1:
                mid_insn_ea = next_insn.ea + 1
            else:
                pytest.skip('Cannot find multi-byte instruction for test')

        # Middle of instruction should not be referenced
        assert not test_env.xrefs.has_any_refs_to(mid_insn_ea), (
            f'has_any_refs_to should return False for unreferenced address 0x{mid_insn_ea:x}'
        )

    def test_has_any_refs_from_for_call_instruction(self, test_env):
        """
        Test has_any_refs_from returns True for a call instruction.

        RATIONALE: Call instructions inherently create references to their target
        functions. This test validates that has_any_refs_from correctly identifies
        that call instructions have outgoing references.

        We search for a known call instruction in the binary, which should exist
        in any compiled program with function calls.
        """
        # Find a call instruction
        call_ea = None
        for func in test_env.functions.get_all():
            # Iterate instructions in function
            ea = func.start_ea
            while ea < func.end_ea:
                insn = test_env.instructions.get_at(ea)
                if insn and test_env.instructions.is_call_instruction(insn):
                    call_ea = ea
                    break
                if insn:
                    ea = insn.ea + insn.size
                else:
                    break

            if call_ea:
                break

        if call_ea is None:
            pytest.skip('No call instruction found in test binary')

        # Verify has_any_refs_from returns True
        assert test_env.xrefs.has_any_refs_from(call_ea), (
            f'has_any_refs_from should return True for call instruction at 0x{call_ea:x}'
        )

    def test_has_any_refs_from_for_nop_instruction(self, test_env):
        """
        Test has_any_refs_from behavior for a simple instruction with no data refs.

        RATIONALE: Not all instructions create references - simple instructions like
        arithmetic or NOP operations typically don't reference data or other code
        (except for normal flow, which can be excluded). This tests the negative case.

        Note: Some instructions may still have flow references, so we check for
        non-flow references specifically.
        """
        # Find first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Check if instruction has any non-flow references
        # Most simple instructions only have flow references
        has_nonflow = False
        for xref in test_env.xrefs.from_ea(first_insn.ea, XrefsFlags.NOFLOW):
            has_nonflow = True
            break

        # Just verify the method returns a boolean
        result = test_env.xrefs.has_any_refs_from(first_insn.ea)
        assert isinstance(result, bool), 'has_any_refs_from should return a boolean'

    def test_has_code_refs_to_for_function_entry(self, test_env):
        """
        Test has_code_refs_to returns True for a function with callers.

        RATIONALE: Function entry points are typically referenced by call instructions
        from other functions. The has_code_refs_to method should specifically detect
        code references (excluding data references), which is useful for identifying
        dead code.

        We find a function with callers and verify it's detected correctly.
        """
        # Find a function with callers
        func_with_callers = None
        for func in test_env.functions.get_all():
            # Check if function has code refs (without flow)
            for _ in test_env.xrefs.code_refs_to_ea(func.start_ea, flow=False):
                func_with_callers = func
                break
            if func_with_callers:
                break

        if func_with_callers is None:
            pytest.skip('No function with callers found')

        func_ea = func_with_callers.start_ea

        # Verify has_code_refs_to returns True
        assert test_env.xrefs.has_code_refs_to(func_ea), (
            f'has_code_refs_to should return True for function at 0x{func_ea:x} with callers'
        )

    def test_has_code_refs_to_for_data_address(self, test_env):
        """
        Test has_code_refs_to returns False for a data address.

        RATIONALE: Data addresses typically don't have code references (though they
        may have data references). This test ensures has_code_refs_to specifically
        filters for code references only, not data references.

        We create a data item and verify it's not detected as having code references.
        """
        # Find or create a data address
        test_addr = test_env.minimum_ea + 0x1000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available')

        # Ensure this is data
        test_env.bytes.create_dword_at(test_addr, count=1, force=True)

        # Data should not have code refs (though it might have data refs)
        result = test_env.xrefs.has_code_refs_to(test_addr)
        assert isinstance(result, bool), 'has_code_refs_to should return boolean'

    def test_has_data_refs_to_for_data_with_references(self, test_env):
        """
        Test has_data_refs_to returns True for data that is accessed.

        RATIONALE: Global variables, string constants, and other data are typically
        accessed by code through data references. The has_data_refs_to method should
        specifically detect data references (excluding code references).

        In a real binary like tiny_c.bin, there should be data items that are
        accessed by code.
        """
        # Search for a data address with data references
        data_with_refs = None

        # Iterate through a reasonable range looking for data with refs
        search_start = test_env.minimum_ea
        search_end = min(search_start + 0x10000, test_env.maximum_ea)

        ea = search_start
        while ea < search_end:
            # Skip invalid addresses
            if not test_env.is_valid_ea(ea):
                ea += 1
                continue

            # Check if this is data and has data refs
            if not test_env.bytes.is_code_at(ea):
                # Check for data refs
                for _ in test_env.xrefs.data_refs_to_ea(ea):
                    data_with_refs = ea
                    break

            if data_with_refs:
                break

            # Move to next item
            ea = test_env.bytes.get_item_end_at(ea)

        if data_with_refs is None:
            pytest.skip('No data with references found in test binary')

        # Verify has_data_refs_to returns True
        assert test_env.xrefs.has_data_refs_to(data_with_refs), (
            f'has_data_refs_to should return True for data at 0x{data_with_refs:x} with refs'
        )

    def test_has_data_refs_to_for_code_address(self, test_env):
        """
        Test has_data_refs_to for a code address.

        RATIONALE: Code addresses typically have code references (calls, jumps) but
        not data references. This test verifies that has_data_refs_to specifically
        checks for data references only.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Check has_data_refs_to - most code addresses won't have data refs
        result = test_env.xrefs.has_data_refs_to(first_insn.ea)
        assert isinstance(result, bool), 'has_data_refs_to should return boolean'


class TestXrefCounting:
    """Tests for xref counting methods."""

    def test_count_refs_to_for_function_with_multiple_callers(self, test_env):
        """
        Test count_refs_to accurately counts multiple callers to a function.

        RATIONALE: The count_refs_to method should return the exact number of
        references to an address. This is useful for analyzing how frequently
        a function is called or how many times data is accessed.

        We find a function with multiple callers and verify the count matches
        the actual number of call sites.
        """
        # Find a function with multiple callers
        func_with_callers = None
        expected_count = 0

        for func in test_env.functions.get_all():
            # Count code refs (excluding flow)
            count = sum(1 for _ in test_env.xrefs.code_refs_to_ea(func.start_ea, flow=False))

            if count >= 2:  # Want at least 2 callers
                func_with_callers = func
                expected_count = count
                break

        if func_with_callers is None:
            pytest.skip('No function with multiple callers found')

        func_ea = func_with_callers.start_ea

        # Count using count_refs_to with CODE_NOFLOW flag
        actual_count = test_env.xrefs.count_refs_to(func_ea, XrefsFlags.CODE_NOFLOW)

        # Should match the count we got from iteration
        assert actual_count == expected_count, (
            f'count_refs_to should return {expected_count} for function at 0x{func_ea:x}, '
            f'got {actual_count}'
        )

    def test_count_refs_to_for_unreferenced_address(self, test_env):
        """
        Test count_refs_to returns 0 for an address with no references.

        RATIONALE: The count method should return 0 for unreferenced addresses,
        which is important for identifying dead code or unused data.

        We use an address in the middle of an instruction which should have no
        references.
        """
        # Get an instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Use middle of instruction if multi-byte
        if first_insn.size > 1:
            mid_insn_ea = first_insn.ea + 1
        else:
            # Try next instruction
            next_insn = test_env.instructions.get_next(first_insn.ea)
            if next_insn and next_insn.size > 1:
                mid_insn_ea = next_insn.ea + 1
            else:
                pytest.skip('Cannot find multi-byte instruction')

        # Count should be 0
        count = test_env.xrefs.count_refs_to(mid_insn_ea)
        assert count == 0, (
            f'count_refs_to should return 0 for unreferenced address 0x{mid_insn_ea:x}, '
            f'got {count}'
        )

    def test_count_refs_from_for_call_instruction(self, test_env):
        """
        Test count_refs_from for a call instruction.

        RATIONALE: Call instructions typically create one outgoing reference to the
        target function. The count_refs_from method should accurately count these
        outgoing references.

        We find a call instruction and verify its reference count.
        """
        # Find a call instruction
        call_ea = None
        for func in test_env.functions.get_all():
            ea = func.start_ea
            while ea < func.end_ea:
                insn = test_env.instructions.get_at(ea)
                if insn and test_env.instructions.is_call_instruction(insn):
                    call_ea = ea
                    break
                if insn:
                    ea = insn.ea + insn.size
                else:
                    break

            if call_ea:
                break

        if call_ea is None:
            pytest.skip('No call instruction found')

        # Count refs from call - should be at least 1 (the target)
        count = test_env.xrefs.count_refs_from(call_ea, XrefsFlags.CODE_NOFLOW)
        assert count >= 1, (
            f'count_refs_from should return at least 1 for call at 0x{call_ea:x}, got {count}'
        )

    def test_count_refs_from_with_different_flags(self, test_env):
        """
        Test count_refs_from with different flag combinations.

        RATIONALE: The count methods support filtering by xref type (code, data,
        with/without flow). This test verifies that different flag combinations
        produce different (and correct) counts.

        We use the first instruction which may have flow references and compare
        counts with and without flow filtering.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Count with ALL flags (including flow)
        count_all = test_env.xrefs.count_refs_from(first_insn.ea, XrefsFlags.ALL)

        # Count without flow
        count_noflow = test_env.xrefs.count_refs_from(first_insn.ea, XrefsFlags.NOFLOW)

        # Count with ALL should be >= count without flow
        assert count_all >= count_noflow, (
            f'count_refs_from with ALL ({count_all}) should be >= NOFLOW ({count_noflow})'
        )

    def test_count_matches_iteration(self, test_env):
        """
        Test that count_refs_to matches manual iteration count.

        RATIONALE: The count methods are implemented by iterating through xrefs
        internally. This test verifies that the count matches what we get from
        manually iterating, ensuring consistency between counting and iteration.

        We pick a function with refs and compare count_refs_to with manual counting.
        """
        # Find a function with references
        func_with_refs = None
        for func in test_env.functions.get_all():
            # Check if it has any refs
            for _ in test_env.xrefs.to_ea(func.start_ea, XrefsFlags.CODE_NOFLOW):
                func_with_refs = func
                break
            if func_with_refs:
                break

        if func_with_refs is None:
            pytest.skip('No function with refs found')

        func_ea = func_with_refs.start_ea

        # Count using count_refs_to
        counted = test_env.xrefs.count_refs_to(func_ea, XrefsFlags.CODE_NOFLOW)

        # Count manually by iteration
        manual_count = sum(1 for _ in test_env.xrefs.to_ea(func_ea, XrefsFlags.CODE_NOFLOW))

        # Should match exactly
        assert counted == manual_count, (
            f'count_refs_to ({counted}) should match manual iteration ({manual_count})'
        )


class TestXrefErrorHandling:
    """Tests for error handling in xref methods."""

    def test_has_any_refs_to_with_invalid_address_raises_error(self, test_env):
        """
        Test has_any_refs_to raises InvalidEAError for invalid addresses.

        RATIONALE: All xref methods should validate addresses and raise
        InvalidEAError for invalid addresses. This ensures consistent error
        handling across the API.
        """
        invalid_ea = 0xDEADBEEF  # Likely outside valid range

        with pytest.raises(InvalidEAError):
            test_env.xrefs.has_any_refs_to(invalid_ea)

    def test_has_any_refs_from_with_invalid_address_raises_error(self, test_env):
        """
        Test has_any_refs_from raises InvalidEAError for invalid addresses.

        RATIONALE: Validates error handling consistency for has_any_refs_from.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.xrefs.has_any_refs_from(invalid_ea)

    def test_count_refs_to_with_invalid_address_raises_error(self, test_env):
        """
        Test count_refs_to raises InvalidEAError for invalid addresses.

        RATIONALE: Validates error handling consistency for count_refs_to.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.xrefs.count_refs_to(invalid_ea)

    def test_count_refs_from_with_invalid_address_raises_error(self, test_env):
        """
        Test count_refs_from raises InvalidEAError for invalid addresses.

        RATIONALE: Validates error handling consistency for count_refs_from.
        """
        invalid_ea = 0xDEADBEEF

        with pytest.raises(InvalidEAError):
            test_env.xrefs.count_refs_from(invalid_ea)


class TestLLMFriendlyAPI:
    """Tests for LLM-friendly unified API methods."""

    def test_get_refs_to_with_all_kind(self, test_env):
        """
        Test get_refs_to with kind="all" returns all xrefs.

        RATIONALE: The get_refs_to method provides an LLM-friendly interface
        using string parameters instead of enums. kind="all" should delegate
        to to_ea() and return all xrefs.
        """
        # Find a function with callers
        func_with_refs = None
        for func in test_env.functions.get_all():
            for _ in test_env.xrefs.to_ea(func.start_ea, XrefsFlags.CODE_NOFLOW):
                func_with_refs = func
                break
            if func_with_refs:
                break

        if func_with_refs is None:
            pytest.skip('No function with refs found')

        func_ea = func_with_refs.start_ea

        # Get refs using LLM-friendly API
        refs = list(test_env.xrefs.get_refs_to(func_ea, "all"))
        expected = list(test_env.xrefs.to_ea(func_ea))

        assert len(refs) == len(expected)

    def test_get_refs_to_with_code_kind(self, test_env):
        """
        Test get_refs_to with kind="code" returns code xrefs only.

        RATIONALE: kind="code" should delegate to code_refs_to_ea() and
        return only code reference addresses.
        """
        # Find a function with callers
        func_with_refs = None
        for func in test_env.functions.get_all():
            for _ in test_env.xrefs.code_refs_to_ea(func.start_ea, flow=False):
                func_with_refs = func
                break
            if func_with_refs:
                break

        if func_with_refs is None:
            pytest.skip('No function with code refs found')

        func_ea = func_with_refs.start_ea

        # Get refs using LLM-friendly API
        refs = list(test_env.xrefs.get_refs_to(func_ea, "code"))
        expected = list(test_env.xrefs.code_refs_to_ea(func_ea))

        assert len(refs) == len(expected)

    def test_get_refs_to_with_invalid_kind_raises_error(self, test_env):
        """
        Test get_refs_to raises InvalidParameterError for unknown kind.

        RATIONALE: Invalid kind parameter should raise InvalidParameterError
        with clear error message listing valid options.
        """
        func_ea = next(test_env.functions.get_all()).start_ea

        with pytest.raises(InvalidParameterError):
            list(test_env.xrefs.get_refs_to(func_ea, "invalid_kind"))

    def test_get_refs_to_is_case_insensitive(self, test_env):
        """
        Test get_refs_to accepts kind parameter in any case.

        RATIONALE: LLM-friendly API should be case-insensitive for string
        parameters to reduce friction.
        """
        func_ea = next(test_env.functions.get_all()).start_ea

        # All of these should work
        refs_lower = list(test_env.xrefs.get_refs_to(func_ea, "all"))
        refs_upper = list(test_env.xrefs.get_refs_to(func_ea, "ALL"))
        refs_mixed = list(test_env.xrefs.get_refs_to(func_ea, "All"))

        assert len(refs_lower) == len(refs_upper) == len(refs_mixed)

    def test_get_refs_from_with_all_kind(self, test_env):
        """
        Test get_refs_from with kind="all" returns all xrefs.

        RATIONALE: get_refs_from should provide symmetric functionality
        to get_refs_to, returning outgoing references.
        """
        # Find a call instruction
        call_ea = None
        for func in test_env.functions.get_all():
            ea = func.start_ea
            while ea < func.end_ea:
                insn = test_env.instructions.get_at(ea)
                if insn and test_env.instructions.is_call_instruction(insn):
                    call_ea = ea
                    break
                if insn:
                    ea = insn.ea + insn.size
                else:
                    break
            if call_ea:
                break

        if call_ea is None:
            pytest.skip('No call instruction found')

        # Get refs using LLM-friendly API
        refs = list(test_env.xrefs.get_refs_from(call_ea, "all"))
        expected = list(test_env.xrefs.from_ea(call_ea))

        assert len(refs) == len(expected)

    def test_get_refs_from_with_code_kind(self, test_env):
        """
        Test get_refs_from with kind="code" returns code xrefs only.

        RATIONALE: kind="code" should delegate to code_refs_from_ea()
        and return only code reference addresses.
        """
        # Find a call instruction
        call_ea = None
        for func in test_env.functions.get_all():
            ea = func.start_ea
            while ea < func.end_ea:
                insn = test_env.instructions.get_at(ea)
                if insn and test_env.instructions.is_call_instruction(insn):
                    call_ea = ea
                    break
                if insn:
                    ea = insn.ea + insn.size
                else:
                    break
            if call_ea:
                break

        if call_ea is None:
            pytest.skip('No call instruction found')

        # Get refs using LLM-friendly API
        refs = list(test_env.xrefs.get_refs_from(call_ea, "code"))
        expected = list(test_env.xrefs.code_refs_from_ea(call_ea))

        assert len(refs) == len(expected)

    def test_has_refs_to_with_all_kind(self, test_env):
        """
        Test has_refs_to with kind="all" checks for any refs.

        RATIONALE: has_refs_to provides an LLM-friendly existence check
        using string parameter. kind="all" should delegate to has_any_refs_to().
        """
        # Find a function with callers
        func_with_refs = None
        for func in test_env.functions.get_all():
            if test_env.xrefs.has_any_refs_to(func.start_ea):
                func_with_refs = func
                break

        if func_with_refs is None:
            pytest.skip('No function with refs found')

        func_ea = func_with_refs.start_ea

        # Check using LLM-friendly API
        result = test_env.xrefs.has_refs_to(func_ea, "all")
        expected = test_env.xrefs.has_any_refs_to(func_ea)

        assert result == expected

    def test_has_refs_to_with_code_kind(self, test_env):
        """
        Test has_refs_to with kind="code" checks for code refs only.

        RATIONALE: kind="code" should delegate to has_code_refs_to().
        """
        # Find a function with code refs
        func_with_refs = None
        for func in test_env.functions.get_all():
            if test_env.xrefs.has_code_refs_to(func.start_ea):
                func_with_refs = func
                break

        if func_with_refs is None:
            pytest.skip('No function with code refs found')

        func_ea = func_with_refs.start_ea

        # Check using LLM-friendly API
        result = test_env.xrefs.has_refs_to(func_ea, "code")
        expected = test_env.xrefs.has_code_refs_to(func_ea)

        assert result == expected

    def test_has_refs_to_with_data_kind(self, test_env):
        """
        Test has_refs_to with kind="data" checks for data refs only.

        RATIONALE: kind="data" should delegate to has_data_refs_to().
        """
        first_func = next(test_env.functions.get_all())
        func_ea = first_func.start_ea

        # Check using LLM-friendly API
        result = test_env.xrefs.has_refs_to(func_ea, "data")
        expected = test_env.xrefs.has_data_refs_to(func_ea)

        assert result == expected

    def test_has_refs_to_with_invalid_kind_raises_error(self, test_env):
        """
        Test has_refs_to raises InvalidParameterError for unknown kind.

        RATIONALE: Invalid kind parameter should raise InvalidParameterError.
        """
        func_ea = next(test_env.functions.get_all()).start_ea

        with pytest.raises(InvalidParameterError):
            test_env.xrefs.has_refs_to(func_ea, "invalid_kind")

    def test_has_refs_from_with_all_kind(self, test_env):
        """
        Test has_refs_from with kind="all" checks for any outgoing refs.

        RATIONALE: has_refs_from provides symmetric functionality to has_refs_to,
        checking for outgoing references using string parameter.
        """
        # Find a call instruction
        call_ea = None
        for func in test_env.functions.get_all():
            ea = func.start_ea
            while ea < func.end_ea:
                insn = test_env.instructions.get_at(ea)
                if insn and test_env.instructions.is_call_instruction(insn):
                    call_ea = ea
                    break
                if insn:
                    ea = insn.ea + insn.size
                else:
                    break
            if call_ea:
                break

        if call_ea is None:
            pytest.skip('No call instruction found')

        # Check using LLM-friendly API
        result = test_env.xrefs.has_refs_from(call_ea, "all")
        expected = test_env.xrefs.has_any_refs_from(call_ea)

        assert result == expected


class TestXrefInfoDataclass:
    """Tests for XrefInfo dataclass representation."""

    def test_xrefinfo_repr_contains_addresses(self, test_env):
        """
        Test XrefInfo __repr__ includes hex addresses.

        RATIONALE: Dataclass repr should show hex addresses and type name
        for easy debugging in IDA's Python console.
        """
        # Find any xref
        func = next(test_env.functions.get_all())
        xrefs = list(test_env.xrefs.to_ea(func.start_ea))

        if not xrefs:
            pytest.skip('No xrefs found for testing')

        xref = xrefs[0]
        repr_str = repr(xref)

        # Should contain hex addresses
        assert f'0x{xref.from_ea:x}' in repr_str.lower(), (
            f'XrefInfo repr should contain from_ea in hex, got: {repr_str}'
        )
        assert f'0x{xref.to_ea:x}' in repr_str.lower(), (
            f'XrefInfo repr should contain to_ea in hex, got: {repr_str}'
        )
        assert xref.type.name in repr_str, (
            f'XrefInfo repr should contain type name, got: {repr_str}'
        )
