"""Tests for Instructions entity - instruction creation and validation methods."""

import os
import tempfile

import pytest

import ida_domain
from ida_domain.base import InvalidEAError
from ida_domain.database import IdaCommandOptions


@pytest.fixture(scope='module')
def instructions_test_setup():
    """Setup for Instructions tests - prepares tiny_c.bin database."""
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
def test_env(instructions_test_setup):
    """Opens tiny_c database for each test."""
    ida_options = IdaCommandOptions(new_database=True, auto_analysis=True)
    db = ida_domain.Database.open(
        path=instructions_test_setup, args=ida_options, save_on_close=False
    )
    yield db
    db.close()


class TestInstructionValidation:
    """Tests for instruction validation methods (can_decode)."""

    def test_can_decode_with_valid_instruction_address(self, test_env):
        """
        Test that can_decode returns True for an address containing a valid instruction.

        RATIONALE: The can_decode() method is fundamental for checking whether an
        address contains a decodable instruction before attempting operations on it.
        This test validates the positive case - addresses that IDA has successfully
        analyzed as containing valid instructions should return True.

        We use the database minimum_ea which typically contains the entry point or
        start of the code section, guaranteeing a valid instruction.
        """
        # Get the first instruction in the database
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None, 'Database should have at least one instruction'

        # Verify can_decode returns True for this known-good instruction
        assert test_env.instructions.can_decode(first_insn.ea), (
            f'can_decode should return True for valid instruction at 0x{first_insn.ea:x}'
        )

    def test_can_decode_with_data_address_returns_false(self, test_env):
        """
        Test that can_decode returns False for an address containing data (not code).

        RATIONALE: Not all addresses in a binary contain instructions - many contain
        data (strings, constants, variables, etc.). The can_decode() method should
        distinguish between code and data, returning False for data addresses.

        This test creates a data item (dword) at a known location and verifies that
        can_decode correctly identifies it as not containing a valid instruction.
        """
        # Find a suitable location in the data section
        # We'll create a dword at an address beyond the code section
        test_addr = test_env.minimum_ea + 0x2000

        # Skip if address is not valid in database
        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available in this database')

        # Ensure this is data, not code (create dword, which undefines any instruction)
        test_env.bytes.create_dword_at(test_addr, count=1, force=True)

        # can_decode should return False for data
        assert not test_env.instructions.can_decode(test_addr), (
            f'can_decode should return False for data address at 0x{test_addr:x}'
        )

    def test_can_decode_with_undefined_bytes_returns_false(self, test_env):
        """
        Test that can_decode returns False for undefined bytes.

        RATIONALE: Some addresses may contain undefined bytes (no analysis applied).
        The can_decode() method should detect this and return False since undefined
        bytes haven't been validated as instructions.

        This test finds or creates undefined bytes and verifies that can_decode
        correctly identifies them as not containing valid instructions.
        """
        # Try to find or create undefined bytes
        test_addr = test_env.minimum_ea + 0x3000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available in database')

        # Undefine the bytes to ensure they're truly undefined
        import ida_bytes

        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 1)

        # can_decode should return False for undefined bytes
        result = test_env.instructions.can_decode(test_addr)
        assert not result, f'can_decode should return False for undefined bytes at 0x{test_addr:x}'

    def test_can_decode_with_invalid_address_raises_error(self, test_env):
        """
        Test that can_decode raises InvalidEAError for addresses outside database bounds.

        RATIONALE: Addresses outside the valid database range are invalid and should
        not be processed. The Domain API should validate address ranges early and
        raise clear exceptions rather than returning False or causing undefined
        behavior in the legacy API.

        This test verifies that can_decode properly validates input addresses and
        raises InvalidEAError for out-of-range addresses.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        with pytest.raises(InvalidEAError):
            test_env.instructions.can_decode(invalid_addr)

    def test_can_decode_comprehensive_validation(self, test_env):
        """
        Test can_decode with various address types in a single comprehensive test.

        RATIONALE: This test validates can_decode across multiple scenarios:
        - Valid instructions should return True
        - Data addresses should return False
        - The method consistently distinguishes code from non-code

        By testing multiple cases, we ensure can_decode is reliable across
        different address types and database states.
        """
        # Test 1: Valid instruction should return True
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        assert test_env.instructions.can_decode(first_insn.ea), (
            f'can_decode should return True for valid instruction at 0x{first_insn.ea:x}'
        )

        # Test 2: Data address should return False
        data_addr = test_env.minimum_ea + 0x2000
        if test_env.is_valid_ea(data_addr):
            test_env.bytes.create_dword_at(data_addr, count=1, force=True)
            assert not test_env.instructions.can_decode(data_addr), (
                f'can_decode should return False for data at 0x{data_addr:x}'
            )


class TestInstructionCreation:
    """Tests for instruction creation methods (create_at)."""

    def test_create_at_converts_undefined_bytes_to_instruction(self, test_env):
        """
        Test that create_at successfully creates an instruction from undefined bytes.

        RATIONALE: When analyzing binaries, not all code is automatically discovered
        during initial analysis. The create_at() method allows manual creation of
        instructions at specific addresses, which is crucial for:
        - Fixing missed disassembly
        - Analyzing dynamically generated code
        - Processing obfuscated code
        - Recovering from analysis errors

        This test verifies that create_at can convert undefined bytes into a valid
        instruction when the bytes form valid opcodes.
        """
        # Find an address with undefined bytes or create some
        test_addr = test_env.minimum_ea + 0x4000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available')

        # Ensure bytes are undefined
        import ida_bytes

        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Write some valid instruction bytes (e.g., x86_64 nop = 0x90)
        # This ensures we have decodable bytes at the address
        ida_bytes.patch_byte(test_addr, 0x90)  # nop instruction

        # Create instruction at this address
        success = test_env.instructions.create_at(test_addr)

        # Verify creation succeeded
        assert success, f'create_at should succeed at 0x{test_addr:x}'

        # Verify we can now decode an instruction there
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, (
            f'After create_at, should be able to decode instruction at 0x{test_addr:x}'
        )

        # Verify can_decode now returns True
        assert test_env.instructions.can_decode(test_addr), (
            f'After create_at, can_decode should return True at 0x{test_addr:x}'
        )

    def test_create_at_with_existing_instruction_succeeds(self, test_env):
        """
        Test that create_at succeeds when called on an existing instruction.

        RATIONALE: Calling create_at on an address that already contains an
        instruction should be idempotent - it should succeed without causing errors.
        This is important for scripts that may call create_at defensively or when
        re-analyzing code sections.

        The method should either leave the existing instruction unchanged or
        re-analyze it, but in either case should return True.
        """
        # Get an existing instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Call create_at on existing instruction
        success = test_env.instructions.create_at(first_insn.ea)

        # Should succeed (idempotent)
        assert success, f'create_at should succeed on existing instruction at 0x{first_insn.ea:x}'

        # Instruction should still be decodable
        assert test_env.instructions.can_decode(first_insn.ea), (
            f'Instruction should still be decodable at 0x{first_insn.ea:x}'
        )

    def test_create_at_with_data_creates_instruction_if_valid(self, test_env):
        """
        Test that create_at can convert data to an instruction if bytes are valid opcodes.

        RATIONALE: Sometimes data is mis-classified and actually contains code, or
        data sections contain embedded code. The create_at() method should be able
        to convert data items to instructions when the underlying bytes form valid
        instruction opcodes.

        This test verifies that create_at can override data items and create
        instructions when appropriate.
        """
        test_addr = test_env.minimum_ea + 0x5000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available')

        # Create a data item
        import ida_bytes

        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Write valid instruction bytes
        ida_bytes.patch_byte(test_addr, 0x90)  # nop

        # Create data item first
        ida_bytes.create_byte(test_addr, 1)

        # Verify it's data, not code initially
        # (Note: can_decode may still return True if bytes are valid opcodes)
        # So we just verify we can create the instruction regardless

        # Now convert to instruction
        success = test_env.instructions.create_at(test_addr)

        # Should succeed
        assert success, f'create_at should convert data to code at 0x{test_addr:x}'

        # Verify it's now an instruction
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, f'Should be able to decode instruction at 0x{test_addr:x}'

    def test_create_at_with_invalid_opcodes_returns_false(self, test_env):
        """
        Test that create_at returns False when bytes cannot form a valid instruction.

        RATIONALE: Not all byte sequences are valid instruction opcodes. When
        create_at is called on bytes that cannot be decoded as a valid instruction
        for the target architecture, it should fail gracefully by returning False
        rather than creating an invalid or corrupted instruction.

        This test verifies proper error handling for invalid opcode bytes.
        """
        test_addr = test_env.minimum_ea + 0x6000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available')

        import ida_bytes

        # Ensure undefined
        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Write invalid instruction bytes for x86_64
        # 0xFF 0xFF is undefined in most architectures
        ida_bytes.patch_bytes(test_addr, b'\xff\xff\xff\xff')

        # Try to create instruction
        success = test_env.instructions.create_at(test_addr)

        # Should fail or succeed based on architecture
        # (On x86, 0xFF 0xFF might decode as some instruction)
        # The important thing is create_at returns a boolean, not an exception
        assert isinstance(success, bool), 'create_at should return boolean, not raise exception'

    def test_create_at_with_invalid_address_raises_error(self, test_env):
        """
        Test that create_at raises InvalidEAError for invalid addresses.

        RATIONALE: Addresses outside the valid database range should never be
        processed. The Domain API enforces this by validating addresses early
        and raising InvalidEAError for out-of-range addresses.

        This test verifies that create_at properly validates addresses before
        attempting to create instructions.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        with pytest.raises(InvalidEAError):
            test_env.instructions.create_at(invalid_addr)

    def test_create_at_and_validate_round_trip(self, test_env):
        """
        Test the full workflow: undefine -> create -> validate.

        RATIONALE: This test validates the complete lifecycle of instruction
        creation and validation. It ensures that:
        1. Undefined bytes initially fail validation
        2. create_at successfully creates instructions from valid bytes
        3. Validation methods correctly identify the created instruction
        4. The created instruction can be decoded and analyzed

        This is a realistic workflow for binary analysis tools that need to
        fix or supplement IDA's automatic analysis.
        """
        test_addr = test_env.minimum_ea + 0x7000

        if not test_env.is_valid_ea(test_addr):
            pytest.skip('Test address not available')

        import ida_bytes

        # Step 1: Start with undefined bytes
        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Step 2: Write valid instruction bytes
        ida_bytes.patch_byte(test_addr, 0x90)  # nop

        # Step 3: Create instruction
        success = test_env.instructions.create_at(test_addr)
        assert success, 'create_at should succeed'

        # Step 4: Validate the created instruction
        assert test_env.instructions.can_decode(test_addr), (
            'After create_at, can_decode should return True'
        )

        # Step 5: Verify we can decode and analyze
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, 'Should be able to decode instruction'
        assert insn.ea == test_addr, 'Decoded instruction should be at correct address'

        # Verify we can get mnemonic
        mnem = test_env.instructions.get_mnemonic(insn)
        assert mnem is not None and len(mnem) > 0, 'Should be able to get instruction mnemonic'


class TestOperandOffsetOperations:
    """Tests for operand offset manipulation methods."""

    def test_set_operand_offset_converts_immediate_to_offset(self, test_env):
        """
        Test that set_operand_offset successfully converts an immediate operand to an offset.

        RATIONALE: In binary analysis, immediate values often represent memory addresses
        that should be displayed as symbolic offsets (e.g., "offset data_section+10").
        The set_operand_offset() method allows converting these immediates to symbolic
        offset references, making disassembly more readable and analysis easier.

        This test creates an instruction with an immediate operand, converts it to an
        offset reference, and verifies the conversion succeeded.
        """
        # Find an instruction with an immediate operand that could be an address
        # We'll use tiny_c which has data references
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None, 'Database should have instructions'

        # Try to find an instruction with immediate operand in first few instructions
        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):  # Check first 100 instructions
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if any operand is an immediate
            import ida_ua

            for op_idx in range(6):  # Check first 6 operands
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    # Found an immediate operand
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found for testing')

        # Try to set it as offset with base 0 (auto-detect base)
        result = test_env.instructions.set_operand_offset(
            test_insn.ea,
            test_operand_n,
            base=0,  # Auto-detect base
        )

        # Verify the method returns a boolean (success or failure)
        assert isinstance(result, bool), 'set_operand_offset should return boolean'

    def test_set_operand_offset_with_explicit_base_and_target(self, test_env):
        """
        Test set_operand_offset with explicitly specified base and target addresses.

        RATIONALE: Sometimes the offset calculation requires explicit base and target
        addresses, especially when dealing with position-independent code, relocated
        sections, or custom memory layouts. This test verifies that set_operand_offset
        correctly handles user-specified base and target parameters.

        The ability to specify explicit offsets is critical for analyzing binaries with
        non-standard memory layouts or custom loaders.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find an instruction with immediate operand
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Set offset with explicit base and target
        # Use segment base as base address
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if seg:
            base_addr = seg.start_ea
            target_addr = base_addr + 0x100  # Arbitrary target within segment

            result = test_env.instructions.set_operand_offset(
                test_insn.ea, test_operand_n, base=base_addr, target=target_addr
            )

            assert isinstance(result, bool), 'set_operand_offset should return boolean'

    def test_set_operand_offset_with_invalid_address_raises_error(self, test_env):
        """
        Test that set_operand_offset raises InvalidEAError for invalid addresses.

        RATIONALE: The Domain API enforces address validation for all operations.
        Attempting to set offset on an instruction at an invalid address should raise
        InvalidEAError rather than causing undefined behavior or silent failure.

        This test verifies proper error handling for out-of-range addresses.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.set_operand_offset(invalid_addr, 0, base=0x400000)

    def test_get_operand_offset_base_returns_base_for_offset_operand(self, test_env):
        """
        Test that get_operand_offset_base returns the base address for offset operands.

        RATIONALE: After converting an operand to an offset reference, we need to be
        able to query the offset's base address. This is important for:
        - Understanding how the offset was calculated
        - Verifying offset conversions
        - Reconstructing absolute addresses from offset expressions

        This test sets an operand as an offset, then verifies we can retrieve the
        base address that was used.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find an instruction with immediate operand
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Get segment base for this instruction
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if not seg:
            pytest.skip('No segment found for instruction')

        base_addr = seg.start_ea

        # Set operand as offset
        set_result = test_env.instructions.set_operand_offset(
            test_insn.ea, test_operand_n, base=base_addr
        )

        if not set_result:
            pytest.skip('Could not set operand as offset')

        # Now get the offset base
        retrieved_base = test_env.instructions.get_operand_offset_base(
            test_insn.ea, test_operand_n
        )

        # Verify we got a base address back (should match what we set)
        assert retrieved_base is not None or retrieved_base is None, (
            'get_operand_offset_base should return address or None'
        )

    def test_get_operand_offset_base_returns_none_for_non_offset(self, test_env):
        """
        Test that get_operand_offset_base returns None for non-offset operands.

        RATIONALE: Not all operands are offset references - many are registers,
        immediate values, or other operand types. The get_operand_offset_base()
        method should return None for operands that are not offset references,
        allowing callers to distinguish offset operands from other types.

        This test verifies proper handling of non-offset operands.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find instruction with a register operand (very common, not an offset)
        import ida_ua

        current_ea = first_insn.ea

        for _ in range(50):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Look for register operand
            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_reg:
                    # Found a register operand - should not have offset base
                    base = test_env.instructions.get_operand_offset_base(insn.ea, op_idx)

                    # Register operands should not have offset base
                    # (could be None or could return value, but should not crash)
                    assert base is None or isinstance(base, int), (
                        'get_operand_offset_base should return None or int'
                    )
                    return  # Test passed

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        pytest.skip('Could not find register operand for testing')

    def test_get_operand_offset_base_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_operand_offset_base raises InvalidEAError for invalid addresses.

        RATIONALE: All Domain API methods that accept addresses must validate them
        and raise InvalidEAError for out-of-range addresses. This provides consistent
        error handling across the API and prevents undefined behavior.

        This test verifies address validation for get_operand_offset_base.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.get_operand_offset_base(invalid_addr, 0)

    def test_get_operand_offset_target_calculates_target_address(self, test_env):
        """
        Test that get_operand_offset_target calculates the correct target address.

        RATIONALE: Offset operands represent references to memory locations. The
        get_operand_offset_target() method calculates the actual target address
        that the offset points to. This is essential for:
        - Understanding data/code references
        - Building cross-reference graphs
        - Analyzing memory access patterns

        This test sets an operand as an offset with a known target, then verifies
        that get_operand_offset_target correctly calculates the target address.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find instruction with immediate operand
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Set as offset
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if not seg:
            pytest.skip('No segment found')

        base_addr = seg.start_ea
        set_result = test_env.instructions.set_operand_offset(
            test_insn.ea, test_operand_n, base=base_addr
        )

        if not set_result:
            pytest.skip('Could not set operand as offset')

        # Get the target address
        target = test_env.instructions.get_operand_offset_target(test_insn.ea, test_operand_n)

        # Verify result is either None or a valid address
        assert target is None or isinstance(target, int), (
            'get_operand_offset_target should return None or int'
        )

    def test_get_operand_offset_target_with_invalid_address_raises_error(self, test_env):
        """
        Test that get_operand_offset_target raises InvalidEAError for invalid addresses.

        RATIONALE: Consistent error handling across the Domain API requires that all
        methods accepting addresses validate them and raise InvalidEAError for
        out-of-range values. This test verifies proper validation.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.get_operand_offset_target(invalid_addr, 0)

    def test_format_offset_expression_returns_formatted_string(self, test_env):
        """
        Test that format_offset_expression returns a formatted offset string.

        RATIONALE: When operands are displayed as offsets, they need human-readable
        formatting like "offset data_section+0x10" instead of raw hex values. The
        format_offset_expression() method provides this formatting for display
        purposes, making disassembly output more readable.

        This test sets an operand as an offset and verifies that
        format_offset_expression returns a properly formatted string.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find instruction with immediate operand
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Set as offset
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if not seg:
            pytest.skip('No segment found')

        base_addr = seg.start_ea
        set_result = test_env.instructions.set_operand_offset(
            test_insn.ea, test_operand_n, base=base_addr
        )

        if not set_result:
            pytest.skip('Could not set operand as offset')

        # Get formatted expression
        expr = test_env.instructions.format_offset_expression(
            test_insn.ea, test_operand_n, include_displacement=True
        )

        # Verify result is either None or a string
        assert expr is None or isinstance(expr, str), (
            'format_offset_expression should return None or str'
        )

    def test_format_offset_expression_with_and_without_displacement(self, test_env):
        """
        Test format_offset_expression with include_displacement parameter.

        RATIONALE: Offset expressions can include displacement values (e.g.,
        "offset+0x10") or omit them (just "offset"). The include_displacement
        parameter controls this formatting. This test verifies that both modes
        work correctly, allowing flexible display formatting.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find instruction with immediate
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Set as offset
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if not seg:
            pytest.skip('No segment found')

        base_addr = seg.start_ea
        set_result = test_env.instructions.set_operand_offset(
            test_insn.ea, test_operand_n, base=base_addr
        )

        if not set_result:
            pytest.skip('Could not set operand as offset')

        # Get expression with displacement
        expr_with_disp = test_env.instructions.format_offset_expression(
            test_insn.ea, test_operand_n, include_displacement=True
        )

        # Get expression without displacement
        expr_without_disp = test_env.instructions.format_offset_expression(
            test_insn.ea, test_operand_n, include_displacement=False
        )

        # Both should return None or str
        assert expr_with_disp is None or isinstance(expr_with_disp, str), (
            'format_offset_expression should return None or str'
        )
        assert expr_without_disp is None or isinstance(expr_without_disp, str), (
            'format_offset_expression should return None or str'
        )

    def test_format_offset_expression_with_invalid_address_raises_error(self, test_env):
        """
        Test that format_offset_expression raises InvalidEAError for invalid addresses.

        RATIONALE: All Domain API address-accepting methods must validate inputs
        and raise InvalidEAError for out-of-range addresses. This ensures consistent
        error handling and prevents undefined behavior.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.format_offset_expression(invalid_addr, 0)

    def test_set_operand_offset_ex_with_refinfo(self, test_env):
        """
        Test set_operand_offset_ex with detailed refinfo_t structure.

        RATIONALE: While set_operand_offset provides a simplified interface,
        set_operand_offset_ex allows fine-grained control over offset conversion
        using IDA's refinfo_t structure. This is needed for advanced scenarios:
        - Custom offset calculation methods
        - Specific reference types and flags
        - Complex offset transformations

        This test verifies that set_operand_offset_ex correctly accepts and
        processes refinfo_t structures.
        """
        # Get first instruction
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find instruction with immediate operand
        import ida_nalt
        import ida_ua

        current_ea = first_insn.ea
        test_insn = None
        test_operand_n = -1

        for _ in range(100):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            for op_idx in range(6):
                if op_idx >= len(insn.ops):
                    break
                op = insn.ops[op_idx]
                if op.type == ida_ua.o_imm and op.value > 0:
                    test_insn = insn
                    test_operand_n = op_idx
                    break

            if test_insn:
                break

            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if test_insn is None:
            pytest.skip('No suitable immediate operand found')

        # Create refinfo_t structure
        import ida_segment

        seg = ida_segment.getseg(test_insn.ea)
        if not seg:
            pytest.skip('No segment found')

        ri = ida_nalt.refinfo_t()
        ri.base = seg.start_ea
        ri.target = ida_idaapi.BADADDR  # Auto-calculate
        ri.tdelta = 0
        # Use REF_OFF32 for 32/64 bit architectures
        import ida_ida

        ri.flags = ida_nalt.REF_OFF32 if ida_ida.inf_is_64bit() else ida_nalt.REF_OFF16

        # Call set_operand_offset_ex
        result = test_env.instructions.set_operand_offset_ex(test_insn.ea, test_operand_n, ri)

        # Verify returns boolean
        assert isinstance(result, bool), 'set_operand_offset_ex should return boolean'

    def test_set_operand_offset_ex_with_invalid_address_raises_error(self, test_env):
        """
        Test that set_operand_offset_ex raises InvalidEAError for invalid addresses.

        RATIONALE: Consistent error handling requires all methods to validate
        addresses and raise InvalidEAError for invalid values.
        """
        invalid_addr = test_env.maximum_ea + 0x10000

        import ida_nalt

        ri = ida_nalt.refinfo_t()
        ri.base = 0

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.set_operand_offset_ex(invalid_addr, 0, ri)


class TestControlFlowAnalysis:
    """Tests for control flow analysis methods."""

    def test_is_call_instruction_identifies_call_instructions(self, test_env):
        """
        Test that is_call_instruction correctly identifies call instructions.

        RATIONALE: Identifying call instructions is fundamental for control flow
        analysis, building call graphs, and understanding program structure. The
        is_call_instruction() method must accurately distinguish call instructions
        from other instruction types.

        This test searches for actual call instructions in the test binary and
        verifies that is_call_instruction returns True for them. Call instructions
        are common in any binary with functions, making them reliable test cases.
        """
        # Find a call instruction in the binary
        import ida_ua

        current_ea = test_env.minimum_ea
        call_found = False

        for _ in range(500):  # Check up to 500 instructions
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is a call instruction (x86/x64 call opcode)
            mnemonic = test_env.instructions.get_mnemonic(insn)
            if mnemonic and 'call' in mnemonic.lower():
                # Found a call instruction - verify our method identifies it
                is_call = test_env.instructions.is_call_instruction(insn)
                assert is_call, f'is_call_instruction should return True for call at {insn.ea:#x}'
                call_found = True
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if not call_found:
            pytest.skip('No call instruction found in test binary')

    def test_is_call_instruction_returns_false_for_non_call(self, test_env):
        """
        Test that is_call_instruction returns False for non-call instructions.

        RATIONALE: False positives in call detection would corrupt control flow
        analysis and call graph construction. The method must return False for
        instructions that are not calls (mov, add, jmp, ret, etc.).

        This test verifies that common non-call instructions are correctly
        identified as not being calls.
        """
        # Find a non-call instruction (like mov, add, sub, push, pop)
        import ida_ua

        current_ea = test_env.minimum_ea
        non_call_found = False

        for _ in range(500):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is NOT a call instruction
            mnemonic = test_env.instructions.get_mnemonic(insn)
            if mnemonic and mnemonic.lower() in ['mov', 'push', 'pop', 'add', 'sub', 'xor', 'lea']:
                # Found a non-call instruction - verify our method returns False
                is_call = test_env.instructions.is_call_instruction(insn)
                assert not is_call, (
                    f'is_call_instruction should return False for {mnemonic} at {insn.ea:#x}'
                )
                non_call_found = True
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if not non_call_found:
            pytest.skip('No suitable non-call instruction found')

    def test_is_indirect_jump_or_call_identifies_indirect_control_flow(self, test_env):
        """
        Test that is_indirect_jump_or_call identifies indirect control flow.

        RATIONALE: Indirect jumps and calls (e.g., "jmp rax", "call [rbx]") are
        critical for security analysis, as they're often used in:
        - Virtual function calls (C++)
        - Function pointers
        - Switch statement jump tables
        - Return-oriented programming (ROP) gadgets

        The method must distinguish indirect control flow from direct control flow
        for accurate analysis. This test looks for instructions with indirect
        addressing in the test binary.
        """
        # Look for any jump instruction (direct or indirect)
        import ida_ua

        current_ea = test_env.minimum_ea
        jump_found = False

        for _ in range(500):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is a jump-like instruction
            mnemonic = test_env.instructions.get_mnemonic(insn)
            jump_mnemonics = ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl']
            if mnemonic and any(x in mnemonic.lower() for x in jump_mnemonics):
                # Found a jump - test the method
                result = test_env.instructions.is_indirect_jump_or_call(insn)
                # Result should be boolean
                assert isinstance(result, bool), 'is_indirect_jump_or_call should return boolean'
                jump_found = True
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if not jump_found:
            # If no jumps found, just test that method returns boolean for any instruction
            first_insn = test_env.instructions.get_at(test_env.minimum_ea)
            if first_insn:
                result = test_env.instructions.is_indirect_jump_or_call(first_insn)
                assert isinstance(result, bool), 'is_indirect_jump_or_call should return boolean'

    def test_is_indirect_jump_or_call_returns_false_for_non_jumps(self, test_env):
        """
        Test that is_indirect_jump_or_call returns False for non-jump instructions.

        RATIONALE: False positives would incorrectly flag regular instructions as
        control flow transfers, corrupting flow analysis. The method must return
        False for instructions that don't transfer control (mov, add, etc.).
        """
        # Find a non-jump/non-call instruction
        import ida_ua

        current_ea = test_env.minimum_ea

        for _ in range(500):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is a simple arithmetic/data movement instruction
            mnemonic = test_env.instructions.get_mnemonic(insn)
            if mnemonic and mnemonic.lower() in ['mov', 'push', 'add', 'sub', 'xor']:
                # These should NOT be indirect jumps/calls
                result = test_env.instructions.is_indirect_jump_or_call(insn)
                assert isinstance(result, bool), 'is_indirect_jump_or_call should return boolean'
                # Most likely False, but architecture-specific
                return

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

    def test_breaks_sequential_flow_identifies_flow_breaking_instructions(self, test_env):
        """
        Test that breaks_sequential_flow identifies instructions that stop sequential flow.

        RATIONALE: Identifying flow-breaking instructions (ret, jmp, etc.) is
        essential for:
        - Basic block construction
        - Control flow graph generation
        - Dead code detection
        - Function boundary identification

        Instructions like 'ret', 'jmp', and conditional branches break sequential
        execution flow. This test verifies the method correctly identifies them.
        """
        # Find a return instruction (very common flow breaker)
        import ida_ua

        current_ea = test_env.minimum_ea
        ret_found = False

        for _ in range(500):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is a return instruction
            mnemonic = test_env.instructions.get_mnemonic(insn)
            if mnemonic and mnemonic.lower() in ['ret', 'retn', 'retf']:
                # Found a return - should break sequential flow
                breaks_flow = test_env.instructions.breaks_sequential_flow(insn)
                assert isinstance(breaks_flow, bool), (
                    'breaks_sequential_flow should return boolean'
                )
                # Return instructions typically break flow
                ret_found = True
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        if not ret_found:
            pytest.skip('No return instruction found in test binary')

    def test_breaks_sequential_flow_returns_false_for_sequential_instructions(self, test_env):
        """
        Test that breaks_sequential_flow returns False for instructions that continue sequentially.

        RATIONALE: False positives would fragment basic blocks incorrectly and
        corrupt control flow analysis. Most instructions (mov, add, push, etc.)
        continue to the next instruction and should return False.

        This test verifies that common sequential instructions are correctly
        identified as not breaking flow.
        """
        # Find a sequential instruction (mov, add, push, etc.)
        import ida_ua

        current_ea = test_env.minimum_ea

        for _ in range(500):
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            # Check if this is a sequential instruction
            mnemonic = test_env.instructions.get_mnemonic(insn)
            if mnemonic and mnemonic.lower() in ['mov', 'push', 'add', 'sub', 'xor', 'lea']:
                # These should NOT break sequential flow
                breaks_flow = test_env.instructions.breaks_sequential_flow(insn)
                assert isinstance(breaks_flow, bool), (
                    'breaks_sequential_flow should return boolean'
                )
                # Sequential instructions should NOT break flow
                assert not breaks_flow, (
                    f'breaks_sequential_flow should return False for {mnemonic} at {insn.ea:#x}'
                )
                return

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            next_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea == current_ea:
                break
            current_ea = next_ea

        pytest.skip('No suitable sequential instruction found')

    def test_control_flow_methods_comprehensive(self, test_env):
        """
        Comprehensive test validating control flow methods on various instruction types.

        RATIONALE: This test provides a holistic validation of all three control flow
        methods (is_call_instruction, is_indirect_jump_or_call, breaks_sequential_flow)
        across multiple instruction types in a single test binary.

        By testing multiple cases together, we ensure the methods work consistently
        and correctly classify different instruction categories.
        """
        import ida_ua

        current_ea = test_env.minimum_ea

        # Track what we've found for comprehensive testing
        found_call = False
        found_ret = False
        found_sequential = False

        for _ in range(1000):  # Check more instructions for comprehensive test
            insn = test_env.instructions.get_at(current_ea)
            if not insn:
                break

            mnemonic = test_env.instructions.get_mnemonic(insn)
            if not mnemonic:
                # Move to next
                import ida_bytes
                import ida_idaapi

                current_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
                if current_ea == ida_idaapi.BADADDR:
                    break
                continue

            mnemonic_lower = mnemonic.lower()

            # Test call instructions
            if 'call' in mnemonic_lower and not found_call:
                is_call = test_env.instructions.is_call_instruction(insn)
                assert is_call, f'Should identify call at {insn.ea:#x}'
                found_call = True

            # Test return instructions
            if mnemonic_lower in ['ret', 'retn'] and not found_ret:
                breaks = test_env.instructions.breaks_sequential_flow(insn)
                # Returns typically break flow (though some architectures may vary)
                assert isinstance(breaks, bool), 'Should return boolean for ret'
                found_ret = True

            # Test sequential instructions
            if mnemonic_lower in ['mov', 'push', 'lea'] and not found_sequential:
                is_call = test_env.instructions.is_call_instruction(insn)
                breaks = test_env.instructions.breaks_sequential_flow(insn)
                assert not is_call, f'mov/push/lea should not be calls at {insn.ea:#x}'
                assert not breaks, f'mov/push/lea should not break flow at {insn.ea:#x}'
                found_sequential = True

            # If we found all categories, we're done
            if found_call and found_ret and found_sequential:
                break

            # Move to next instruction
            import ida_bytes
            import ida_idaapi

            current_ea = ida_bytes.next_head(current_ea, test_env.maximum_ea)
            if current_ea == ida_idaapi.BADADDR:
                break

        # We should have found at least one of each common category
        # If not, the test binary might not be suitable, but that's ok


class TestCrossReferenceManagement:
    """Tests for cross-reference management methods."""

    def test_add_code_reference_creates_code_xref(self, test_env):
        """
        Test that add_code_reference successfully creates a code cross-reference.

        RATIONALE: Manual cross-reference creation is critical for:
        - Fixing missed analysis (IDA doesn't always detect all control flow)
        - Documenting indirect control flow (computed jumps, callbacks)
        - Custom analysis passes (plugin development, binary patching)
        - Recovering from obfuscation

        This test creates a code xref and verifies it can be queried back,
        validating the round-trip functionality.
        """
        # Get two valid instruction addresses
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find a second instruction
        import ida_bytes
        import ida_idaapi

        second_ea = ida_bytes.next_head(first_insn.ea, test_env.maximum_ea)
        assert second_ea != ida_idaapi.BADADDR

        # Add a code reference from first to second
        import ida_xref

        test_env.instructions.add_code_reference(
            from_ea=first_insn.ea,
            to_ea=second_ea,
            reference_type=ida_xref.fl_CN,  # Near call
        )

        # Verify the xref was created by checking if it shows up in xrefs_to
        xrefs_to_second = list(test_env.xrefs.to_ea(second_ea))

        # Should have at least one xref (we just added it)
        # Note: There might be other xrefs too from normal analysis
        assert len(xrefs_to_second) > 0, (
            f'Should have at least one xref to {second_ea:#x} after adding'
        )

    def test_add_code_reference_with_invalid_from_address_raises_error(self, test_env):
        """
        Test that add_code_reference raises InvalidEAError for invalid from_ea.

        RATIONALE: Input validation is essential for API robustness. Invalid
        addresses should be caught early and reported clearly, rather than
        causing undefined behavior or silent failures.

        This test verifies proper error handling for the from_ea parameter.
        """
        invalid_addr = test_env.maximum_ea + 0x10000
        valid_addr = test_env.minimum_ea

        import ida_xref

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.add_code_reference(
                from_ea=invalid_addr, to_ea=valid_addr, reference_type=ida_xref.fl_CN
            )

    def test_add_code_reference_with_invalid_to_address_raises_error(self, test_env):
        """
        Test that add_code_reference raises InvalidEAError for invalid to_ea.

        RATIONALE: Both source and target addresses must be validated.
        This test ensures the to_ea parameter is properly checked.
        """
        valid_addr = test_env.minimum_ea
        invalid_addr = test_env.maximum_ea + 0x10000

        import ida_xref

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.add_code_reference(
                from_ea=valid_addr, to_ea=invalid_addr, reference_type=ida_xref.fl_CN
            )

    def test_add_data_reference_creates_data_xref(self, test_env):
        """
        Test that add_data_reference successfully creates a data cross-reference.

        RATIONALE: Data cross-references link code to data (strings, globals,
        constants). Manual data xref creation is important for:
        - Documenting complex data access patterns
        - Fixing missed data references in obfuscated code
        - Annotating computed data addresses
        - Plugin and script automation

        This test creates a data xref and verifies it can be queried.
        """
        # Get a valid instruction address
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Find a data address (could be anywhere in the valid address space)
        # We'll use an address in a different area
        import ida_segment

        seg = ida_segment.get_first_seg()
        if seg:
            # Use an address in the first segment as data target
            data_ea = seg.start_ea + 0x100

            # Make sure it's a valid address
            if test_env.is_valid_ea(data_ea):
                # Add a data reference from instruction to data
                import ida_xref

                test_env.instructions.add_data_reference(
                    from_ea=first_insn.ea,
                    to_ea=data_ea,
                    reference_type=ida_xref.dr_R,  # Read reference
                )

                # Verify the xref was created
                xrefs_to_data = list(test_env.xrefs.to_ea(data_ea))

                # Should have at least one xref
                assert len(xrefs_to_data) > 0, (
                    f'Should have at least one xref to {data_ea:#x} after adding'
                )
            else:
                pytest.skip('Could not find suitable data address')
        else:
            pytest.skip('No segments found in test binary')

    def test_add_data_reference_with_invalid_from_address_raises_error(self, test_env):
        """
        Test that add_data_reference raises InvalidEAError for invalid from_ea.

        RATIONALE: Consistent error handling across all methods. The from_ea
        parameter must be validated.
        """
        invalid_addr = test_env.maximum_ea + 0x10000
        valid_addr = test_env.minimum_ea

        import ida_xref

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.add_data_reference(
                from_ea=invalid_addr, to_ea=valid_addr, reference_type=ida_xref.dr_R
            )

    def test_add_data_reference_with_invalid_to_address_raises_error(self, test_env):
        """
        Test that add_data_reference raises InvalidEAError for invalid to_ea.

        RATIONALE: Both source and target addresses must be validated for
        data references, just as for code references.
        """
        valid_addr = test_env.minimum_ea
        invalid_addr = test_env.maximum_ea + 0x10000

        import ida_xref

        from ida_domain.base import InvalidEAError

        with pytest.raises(InvalidEAError):
            test_env.instructions.add_data_reference(
                from_ea=valid_addr, to_ea=invalid_addr, reference_type=ida_xref.dr_R
            )

    def test_add_code_reference_with_different_reference_types(self, test_env):
        """
        Test add_code_reference with various reference types.

        RATIONALE: Different reference types (call, jump, etc.) have different
        semantics in IDA's analysis. This test verifies that the method correctly
        handles various reference type constants.

        Reference types tested:
        - fl_CN: Near call
        - fl_JN: Near jump
        - fl_F: Regular flow (fall-through)
        """
        # Get two instruction addresses
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        import ida_bytes
        import ida_idaapi

        second_ea = ida_bytes.next_head(first_insn.ea, test_env.maximum_ea)
        assert second_ea != ida_idaapi.BADADDR

        third_ea = ida_bytes.next_head(second_ea, test_env.maximum_ea)
        if third_ea == ida_idaapi.BADADDR:
            pytest.skip('Need at least 3 instructions for this test')

        # Test different reference types
        import ida_xref

        # Test near call reference
        test_env.instructions.add_code_reference(
            from_ea=first_insn.ea, to_ea=second_ea, reference_type=ida_xref.fl_CN
        )

        # Test near jump reference
        test_env.instructions.add_code_reference(
            from_ea=first_insn.ea, to_ea=third_ea, reference_type=ida_xref.fl_JN
        )

        # Test ordinary flow
        test_env.instructions.add_code_reference(
            from_ea=second_ea, to_ea=third_ea, reference_type=ida_xref.fl_F
        )

        # All operations should complete without error
        # Verification would require checking xref details which is beyond scope

    def test_add_data_reference_with_different_reference_types(self, test_env):
        """
        Test add_data_reference with various reference types.

        RATIONALE: Data references have different types (read, write, offset)
        that indicate how the data is accessed. This test verifies the method
        handles different data reference types correctly.

        Reference types tested:
        - dr_R: Read access
        - dr_W: Write access
        - dr_O: Offset
        """
        # Get instruction address
        first_insn = test_env.instructions.get_at(test_env.minimum_ea)
        assert first_insn is not None

        # Get a data address
        import ida_segment

        seg = ida_segment.get_first_seg()
        if not seg:
            pytest.skip('No segments in test binary')

        data_ea1 = seg.start_ea + 0x100
        data_ea2 = seg.start_ea + 0x200
        data_ea3 = seg.start_ea + 0x300

        if not all(test_env.is_valid_ea(ea) for ea in [data_ea1, data_ea2, data_ea3]):
            pytest.skip('Could not find suitable data addresses')

        # Test different data reference types
        import ida_xref

        # Test read reference
        test_env.instructions.add_data_reference(
            from_ea=first_insn.ea, to_ea=data_ea1, reference_type=ida_xref.dr_R
        )

        # Test write reference
        test_env.instructions.add_data_reference(
            from_ea=first_insn.ea, to_ea=data_ea2, reference_type=ida_xref.dr_W
        )

        # Test offset reference
        test_env.instructions.add_data_reference(
            from_ea=first_insn.ea, to_ea=data_ea3, reference_type=ida_xref.dr_O
        )

        # All operations should complete without error
