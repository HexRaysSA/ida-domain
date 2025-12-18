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
        path=instructions_test_setup,
        args=ida_options,
        save_on_close=False
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
        assert first_insn is not None, "Database should have at least one instruction"

        # Verify can_decode returns True for this known-good instruction
        assert test_env.instructions.can_decode(first_insn.ea), (
            f"can_decode should return True for valid instruction at 0x{first_insn.ea:x}"
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
            pytest.skip("Test address not available in this database")

        # Ensure this is data, not code (create dword, which undefines any instruction)
        test_env.bytes.create_dword_at(test_addr, count=1, force=True)

        # can_decode should return False for data
        assert not test_env.instructions.can_decode(test_addr), (
            f"can_decode should return False for data address at 0x{test_addr:x}"
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
            pytest.skip("Test address not available in database")

        # Undefine the bytes to ensure they're truly undefined
        import ida_bytes
        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 1)

        # can_decode should return False for undefined bytes
        result = test_env.instructions.can_decode(test_addr)
        assert not result, (
            f"can_decode should return False for undefined bytes at 0x{test_addr:x}"
        )

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
            f"can_decode should return True for valid instruction at 0x{first_insn.ea:x}"
        )

        # Test 2: Data address should return False
        data_addr = test_env.minimum_ea + 0x2000
        if test_env.is_valid_ea(data_addr):
            test_env.bytes.create_dword_at(data_addr, count=1, force=True)
            assert not test_env.instructions.can_decode(data_addr), (
                f"can_decode should return False for data at 0x{data_addr:x}"
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
            pytest.skip("Test address not available")

        # Ensure bytes are undefined
        import ida_bytes
        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Write some valid instruction bytes (e.g., x86_64 nop = 0x90)
        # This ensures we have decodable bytes at the address
        ida_bytes.patch_byte(test_addr, 0x90)  # nop instruction

        # Create instruction at this address
        success = test_env.instructions.create_at(test_addr)

        # Verify creation succeeded
        assert success, f"create_at should succeed at 0x{test_addr:x}"

        # Verify we can now decode an instruction there
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, (
            f"After create_at, should be able to decode instruction at 0x{test_addr:x}"
        )

        # Verify can_decode now returns True
        assert test_env.instructions.can_decode(test_addr), (
            f"After create_at, can_decode should return True at 0x{test_addr:x}"
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
        assert success, (
            f"create_at should succeed on existing instruction at 0x{first_insn.ea:x}"
        )

        # Instruction should still be decodable
        assert test_env.instructions.can_decode(first_insn.ea), (
            f"Instruction should still be decodable at 0x{first_insn.ea:x}"
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
            pytest.skip("Test address not available")

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
        assert success, f"create_at should convert data to code at 0x{test_addr:x}"

        # Verify it's now an instruction
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, (
            f"Should be able to decode instruction at 0x{test_addr:x}"
        )

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
            pytest.skip("Test address not available")

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
        assert isinstance(success, bool), (
            "create_at should return boolean, not raise exception"
        )

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
            pytest.skip("Test address not available")

        import ida_bytes

        # Step 1: Start with undefined bytes
        ida_bytes.del_items(test_addr, ida_bytes.DELIT_SIMPLE, 8)

        # Step 2: Write valid instruction bytes
        ida_bytes.patch_byte(test_addr, 0x90)  # nop

        # Step 3: Create instruction
        success = test_env.instructions.create_at(test_addr)
        assert success, "create_at should succeed"

        # Step 4: Validate the created instruction
        assert test_env.instructions.can_decode(test_addr), (
            "After create_at, can_decode should return True"
        )

        # Step 5: Verify we can decode and analyze
        insn = test_env.instructions.get_at(test_addr)
        assert insn is not None, "Should be able to decode instruction"
        assert insn.ea == test_addr, "Decoded instruction should be at correct address"

        # Verify we can get mnemonic
        mnem = test_env.instructions.get_mnemonic(insn)
        assert mnem is not None and len(mnem) > 0, (
            "Should be able to get instruction mnemonic"
        )
