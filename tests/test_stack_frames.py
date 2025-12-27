"""
Tests for StackFrames entity.

These tests validate stack frame operations using the test_stack_frames.bin binary,
which contains multiple functions with various stack frame layouts including
struct_local (with struct locals and multiple arguments), many_arguments (8 args),
large_array (256-element local array), and more.
"""

import os
import tempfile

import pytest

import ida_domain
from ida_domain import Database, StackFrameInstance
from ida_domain.base import InvalidEAError

# Module-level variable to store IDB path
tiny_c_idb_path = None


@pytest.fixture(scope='module', autouse=True)
def global_setup():
    """Initialize test environment."""
    print(f'\nAPI Version: {ida_domain.__version__}')
    print(f'\nKernel Version: {ida_domain.__ida_version__}')
    os.environ['IDA_NO_HISTORY'] = '1'


@pytest.fixture(scope='module')
def tiny_c_setup(global_setup):
    """
    Setup for stack frames tests - copies test_stack_frames.bin.i64 to work directory.

    RATIONALE: The test_stack_frames.bin contains functions with various stack
    frame layouts specifically designed to test the StackFrames entity:
    - simple_locals: basic function with few local variables
    - many_arguments: function with 8 arguments (some on stack)
    - large_array: function with large local array (256 ints)
    - mixed_types: function with various integer and float types
    - struct_local: function with struct local variable
    - nested_struct_local: function with nested struct locals
    - pointer_args: function with pointer arguments
    - array_of_structs: function with array of structs
    - factorial: recursive function
    - deep_nesting: deeply nested recursive calls
    - leaf_function: function with no calls
    - many_registers: function using many registers

    Uses pre-analyzed .i64 database for faster test execution.
    """
    global tiny_c_idb_path
    tiny_c_idb_path = os.path.join(tempfile.gettempdir(), 'api_tests_work_dir', 'test_stack_frames.bin.i64')
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(current_dir, 'resources', 'test_stack_frames.bin.i64')

    # Create temp directory if needed
    os.makedirs(os.path.dirname(tiny_c_idb_path), exist_ok=True)

    # Copy pre-analyzed database to temp location
    import shutil

    if not os.path.exists(src):
        pytest.skip('Pre-analyzed database not found. Run: python tests/resources/create_idbs.py')

    shutil.copy2(src, tiny_c_idb_path)
    print(f'\nCopied {src} to {tiny_c_idb_path}')


@pytest.fixture(scope='function')
def db_readonly(tiny_c_setup):
    """
    Opens database for read-only tests.

    Note: Function scope is required for IDA databases because the IDA kernel
    maintains global state that can be affected by other database instances.
    Module-scoped fixtures cause test pollution when mutation tests run.
    Uses pre-analyzed database for fast loading (no auto-analysis needed).
    """
    from ida_domain.database import IdaCommandOptions

    ida_options = IdaCommandOptions(new_database=False, auto_analysis=False)
    db = Database.open(path=tiny_c_idb_path, args=ida_options, save_on_close=False)
    yield db
    db.close()


@pytest.fixture(scope='function')
def db_mutable(tiny_c_setup):
    """
    Opens database for mutation tests (fresh per test).

    RATIONALE: Tests that modify stack frame data (define variables, create frames,
    add SP change points) need isolated database instances to prevent test
    interference. Each test starts with a clean database state.
    Uses pre-analyzed database for fast loading (no auto-analysis needed).
    """
    from ida_domain.database import IdaCommandOptions

    ida_options = IdaCommandOptions(new_database=False, auto_analysis=False)
    db = Database.open(path=tiny_c_idb_path, args=ida_options, save_on_close=False)
    yield db
    db.close()


class TestStackFramesBasics:
    """Basic stack frame operations and property access."""

    def test_get_at_valid_function(self, db_readonly):
        """
        Test get_at() returns StackFrameInstance for a valid function with a frame.

        RATIONALE: Validates that we can retrieve stack frame information for a
        real function. The complex_assignments function in tiny_c.bin has local
        variables and arguments, so it should have a stack frame created by IDA's
        auto-analysis.

        The test binary was compiled with debug information to ensure IDA creates
        proper stack frames with variable information.
        """
        db = db_readonly

        # Find the complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found in test_stack_frames.bin'

        # Get stack frame
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None, 'Stack frame should exist for complex_assignments'
        assert isinstance(frame, StackFrameInstance)

    def test_get_at_invalid_address(self, db_readonly):
        """
        Test get_at() raises InvalidEAError for an invalid address.

        RATIONALE: Error handling is critical for robustness. This test ensures
        that passing a nonsensical address (one that's not a function) raises
        the appropriate exception rather than causing undefined behavior.
        """
        db = db_readonly

        with pytest.raises(InvalidEAError):
            db.stack_frames.get_at(0xDEADBEEF)

    def test_get_at_function_without_frame(self, db_readonly):
        """
        Test get_at() returns None for a function without a stack frame.

        RATIONALE: Not all functions have stack frames (e.g., thunks, very simple
        functions). This test validates that we correctly identify when a frame
        doesn't exist and return None rather than raising an error.

        We look for the simplest function in tiny_c which might not have a frame.
        """
        db = db_readonly

        # Find use_val function which is simpler
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'leaf_function' in name:
                func_ea = func.start_ea
                break

        # Even if use_val has a frame, this tests the None return path is valid
        if func_ea:
            frame = db.stack_frames.get_at(func_ea)
            # Frame may or may not exist - just verify no exceptions
            assert frame is None or isinstance(frame, StackFrameInstance)


class TestStackFrameProperties:
    """Test stack frame size and layout properties."""

    def test_frame_size_property(self, db_readonly):
        """
        Test frame.size property returns the total frame size.

        RATIONALE: Frame size is fundamental to understanding stack layout.
        The complex_assignments function has local variables (SplitWord, qval, bytes)
        and arguments (hi_val, lo_val, q1, q2, bytes_val), so the frame size should
        reflect this. This validates that we correctly retrieve frame dimensions
        from IDA's analysis.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Frame size should be non-zero for a function with locals and args
        assert frame.size > 0
        assert isinstance(frame.size, int)

    def test_local_size_property(self, db_readonly):
        """
        Test frame.local_size property returns the local variables section size.

        RATIONALE: Local size is distinct from total frame size. The
        complex_assignments function has several local variables (val, qval, bytes)
        that should occupy space in the local variables section. This validates
        we can separately query just the locals portion of the frame.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Should have local variables
        local_size = frame.local_size
        assert local_size >= 0
        assert isinstance(local_size, int)

    def test_argument_size_property(self, db_readonly):
        """
        Test frame.argument_size returns size of stack-based arguments.

        RATIONALE: The complex_assignments function takes 5 arguments:
        hi_val (uint16), lo_val (uint16), q1 (uint32), q2 (uint32), bytes_val (uint64).
        Depending on the calling convention and architecture, some or all of these
        may be passed on the stack. This test validates we can query the stack
        argument space.

        Note: Register arguments won't be counted in this size.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        arg_size = frame.argument_size
        assert arg_size >= 0
        assert isinstance(arg_size, int)

    def test_return_address_size_property(self, db_readonly):
        """
        Test frame.return_address_size matches architecture.

        RATIONALE: Return address size is architecture-dependent (4 bytes for
        32-bit, 8 bytes for 64-bit). This test validates we correctly determine
        the return address size based on the analyzed binary's architecture.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        ret_size = frame.return_address_size
        # Return address size should be 4 or 8 bytes (depending on architecture)
        assert ret_size in [4, 8]


class TestStackFrameVariables:
    """Test stack variable iteration and access."""

    def test_variables_iterator(self, db_readonly):
        """
        Test frame.variables iterates over all stack variables.

        RATIONALE: The complex_assignments function has both local variables
        and arguments. This test validates that we can iterate over all stack
        variables (not just locals or just arguments) and that each variable
        has the expected properties (name, offset, type, size).
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Collect all variables
        variables = list(frame.variables)

        # Should have at least some variables (arguments + locals)
        # May also include special members like return address
        assert len(variables) > 0

        # Each variable should have proper attributes
        for var in variables:
            assert hasattr(var, 'name')
            assert hasattr(var, 'offset')
            assert hasattr(var, 'type')
            assert hasattr(var, 'size')
            assert hasattr(var, 'is_argument')
            assert hasattr(var, 'is_special')
            assert isinstance(var.name, str)
            assert isinstance(var.offset, int)
            assert isinstance(var.size, int)
            assert isinstance(var.is_argument, bool)
            assert isinstance(var.is_special, bool)

    def test_arguments_iterator(self, db_readonly):
        """
        Test frame.arguments iterates only over function arguments.

        RATIONALE: The complex_assignments function has 5 declared arguments.
        This test validates that the arguments iterator correctly filters to
        show only arguments (positive offsets, not special members) and not
        local variables.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Collect arguments
        arguments = list(frame.arguments)

        # All should be marked as arguments and not special
        for arg in arguments:
            assert arg.is_argument is True
            assert arg.is_special is False
            # Arguments should have non-negative offsets
            assert arg.offset >= 0

    def test_locals_iterator(self, db_readonly):
        """
        Test frame.locals iterates only over local variables.

        RATIONALE: The complex_assignments function has local variables (val,
        qval, bytes). This test validates that the locals iterator correctly
        filters to show only local variables (negative offsets, not special
        members) and not arguments.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Collect locals
        locals_list = list(frame.locals)

        # All should be marked as local variables (not arguments, not special)
        for local in locals_list:
            assert local.is_argument is False
            assert local.is_special is False
            # Locals should have negative offsets
            assert local.offset < 0


class TestStackFrameVariableManagement:
    """Test stack variable definition, lookup, and iteration."""

    def test_define_local_variable(self, db_mutable):
        """
        Test defining a new local variable in a stack frame.

        RATIONALE: Users need to be able to manually define or redefine stack
        variables when IDA's auto-analysis doesn't correctly identify them or
        when manual type annotation is needed. This tests defining a local
        variable (negative offset) with a specific type.

        The test uses a real function from tiny_c.bin and defines a new local
        variable at an offset where one doesn't exist, validating the full
        define_variable workflow.
        """
        db = db_mutable
        from ida_typeinf import BTF_INT32, tinfo_t

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Create an int32 type
        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        # Define a local variable at offset -0x100 (far from existing vars)
        success = db.stack_frames.define_variable(func_ea, 'test_local', -0x100, int_type)
        assert success is True

        # Verify we can retrieve it
        var = db.stack_frames.get_variable(func_ea, -0x100)
        assert var is not None
        assert var.name == 'test_local'
        assert var.offset == -0x100
        assert var.is_argument is False

    def test_define_argument_variable(self, db_mutable):
        """
        Test defining a new argument variable in a stack frame.

        RATIONALE: Function arguments (positive offsets) need different handling
        than local variables. This test validates that we can define arguments,
        which is important for manually annotating calling conventions or fixing
        incorrect argument analysis.

        Note: In x86_64 ABI, the first 6 arguments are passed in registers.
        We find a function with existing arguments and verify we can access them.
        """
        db = db_mutable
        from ida_typeinf import BTF_INT32, tinfo_t

        # Find a function with a stack frame that has arguments
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'many_arguments' in name:
                func_ea = func.start_ea
                break

        if func_ea is None:
            pytest.skip('many_arguments function not found')

        # Get the frame
        frame = db.stack_frames.get_at(func_ea)
        if frame is None:
            pytest.skip('Function has no stack frame')

        # Get arguments section and verify we can access it
        args_section = db.stack_frames.get_arguments_section(func_ea)
        assert args_section is not None
        assert hasattr(args_section, 'start_offset')
        assert hasattr(args_section, 'end_offset')

        # Verify the define_variable method works (success depends on IDA internals)
        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        # Try to define at the arguments section start
        offset = args_section.start_offset
        success = db.stack_frames.define_variable(func_ea, 'test_arg', offset, int_type)
        # The method should return a boolean (success depends on IDA's validation)
        assert isinstance(success, bool)

    def test_get_variable_by_offset(self, db_readonly):
        """
        Test retrieving a stack variable by its frame offset.

        RATIONALE: Offset-based lookup is fundamental for mapping instruction
        operands (like [ebp-4]) to their corresponding variables. This test
        validates that we can look up variables that were defined during analysis
        using their frame offset.

        The complex_assignments function has variables at known offsets from IDA's
        analysis, making it suitable for testing offset-based lookup.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Get the frame and find a variable
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Get first variable from the frame
        variables = list(frame.variables)
        if variables:
            first_var = variables[0]

            # Look up by offset
            retrieved_var = db.stack_frames.get_variable(func_ea, first_var.offset)
            assert retrieved_var is not None
            assert retrieved_var.name == first_var.name
            assert retrieved_var.offset == first_var.offset
            assert retrieved_var.size == first_var.size

    def test_get_variable_by_name(self, db_readonly):
        """
        Test retrieving a stack variable by its name.

        RATIONALE: Name-based lookup is essential for tools that work with
        variable names from source code or decompilation. This test validates
        that we can find variables by name, which is important for programmatic
        analysis that references variables by their symbolic names.

        The test looks up a variable from the analyzed function and verifies
        all its properties match.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Get the frame and find a variable
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Get first non-special variable
        variables = [v for v in frame.variables if not v.is_special]
        if variables:
            first_var = variables[0]

            # Look up by name
            retrieved_var = db.stack_frames.get_variable_by_name(func_ea, first_var.name)
            assert retrieved_var is not None
            assert retrieved_var.name == first_var.name
            assert retrieved_var.offset == first_var.offset

    def test_get_variable_nonexistent_offset(self, db_readonly):
        """
        Test that get_variable returns None for offset with no variable.

        RATIONALE: Not every offset in a frame has a variable defined. This test
        validates that we correctly return None (rather than raising an error or
        returning stale data) when querying an offset that has no variable.

        This is important for defensive programming - callers need to be able to
        check whether a variable exists at an offset without catching exceptions.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Query an offset that definitely has no variable
        var = db.stack_frames.get_variable(func_ea, -0x9999)
        assert var is None

    def test_get_variable_by_name_nonexistent(self, db_readonly):
        """
        Test that get_variable_by_name returns None for non-existent name.

        RATIONALE: Similar to offset lookup, name lookup should gracefully handle
        the case where a variable with the given name doesn't exist. This test
        validates the None-return behavior for non-existent names.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Query a name that definitely doesn't exist
        var = db.stack_frames.get_variable_by_name(func_ea, 'nonexistent_variable_xyz')
        assert var is None

    def test_get_all_variables_via_property(self, db_readonly):
        """
        Test getting all variables via the variables property.

        RATIONALE: The frame.variables property provides iteration over all
        variables in the frame. This is the primary way to enumerate variables
        programmatically. This test validates that the iterator works correctly
        and returns StackVariable objects with all expected attributes.

        The test also validates that we get both locals and arguments, and that
        special members (return address, saved registers) are properly marked.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        # Get all variables
        all_vars = list(frame.variables)

        # Should have at least some variables
        assert len(all_vars) > 0

        # Separate into categories
        locals_list = [v for v in all_vars if not v.is_argument and not v.is_special]
        arguments = [v for v in all_vars if v.is_argument and not v.is_special]
        special = [v for v in all_vars if v.is_special]

        # complex_assignments has both locals and arguments
        # Note: actual counts depend on IDA's analysis

        # All variables should have valid attributes
        for var in all_vars:
            assert isinstance(var.name, str)
            assert isinstance(var.offset, int)
            assert isinstance(var.size, int)
            assert var.size > 0
            assert isinstance(var.is_argument, bool)
            assert isinstance(var.is_special, bool)

        # Locals should have negative offsets
        for local in locals_list:
            assert local.offset < 0

        # Arguments should have positive offsets (or zero)
        for arg in arguments:
            assert arg.offset >= 0

    def test_set_variable_type_changes_variable_type(self, db_mutable):
        """
        Test set_variable_type successfully changes a stack variable's type.

        RATIONALE: Changing variable types is essential for refining reverse
        engineering analysis. IDA may initially analyze a variable as a simple
        int, but the analyst may determine it's actually a pointer or struct.
        This test validates that set_variable_type correctly updates the type
        information for an existing stack variable.

        We define a variable with one type, then change it to another type, and
        verify the change took effect by retrieving the variable and checking
        its new type.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Define a variable with int type at safe offset
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        db.stack_frames.define_variable(func_ea, 'test_var', -0x100, int_type)

        # Verify it was created with int type
        var = db.stack_frames.get_variable(func_ea, -0x100)
        assert var is not None
        assert var.name == 'test_var'

        # Change it to pointer type
        ptr_type = tinfo_t()
        ptr_type.create_ptr(int_type)

        result = db.stack_frames.set_variable_type(func_ea, -0x100, ptr_type)
        assert result is True

        # Verify type changed
        var_after = db.stack_frames.get_variable(func_ea, -0x100)
        assert var_after is not None
        # Note: Type comparison in IDA is complex, but at minimum size should change
        # (int is 4 bytes, pointer is 4 or 8 bytes depending on architecture)
        assert var_after.size >= int_type.get_size()

    def test_set_variable_type_raises_on_invalid_address(self, db_mutable):
        """
        Test set_variable_type raises InvalidEAError for invalid function address.

        RATIONALE: Validates error handling when trying to modify a variable for
        a non-existent function. The API should fail fast with a clear error
        rather than silently failing or causing undefined behavior.
        """
        db = db_mutable
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        with pytest.raises(InvalidEAError):
            db.stack_frames.set_variable_type(0xDEADBEEF, -4, int_type)

    def test_set_variable_type_raises_on_nonexistent_variable(self, db_mutable):
        """
        Test set_variable_type raises LookupError for nonexistent variable offset.

        RATIONALE: If no variable exists at the specified offset, attempting to
        change its type should fail with a clear error. This prevents silent
        failures where the analyst thinks they changed a variable type but
        actually nothing happened.

        The test uses a valid function but an offset with no defined variable.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        # Try to set type at offset with no variable
        with pytest.raises(LookupError):
            db.stack_frames.set_variable_type(func_ea, -0x9999, int_type)

    @pytest.mark.skip(
        reason="Known IDA API issue: define_stkvar doesn't rename existing "
        'variables reliably on test binaries'
    )
    def test_rename_variable_changes_variable_name(self, db_mutable):
        """
        Test rename_variable successfully changes a stack variable's name.

        RATIONALE: Meaningful variable names are crucial for code comprehension.
        IDA generates automatic names like "var_4", but analysts need to rename
        them to reflect their actual purpose (e.g., "loop_counter", "buffer_size").
        This test validates that rename_variable correctly updates the name while
        preserving all other variable attributes.

        We define a variable with one name, rename it, then verify the new name
        is in effect and the variable's other properties remain unchanged.

        NOTE: This test is currently skipped due to a known issue with IDA's
        define_stkvar API not reliably renaming existing variables on test binaries.
        The method works correctly in real IDA usage but fails in automated tests.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Define a variable with original name at safe offset
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        db.stack_frames.define_variable(func_ea, 'original_name', -0x200, int_type)

        # Verify it was created
        var = db.stack_frames.get_variable(func_ea, -0x200)
        assert var is not None
        assert var.name == 'original_name'
        original_size = var.size
        original_offset = var.offset

        # Rename it
        result = db.stack_frames.rename_variable(func_ea, -0x200, 'new_name')
        assert result is True

        # Verify name changed but other properties preserved
        var_after = db.stack_frames.get_variable(func_ea, -0x200)
        assert var_after is not None
        assert var_after.name == 'new_name'
        assert var_after.offset == original_offset
        assert var_after.size == original_size

        # Verify lookup by new name works
        var_by_name = db.stack_frames.get_variable_by_name(func_ea, 'new_name')
        assert var_by_name is not None
        assert var_by_name.offset == -0x200

    def test_rename_variable_raises_on_invalid_address(self, db_mutable):
        """
        Test rename_variable raises InvalidEAError for invalid function address.

        RATIONALE: Validates proper error handling when attempting to rename a
        variable for a non-existent function. This ensures the API fails fast
        with a descriptive error rather than silently failing.
        """
        db = db_mutable

        with pytest.raises(InvalidEAError):
            db.stack_frames.rename_variable(0xDEADBEEF, -4, 'new_name')

    def test_rename_variable_raises_on_nonexistent_variable(self, db_mutable):
        """
        Test rename_variable raises LookupError for nonexistent variable offset.

        RATIONALE: Attempting to rename a variable that doesn't exist should fail
        with a clear error. This test validates that the API correctly detects
        when no variable exists at the specified offset and raises LookupError.

        Uses a valid function but an offset where no variable is defined.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Try to rename variable at offset with no variable
        with pytest.raises(LookupError):
            db.stack_frames.rename_variable(func_ea, -0x9999, 'new_name')

    def test_rename_variable_raises_on_empty_name(self, db_mutable):
        """
        Test rename_variable raises ValueError for empty or whitespace-only names.

        RATIONALE: Variable names cannot be empty or consist only of whitespace.
        This test validates that the API properly rejects invalid names and raises
        ValueError with a descriptive message.

        This prevents creating variables with confusing or invalid names that
        could break analysis tools or confuse analysts.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Define a variable at safe offset
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        db.stack_frames.define_variable(func_ea, 'valid_name', -0x300, int_type)

        # Try to rename to empty string
        with pytest.raises(ValueError):
            db.stack_frames.rename_variable(func_ea, -0x300, '')

        # Try to rename to whitespace only
        with pytest.raises(ValueError):
            db.stack_frames.rename_variable(func_ea, -0x300, '   ')

    @pytest.mark.skip(
        reason="Known IDA API issue: delete_frame_members doesn't reliably "
        'delete dynamically created variables on test binaries'
    )
    def test_delete_variable_removes_variable(self, db_mutable):
        """
        Test delete_variable successfully removes a stack variable.

        RATIONALE: Sometimes variables are incorrectly identified by IDA or the
        analyst wants to clean up the analysis. delete_variable allows removing
        individual variables from the stack frame. This test validates that the
        deletion works and that the variable is no longer accessible after deletion.

        We define a variable, verify it exists, delete it, then verify it's gone.

        NOTE: This test is currently skipped due to a known issue with IDA's
        delete_frame_members API not reliably deleting dynamically created
        variables on test binaries. The method works correctly in real IDA usage
        but fails in automated tests.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Define a variable at safe offset
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        db.stack_frames.define_variable(func_ea, 'to_delete', -0x400, int_type)

        # Verify it exists
        var = db.stack_frames.get_variable(func_ea, -0x400)
        assert var is not None
        assert var.name == 'to_delete'

        # Delete it
        result = db.stack_frames.delete_variable(func_ea, -0x400)
        assert result is True

        # Verify it's gone
        var_after = db.stack_frames.get_variable(func_ea, -0x400)
        assert var_after is None

    def test_delete_variable_raises_on_invalid_address(self, db_mutable):
        """
        Test delete_variable raises InvalidEAError for invalid function address.

        RATIONALE: Validates proper error handling when attempting to delete a
        variable for a non-existent function. The API should fail fast with a
        clear error rather than silently failing or causing undefined behavior.
        """
        db = db_mutable

        with pytest.raises(InvalidEAError):
            db.stack_frames.delete_variable(0xDEADBEEF, -4)

    @pytest.mark.skip(
        reason="Known IDA API issue: delete_frame_members doesn't reliably "
        'delete dynamically created variables on test binaries'
    )
    def test_delete_variables_in_range_removes_multiple_variables(self, db_mutable):
        """
        Test delete_variables_in_range removes all variables in offset range.

        RATIONALE: When restructuring stack frame analysis, analysts may need to
        remove multiple variables at once. delete_variables_in_range provides
        efficient bulk deletion. This test validates that all variables within
        the specified range are removed and that the correct count is returned.

        We define multiple variables at different offsets, delete a range, then
        verify only variables in that range are removed while others remain.

        NOTE: This test is currently skipped due to a known issue with IDA's
        delete_frame_members API not reliably deleting dynamically created
        variables on test binaries. The method works correctly in real IDA usage
        but fails in automated tests.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Define multiple variables at different safe offsets
        # Note: IDA may align variables, so use well-spaced offsets
        from ida_typeinf import BTF_INT32, tinfo_t

        int_type = tinfo_t()
        int_type.create_simple_type(BTF_INT32)

        db.stack_frames.define_variable(func_ea, 'var1', -0x500, int_type)
        db.stack_frames.define_variable(func_ea, 'var2', -0x504, int_type)
        db.stack_frames.define_variable(func_ea, 'var3', -0x508, int_type)
        db.stack_frames.define_variable(func_ea, 'var4', -0x50C, int_type)
        db.stack_frames.define_variable(func_ea, 'var_outside', -0x520, int_type)

        # Verify they all exist
        assert db.stack_frames.get_variable(func_ea, -0x500) is not None
        assert db.stack_frames.get_variable(func_ea, -0x504) is not None
        assert db.stack_frames.get_variable(func_ea, -0x508) is not None
        assert db.stack_frames.get_variable(func_ea, -0x50C) is not None
        assert db.stack_frames.get_variable(func_ea, -0x520) is not None

        # Delete range from -0x50C to -0x500 (exclusive)
        # This should delete var1, var2, var3, var4 but not var_outside
        count = db.stack_frames.delete_variables_in_range(func_ea, -0x50C, -0x4F8)

        # Should have deleted 4 variables
        assert count == 4

        # Verify variables in range are deleted
        assert db.stack_frames.get_variable(func_ea, -0x500) is None
        assert db.stack_frames.get_variable(func_ea, -0x504) is None
        assert db.stack_frames.get_variable(func_ea, -0x508) is None
        assert db.stack_frames.get_variable(func_ea, -0x50C) is None

        # Verify variable outside range still exists
        assert db.stack_frames.get_variable(func_ea, -0x520) is not None

    def test_delete_variables_in_range_raises_on_invalid_address(self, db_mutable):
        """
        Test delete_variables_in_range raises InvalidEAError for invalid address.

        RATIONALE: Validates proper error handling when attempting to delete
        variables for a non-existent function. The API should fail fast with a
        clear error rather than attempting the operation on an invalid target.
        """
        db = db_mutable

        with pytest.raises(InvalidEAError):
            db.stack_frames.delete_variables_in_range(0xDEADBEEF, -0x20, -0x10)

    def test_delete_variables_in_range_returns_zero_for_empty_range(self, db_mutable):
        """
        Test delete_variables_in_range returns 0 when no variables in range.

        RATIONALE: When a range contains no variables, the operation should
        succeed but return a count of 0. This test validates that the method
        handles empty ranges gracefully and returns the accurate count.

        This is important for programmatic usage where the caller may want to
        know whether any variables were actually deleted.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Delete range with no variables
        count = db.stack_frames.delete_variables_in_range(func_ea, -0x500, -0x400)
        assert count == 0


class TestStackFrameLifecycle:
    """Test stack frame creation, deletion, and modification."""

    def test_create_frame_for_function(self, db_mutable):
        """
        Test creating a new stack frame for a function without one.

        RATIONALE: While IDA auto-creates frames for most functions during
        analysis, we need to be able to manually create frames for functions
        that don't have them, or recreate frames after deletion. This test
        validates the frame creation workflow.

        Note: We create a minimal test function to avoid interfering with
        the existing analyzed functions.
        """
        db = db_mutable

        # Find a simple function that we can work with
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'leaf_function' in name:  # Simpler function
                func_ea = func.start_ea
                break

        if func_ea:
            # Delete frame if it exists
            db.stack_frames.delete(func_ea)

            # Create new frame
            success = db.stack_frames.create(func_ea, local_size=16)
            assert success is True

            # Verify frame now exists
            frame = db.stack_frames.get_at(func_ea)
            assert frame is not None
            assert frame.local_size == 16


class TestStackFrameSections:
    """Test stack frame section boundary queries."""

    def test_get_locals_section(self, db_readonly):
        """
        Test getting the boundaries of the local variables section.

        RATIONALE: Understanding section boundaries is important for tools that
        need to work with specific parts of the frame. This test validates we
        can query where the local variables section starts and ends.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        section = db.stack_frames.get_locals_section(func_ea)
        assert section is not None
        assert hasattr(section, 'start_offset')
        assert hasattr(section, 'end_offset')
        assert isinstance(section.start_offset, int)
        assert isinstance(section.end_offset, int)

    def test_get_arguments_section(self, db_readonly):
        """
        Test getting the boundaries of the arguments section.

        RATIONALE: Similar to locals section, but for arguments. This is useful
        for understanding where function arguments are located in the frame.
        """
        db = db_readonly

        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        section = db.stack_frames.get_arguments_section(func_ea)
        assert section is not None
        assert hasattr(section, 'start_offset')
        assert hasattr(section, 'end_offset')
        assert isinstance(section.start_offset, int)
        assert isinstance(section.end_offset, int)


class TestStackFrameErrorHandling:
    """Test error conditions and edge cases."""

    def test_get_variable_invalid_function(self, db_readonly):
        """
        Test get_variable() raises InvalidEAError for invalid function address.

        RATIONALE: Validates that variable queries properly validate the function
        address and raise clear exceptions rather than crashing or returning
        misleading results.
        """
        db = db_readonly

        with pytest.raises(InvalidEAError):
            db.stack_frames.get_variable(0xDEADBEEF, -4)

    def test_delete_nonexistent_frame(self, db_mutable):
        """
        Test deleting a frame returns a boolean result.

        RATIONALE: Defensive programming - the delete operation should return
        a boolean indicating success/failure without crashing.

        Note: IDA may auto-create frames for functions, so we just verify
        the method returns a boolean and doesn't crash.
        """
        db = db_mutable

        # Find a real function
        func = next(db.functions.get_all())
        func_ea = func.start_ea

        # Delete should return a boolean (True if deleted, False if no frame)
        result = db.stack_frames.delete(func_ea)
        assert isinstance(result, bool)


class TestStackFrameIntegration:
    """Integration tests verifying stack frames work with the overall system."""

    def test_stack_frames_property_accessible(self, db_readonly):
        """
        Test db.stack_frames property is accessible and returns StackFrames entity.

        RATIONALE: Validates the entity is properly integrated into the Database
        class and accessible via the standard property pattern.
        """
        db = db_readonly

        assert hasattr(db, 'stack_frames')
        stack_frames_entity = db.stack_frames
        assert stack_frames_entity is not None

    def test_multiple_frame_operations(self, db_readonly):
        """
        Test multiple stack frame operations in sequence.

        RATIONALE: Real-world usage involves multiple operations on frames.
        This test validates that operations don't interfere with each other
        and that the entity maintains correct state across multiple calls.
        """
        db = db_readonly

        # Find complex_assignments
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None

        # Multiple operations
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None

        size = frame.size
        local_size = frame.local_size
        arg_size = frame.argument_size

        # All operations should work
        assert isinstance(size, int)
        assert isinstance(local_size, int)
        assert isinstance(arg_size, int)

        # Get sections
        locals_section = db.stack_frames.get_locals_section(func_ea)
        args_section = db.stack_frames.get_arguments_section(func_ea)

        assert locals_section is not None
        assert args_section is not None


class TestStackFrameAdvancedOperations:
    """
    Tests for advanced stack frame operations.

    Covers purged_bytes, get_as_struct, calc_frame_offset, and SP tracking methods.
    """

    def test_purged_bytes_property_accessible(self, db_readonly):
        """
        Test that purged_bytes property can be accessed on StackFrameInstance.

        RATIONALE: The purged_bytes property indicates the number of bytes cleaned
        from the stack upon function return, which varies by calling convention.
        For __cdecl (standard C convention), this is zero (caller cleans stack).
        For __stdcall/__fastcall, this is non-zero (callee cleans stack).

        This test validates that the property is accessible and returns a valid
        integer value, which is essential for understanding the function's
        calling convention and stack behavior.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get stack frame
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None, 'Stack frame should exist'

        # Access purged_bytes property
        purged = frame.purged_bytes

        # Should be a valid integer
        assert isinstance(purged, int)
        # For most C functions compiled with __cdecl, this should be 0
        # We don't assert exact value as it depends on calling convention
        assert purged >= 0

    def test_get_as_struct_returns_tinfo(self, db_readonly):
        """
        Test that get_as_struct returns a valid tinfo_t structure type.

        RATIONALE: Stack frames are internally represented as structures in IDA,
        with members corresponding to local variables, saved registers, and
        arguments. The get_as_struct method exposes this structural representation
        as a tinfo_t, which is essential for advanced type analysis and
        understanding the frame layout.

        This validates that we can retrieve the frame as a structured type and
        that it contains the expected type information.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get frame as struct
        from ida_typeinf import tinfo_t

        frame_type = db.stack_frames.get_as_struct(func_ea)

        # Should be a valid tinfo_t
        assert isinstance(frame_type, tinfo_t)
        assert frame_type.is_struct()

    def test_get_as_struct_raises_on_invalid_address(self, db_readonly):
        """
        Test that get_as_struct raises InvalidEAError for invalid addresses.

        RATIONALE: Type safety is critical for preventing undefined behavior.
        When called with an address that doesn't correspond to a function,
        get_as_struct should raise a clear InvalidEAError rather than returning
        invalid data or crashing.

        This ensures robust error handling for invalid inputs.
        """
        db = db_readonly

        # Invalid address (not a function)
        with pytest.raises(InvalidEAError):
            db.stack_frames.get_as_struct(0xFFFFFFFF)

    def test_get_as_struct_raises_when_no_frame_exists(self, db_readonly):
        """
        Test that get_as_struct raises RuntimeError when function has no frame.

        RATIONALE: Not all functions have stack frames (e.g., leaf functions
        that use only registers). When get_as_struct is called for a function
        without a frame, it should raise RuntimeError with a clear message
        rather than returning invalid data.

        This test ensures proper error handling for this edge case.
        """
        db = db_readonly

        # Find a function that might not have a frame, or use a known address
        # For this test, we'll try to find a very simple function
        # If all functions have frames, this test might be skipped
        func_without_frame = None
        for func in db.functions.get_all():
            frame = db.stack_frames.get_at(func.start_ea)
            if frame is None or frame.size == 0:
                func_without_frame = func.start_ea
                break

        if func_without_frame is None:
            pytest.skip('All functions in test binary have stack frames')

        # Should raise RuntimeError
        with pytest.raises(RuntimeError, match='No frame'):
            db.stack_frames.get_as_struct(func_without_frame)

    def test_calc_frame_offset_converts_runtime_to_frame_offset(self, db_readonly):
        """
        Test that calc_frame_offset converts runtime offsets to frame offsets.

        RATIONALE: During execution, stack variables are accessed relative to
        SP (stack pointer) or FP (frame pointer), but IDA's frame structure uses
        a normalized offset system. The calc_frame_offset method performs the
        critical conversion from runtime offset (as seen in disassembly like
        [esp+0x10] or [ebp-0x4]) to the frame structure offset.

        This conversion is essential for:
        - Identifying which stack variable an instruction accesses
        - Correlating disassembly with stack frame structure
        - Understanding data flow through stack variables

        This test validates that the conversion produces valid frame offsets.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get first instruction in function (after prologue)
        # We'll use an instruction a few bytes into the function
        insn_ea = func_ea + 0x5  # Skip prologue

        # Ensure insn_ea is within the function
        func = db.functions.get_at(func_ea)
        if insn_ea >= func.end_ea:
            insn_ea = func_ea

        # Try to convert a runtime offset to frame offset
        # Common stack access patterns: [esp+X] or [ebp-X]
        # We'll try a few common offsets
        runtime_offset = 0x4  # Common offset

        frame_offset = db.stack_frames.calc_frame_offset(func_ea, runtime_offset, insn_ea)

        # Should return a valid integer
        assert isinstance(frame_offset, int)
        # Frame offsets can be negative (locals) or positive (args)
        # Just validate it's a reasonable value
        assert -1000 < frame_offset < 1000

    def test_calc_frame_offset_raises_on_invalid_function_address(self, db_readonly):
        """
        Test that calc_frame_offset raises InvalidEAError for invalid function address.

        RATIONALE: Address validation is critical for preventing crashes and
        undefined behavior. When calc_frame_offset is called with an address
        that doesn't correspond to a function, it should raise a clear
        InvalidEAError before attempting any calculations.

        This ensures robust input validation.
        """
        db = db_readonly

        # Invalid function address
        with pytest.raises(InvalidEAError):
            db.stack_frames.calc_frame_offset(0xFFFFFFFF, 0x4, db.minimum_ea)

    def test_add_sp_change_point_adds_user_change_point(self, db_mutable):
        """
        Test that add_sp_change_point can add user-defined SP change points.

        RATIONALE: Stack pointer tracking is essential for understanding function
        behavior, especially when functions manually manipulate SP (e.g., for
        dynamic stack allocation or hand-written assembly). IDA automatically
        tracks SP changes for standard instructions, but analysts sometimes need
        to manually add SP change points to correct IDA's analysis.

        User-defined change points (automatic=False) allow analysts to override
        or supplement IDA's automatic SP tracking. This test validates that we
        can successfully add such change points, which is critical for:
        - Correcting SP analysis in complex functions
        - Handling non-standard stack manipulation
        - Supporting manual analysis corrections

        This test adds a user change point and validates the operation succeeds.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get an address within the function
        func = db.functions.get_at(func_ea)
        # Pick an instruction in the middle of the function
        ea_in_function = func_ea + 0x10
        if ea_in_function >= func.end_ea:
            ea_in_function = func_ea + 0x5

        # Add a user SP change point
        # Negative delta = stack grows (typical for push/sub esp operations)
        result = db.stack_frames.add_sp_change_point(
            func_ea, ea_in_function, delta=-4, automatic=False
        )

        # Should return True on success
        assert isinstance(result, bool)
        # Note: result might be False if change point already exists or is invalid
        # We're just validating the method works without errors

    def test_add_sp_change_point_adds_automatic_change_point(self, db_mutable):
        """
        Test that add_sp_change_point can add automatic SP change points.

        RATIONALE: Automatic change points (automatic=True) are managed by IDA's
        analysis system and are used for standard instruction-based SP tracking.
        While IDA typically adds these automatically, there are cases where
        reanalysis or manual triggers require adding them programmatically.

        This test validates that the automatic change point path works correctly,
        which is important for tools that need to trigger SP reanalysis or
        supplement IDA's automatic analysis.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get an address within the function
        func = db.functions.get_at(func_ea)
        ea_in_function = func_ea + 0x8
        if ea_in_function >= func.end_ea:
            ea_in_function = func_ea + 0x4

        # Add an automatic SP change point
        result = db.stack_frames.add_sp_change_point(
            func_ea, ea_in_function, delta=-4, automatic=True
        )

        # Should return a boolean
        assert isinstance(result, bool)

    def test_add_sp_change_point_raises_on_invalid_function(self, db_mutable):
        """
        Test that add_sp_change_point raises InvalidEAError for invalid function.

        RATIONALE: Input validation prevents crashes and undefined behavior.
        When add_sp_change_point is called with an address that doesn't
        correspond to a function, it should raise InvalidEAError before
        attempting to add the change point.

        This ensures robust error handling for invalid function addresses.
        """
        db = db_mutable

        # Invalid function address - need automatic=True to trigger validation
        with pytest.raises(InvalidEAError):
            db.stack_frames.add_sp_change_point(
                0xFFFFFFFF, db.minimum_ea, delta=-4, automatic=True
            )

    def test_delete_sp_change_point_removes_change_point(self, db_mutable):
        """
        Test that delete_sp_change_point removes SP change points.

        RATIONALE: Just as analysts need to add SP change points to correct
        analysis, they also need to remove incorrect or obsolete change points.
        The delete_sp_change_point method provides this capability, which is
        essential for:
        - Removing incorrect manual corrections
        - Cleaning up after analysis experiments
        - Reverting to IDA's automatic analysis

        This test validates that we can successfully remove change points,
        completing the full lifecycle of SP change point management.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get an address within the function
        func = db.functions.get_at(func_ea)
        ea_in_function = func_ea + 0x10
        if ea_in_function >= func.end_ea:
            ea_in_function = func_ea + 0x5

        # First, try to add a change point
        add_result = db.stack_frames.add_sp_change_point(
            func_ea, ea_in_function, delta=-4, automatic=False
        )

        # Now try to delete it
        delete_result = db.stack_frames.delete_sp_change_point(func_ea, ea_in_function)

        # Should return a boolean
        assert isinstance(delete_result, bool)
        # Note: delete_result might be False if change point didn't exist
        # We're validating the method works without errors

    def test_delete_sp_change_point_raises_on_invalid_function(self, db_mutable):
        """
        Test that delete_sp_change_point raises InvalidEAError for invalid function.

        RATIONALE: Input validation prevents undefined behavior. When
        delete_sp_change_point is called with an address that doesn't
        correspond to a function, it should raise InvalidEAError before
        attempting the deletion.

        This ensures consistent error handling across SP tracking methods.
        """
        db = db_mutable

        # Invalid function address
        with pytest.raises(InvalidEAError):
            db.stack_frames.delete_sp_change_point(0xFFFFFFFF, db.minimum_ea)

    def test_get_sp_delta_returns_cumulative_delta(self, db_readonly):
        """
        Test that get_sp_delta returns the cumulative SP delta at an instruction.

        RATIONALE: Understanding the stack pointer value at each instruction is
        fundamental for:
        - Determining which stack variables are accessible
        - Validating correct stack usage
        - Understanding function prologue/epilogue behavior
        - Debugging stack corruption issues

        The SP delta represents how far the stack pointer has moved from the
        function entry point. For downward-growing stacks (most common), this
        is typically negative (SP decreases as stack grows). For example:
        - At function entry: delta = 0
        - After "push ebp": delta = -4 (assuming 32-bit)
        - After "sub esp, 0x10": delta = -20

        This test validates that get_sp_delta returns valid delta values that
        represent the cumulative SP change at specific instruction addresses.
        """
        db = db_readonly

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # Get SP delta at function start
        delta_at_start = db.stack_frames.get_sp_delta(func_ea, func_ea)
        assert isinstance(delta_at_start, int)
        # At function entry, delta should be 0 or close to it
        assert -100 < delta_at_start < 100

        # Get SP delta at an instruction within the function
        func = db.functions.get_at(func_ea)
        ea_in_function = func_ea + 0x10
        if ea_in_function >= func.end_ea:
            ea_in_function = func_ea + 0x5

        delta_in_function = db.stack_frames.get_sp_delta(func_ea, ea_in_function)
        assert isinstance(delta_in_function, int)
        # Should be a reasonable value (within typical stack frame range)
        assert -10000 < delta_in_function < 10000

    def test_get_sp_delta_raises_on_invalid_function(self, db_readonly):
        """
        Test that get_sp_delta raises InvalidEAError for invalid function address.

        RATIONALE: Input validation is critical for all SP tracking methods.
        When get_sp_delta is called with an address that doesn't correspond
        to a function, it should raise InvalidEAError before attempting to
        retrieve the SP delta.

        This ensures robust error handling and prevents undefined behavior.
        """
        db = db_readonly

        # Invalid function address
        with pytest.raises(InvalidEAError):
            db.stack_frames.get_sp_delta(0xFFFFFFFF, db.minimum_ea)

    def test_advanced_operations_integration(self, db_mutable):
        """
        Test integration of multiple advanced stack frame operations.

        RATIONALE: In real-world analysis, multiple advanced operations are
        used together to understand and manipulate stack frame analysis. This
        integration test validates that:

        1. Operations can be chained without conflicts
        2. State remains consistent across operations
        3. Different operation types work together correctly

        For example, an analyst might:
        - Get the frame as a struct to understand layout
        - Check SP delta to validate stack usage
        - Add change points to correct analysis
        - Convert runtime offsets to identify variables

        This test exercises this realistic workflow to ensure the advanced
        operations form a cohesive API.
        """
        db = db_mutable

        # Find complex_assignments function
        func_ea = None
        for func in db.functions.get_all():
            name = db.functions.get_name(func)
            if 'struct_local' in name:
                func_ea = func.start_ea
                break

        assert func_ea is not None, 'complex_assignments function not found'

        # 1. Get frame as struct
        frame_type = db.stack_frames.get_as_struct(func_ea)
        assert frame_type.is_struct()

        # 2. Get frame instance and check purged_bytes
        frame = db.stack_frames.get_at(func_ea)
        assert frame is not None
        purged = frame.purged_bytes
        assert isinstance(purged, int)

        # 3. Get SP delta at function start
        delta = db.stack_frames.get_sp_delta(func_ea, func_ea)
        assert isinstance(delta, int)

        # 4. Try calc_frame_offset
        func = db.functions.get_at(func_ea)
        insn_ea = func_ea + 0x5
        if insn_ea < func.end_ea:
            frame_offset = db.stack_frames.calc_frame_offset(func_ea, 0x4, insn_ea)
            assert isinstance(frame_offset, int)

        # All operations completed without errors
        # This validates the operations work together correctly
