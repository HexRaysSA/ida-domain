from ida_domain.names import DemangleFlags, SetNameFlags


def test_names(test_env):
    db = test_env

    assert db.names.get_count() == 28
    assert len(db.names) == 28

    expected_names = [
        (0x0, '_start'),
        (0xC4, 'test_all_operand_types'),
        (0x272, 'skip_jumps'),
        (0x2A3, 'add_numbers'),
        (0x2AF, 'multiply_numbers'),
        (0x2BC, 'print_number'),
        (0x2D0, 'print_number.print_digit'),
        (0x2F7, 'level1_func'),
        (0x307, 'level2_func_a'),
        (0x312, 'level2_func_b'),
        (0x31D, 'level3_func'),
        (0x330, 'test_data'),
        (0x338, 'test_array'),
        (0x378, 'temp_float'),
        (0x37C, 'temp_double'),
        (0x390, 'vector_data'),
        (0x3A0, 'src_string'),
        (0x3B3, 'dst_string'),
        (0x3D4, 'hello'),
        (0x3E1, 'sum_str'),
        (0x3E6, 'product_str'),
        (0x3EF, 'newline'),
        (0x3F0, 'float_val'),
        (0x3F4, 'double_val'),
        (0x400, 'hello_len'),
        (0x408, 'sum_len'),
        (0x410, 'product_len'),
        (0x418, 'newline_len'),
    ]

    for i, (expected_addr, expected_name) in enumerate(expected_names):
        nameAndAddress = db.names.get_at_index(i)
        assert nameAndAddress[0] == expected_addr, (
            f'Name address mismatch at index {i}, {hex(nameAndAddress[0])} != {hex(expected_addr)}'
        )
        assert nameAndAddress[1] == expected_name, (
            f'Name mismatch at index {i}, {nameAndAddress[1]} != {expected_name}'
        )

        nameAndAddress = db.names[i]
        assert nameAndAddress[0] == expected_addr, (
            f'Name address mismatch at index {i}, {hex(nameAndAddress[0])} != {hex(expected_addr)}'
        )
        assert nameAndAddress[1] == expected_name, (
            f'Name mismatch at index {i}, {nameAndAddress[1]} != {expected_name}'
        )

    for i, (addr, name) in enumerate(db.names):
        assert addr == expected_names[i][0]
        assert name == expected_names[i][1]

    name = db.names.get_at(0x0)
    assert name == '_start'

    name = db.names.get_at(0x418)
    assert name == 'newline_len'

    assert db.names.get_at(db.minimum_ea) == '_start'

    from ida_domain.names import DemangleFlags, SetNameFlags

    test_addr = 0x418
    success = db.names.set_name(test_addr, 'test_name', SetNameFlags.NOCHECK)
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'test_name'

    success = db.names.set_name(
        test_addr, 'test_name_public', SetNameFlags.PUBLIC | SetNameFlags.NOCHECK
    )
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'test_name_public'

    success = db.names.force_name(
        test_addr, 'forced_name', SetNameFlags.FORCE | SetNameFlags.NOCHECK
    )
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == 'forced_name'

    success = db.names.delete(test_addr)
    assert isinstance(success, bool) and success
    assert db.names.get_at(test_addr) == ''  # Should be empty after deletion

    assert db.names.is_valid_name('valid_name') is True
    assert db.names.is_valid_name('123invalid') is False  # Names can't start with numbers
    assert db.names.is_valid_name('') is False  # Empty names are invalid

    test_addr = 0x330  # Use test_data address

    original_public = db.names.is_public_name(test_addr)
    assert not original_public
    db.names.make_name_public(test_addr)
    assert db.names.is_public_name(test_addr) is True
    db.names.make_name_non_public(test_addr)
    assert db.names.is_public_name(test_addr) is False

    original_weak = db.names.is_weak_name(test_addr)
    assert not original_weak

    db.names.make_name_weak(test_addr)
    assert db.names.is_weak_name(test_addr) is True
    db.names.make_name_non_weak(test_addr)
    assert db.names.is_weak_name(test_addr) is False

    demangled = db.names.get_demangled_name(0x2A3)  # add_numbers function
    assert isinstance(demangled, str)
    assert demangled == 'add_numbers'

    # Test demangle_name method with a known mangled name pattern
    mangled_name = '_Z3fooi'  # Simple C++ mangled name
    demangled = db.names.demangle_name(mangled_name)
    assert isinstance(demangled, str)
    assert demangled == 'foo(int)'

    # Test demangle_name with non-mangled name (should return original)
    normal_name = 'normal_function_name'
    result = db.names.demangle_name(normal_name, DemangleFlags.DEFNONE)
    assert result is None

    assert db.names.delete(test_addr)
