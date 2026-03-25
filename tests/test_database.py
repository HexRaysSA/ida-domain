import conftest

import ida_domain  # isort: skip

from ida_domain.database import IdaCommandOptions


def test_database(test_env):
    db = test_env
    db.close(False)
    assert db.is_open() is False
    db = ida_domain.Database.open(conftest.idb_path)
    assert db.is_open() is True

    db.current_ea = 0x50
    assert db.current_ea == 0x50

    assert db.minimum_ea == 0x0
    assert db.maximum_ea == 0x420

    assert db.base_address == 0x0
    assert db.module == 'tiny_asm.bin'
    assert db.filesize == 3680
    assert db.md5 == 'f53ff12139b2cf71703222e79cfe0b9b'
    assert db.sha256 == '03858ca230c1755b1db18c4051c348de5b4b274ff0489ea14237f56a9f9adf30'
    assert db.crc32 == 404194086
    assert db.architecture == 'metapc'
    assert db.bitness == 64
    assert db.format == 'ELF64 for x86-64 (Relocatable)'

    metadata = db.metadata
    from dataclasses import fields

    assert len(fields(metadata)) == 13

    assert 'tiny_asm.bin' in metadata.path
    assert metadata.module == 'tiny_asm.bin'
    assert metadata.base_address == 0x0
    assert metadata.filesize == 0xE60
    assert metadata.md5 == 'f53ff12139b2cf71703222e79cfe0b9b'
    assert metadata.sha256 == '03858ca230c1755b1db18c4051c348de5b4b274ff0489ea14237f56a9f9adf30'
    assert metadata.crc32 == 0x18178326
    assert metadata.architecture == 'metapc'
    assert metadata.bitness == 0x40
    assert metadata.format == 'ELF64 for x86-64 (Relocatable)'
    assert len(metadata.load_time) == 19  # dummy check, expect "YYYY-MM-DD HH:MM:SS"
    assert metadata.execution_mode == 'User Mode'
    assert metadata.compiler_information == (
        'Name: GNU C++, sizes in bits: '
        '(byte: 8, short: 16, enum: 32, int: 32, long: 64, double: 128, long_long: 64)'
    )

    compiler_info = db.compiler_information
    assert compiler_info.name == 'GNU C++'
    assert compiler_info.byte_size_bits == 8
    assert compiler_info.short_size_bits == 16
    assert compiler_info.enum_size_bits == 32
    assert compiler_info.int_size_bits == 32
    assert compiler_info.long_size_bits == 64
    assert compiler_info.double_size_bits == 128
    assert compiler_info.long_long_size_bits == 64

    assert db.execution_mode == ida_domain.database.ExecutionMode.User
    db.close(False)

    # Test context manager protocol
    with ida_domain.Database.open(conftest.idb_path, save_on_close=False) as db2:
        assert db2.is_open()
        func = db2.functions.get_at(0x2A3)
        assert func is not None
        assert func.start_ea == 0x2A3
        assert db2.functions.set_name(func, 'testing_function_rename')
        assert func.name == 'testing_function_rename'
    # The database should be close automatically
    assert not db2.is_open()

    # Reopen it and check the rename was discarded due to save_on_close=False
    db2 = ida_domain.Database.open(conftest.idb_path, save_on_close=False)
    assert db2.is_open()
    func = db2.functions.get_at(0x2A3)
    assert func is not None
    assert func.start_ea == 0x2A3
    assert func.name == 'add_numbers'
    db2.close(False)

    with ida_domain.Database.open(conftest.idb_path, save_on_close=True) as db3:
        assert db3.is_open()
        func = db3.functions.get_at(0x2A3)
        assert func is not None
        assert func.start_ea == 0x2A3
        assert db3.functions.set_name(func, 'testing_function_rename')
        assert func.name == 'testing_function_rename'

    # The database should be close automatically
    assert not db3.is_open()
    # Reopen it and check the rename was preserved due to save_on_close=True
    db3 = ida_domain.Database.open(conftest.idb_path, save_on_close=False)
    assert db3.is_open()
    func = db3.functions.get_at(0x2A3)
    assert func is not None
    assert func.start_ea == 0x2A3
    assert func.name == 'testing_function_rename'
    db3.close(False)


def test_ida_command_options():
    # Test default state produces empty args
    opts = IdaCommandOptions()
    assert opts.build_args() == ''

    # Test auto analysis option
    opts = IdaCommandOptions(auto_analysis=True)
    assert opts.build_args() == ''

    opts = IdaCommandOptions(auto_analysis=False)
    assert opts.build_args() == '-a'

    # Test loading address option
    opts = IdaCommandOptions(loading_address=0x1000)
    assert opts.build_args() == '-b1000'

    # Test new database option
    opts = IdaCommandOptions(new_database=True)
    assert opts.build_args() == '-c'

    # Test compiler option
    opts = IdaCommandOptions(compiler='gcc')
    assert opts.build_args() == '-Cgcc'

    opts = IdaCommandOptions(compiler='gcc:x64')
    assert opts.build_args() == '-Cgcc:x64'

    # Test first pass directive option
    opts = IdaCommandOptions(first_pass_directives=['VPAGESIZE=8192'])
    assert opts.build_args() == '-dVPAGESIZE=8192'

    # Add multiple directives
    opts = IdaCommandOptions(first_pass_directives=['DIR1', 'DIR2'])
    assert opts.build_args() == '-dDIR1 -dDIR2'

    # Test second pass directive option
    opts = IdaCommandOptions(second_pass_directives=['OPTION=VALUE'])
    assert opts.build_args() == '-DOPTION=VALUE'

    # Test disable FPP instructions option
    opts = IdaCommandOptions(disable_fpp=True)
    assert opts.build_args() == '-f'

    # Test entry point option
    opts = IdaCommandOptions(entry_point=0x401000)
    assert opts.build_args() == '-i401000'

    # Test JIT debugger option
    opts = IdaCommandOptions(jit_debugger=True)
    assert opts.build_args() == '-I1'

    opts = IdaCommandOptions(jit_debugger=False)
    assert opts.build_args() == '-I0'

    # Test log file option
    opts = IdaCommandOptions(log_file='debug.log')
    assert opts.build_args() == '-Ldebug.log'

    # Test disable mouse option
    opts = IdaCommandOptions(disable_mouse=True)
    assert opts.build_args() == '-M'

    # Test plugin options
    opts = IdaCommandOptions(plugin_options='opt1=val1')
    assert opts.build_args() == '-Oopt1=val1'

    # Test output database option (should also set -c flag)
    opts = IdaCommandOptions(output_database='output.idb')
    assert opts.build_args() == '-c -ooutput.idb'

    # Test processor option
    opts = IdaCommandOptions(processor='arm')
    assert opts.build_args() == '-parm'

    # Test database compression options
    opts = IdaCommandOptions(db_compression='compress')
    assert opts.build_args() == '-P+'

    opts = IdaCommandOptions(db_compression='pack')
    assert opts.build_args() == '-P'

    opts = IdaCommandOptions(db_compression='no_pack')
    assert opts.build_args() == '-P-'

    # Test run debugger option
    opts = IdaCommandOptions(run_debugger='+')
    assert opts.build_args() == '-r+'

    opts = IdaCommandOptions(run_debugger='debug-options')
    assert opts.build_args() == '-rdebug-options'

    # Test load resources option
    opts = IdaCommandOptions(load_resources=True)
    assert opts.build_args() == '-R'

    # Test run script option
    opts = IdaCommandOptions(script_file='analyze.py')
    assert opts.build_args() == '-Sanalyze.py'

    args = ['arg1', 'arg with spaces', '--flag=value']
    opts = IdaCommandOptions(script_file='script.py', script_args=args)
    assert opts.build_args() == '-S"script.py arg1 "arg with spaces" --flag=value"'

    # Test file type option
    opts = IdaCommandOptions(file_type='PE')
    assert opts.build_args() == '-TPE'

    opts = IdaCommandOptions(file_type='ZIP', file_member='classes.dex')
    assert opts.build_args() == '-TZIP:classes.dex'

    # Test empty database option
    opts = IdaCommandOptions(empty_database=True)
    assert opts.build_args() == '-t'

    # Test Windows directory option
    opts = IdaCommandOptions(windows_dir='C:\\Windows')
    assert opts.build_args() == '-WC:\\Windows'

    # Test no segmentation option
    opts = IdaCommandOptions(no_segmentation=True)
    assert opts.build_args() == '-x'

    # Test debug flags option
    # Test with numeric flags
    opts = IdaCommandOptions(debug_flags=0x404)
    assert opts.build_args() == '-z404'

    # Test with named flags
    flags = ['flirt', 'type_system']
    opts = IdaCommandOptions(debug_flags=flags)
    assert opts.build_args() == '-z4004'

    # Test combined options (no chaining, just set fields)
    opts = IdaCommandOptions(auto_analysis=False, log_file='analysis.log', processor='arm')
    args = opts.build_args()
    assert args == '-a -Lanalysis.log -parm'

    # Test complex scenario
    opts = IdaCommandOptions(
        new_database=True,
        compiler='gcc:x64',
        processor='arm',
        script_file='analyze.py',
        script_args=['deep', '--verbose'],
    )
    args = opts.build_args()
    assert args == '-c -Cgcc:x64 -parm -S"analyze.py deep --verbose"'

    # Test another complex scenario
    opts = IdaCommandOptions(
        output_database='project.idb',
        db_compression='compress',
        file_type='ZIP',
        file_member='classes.dex',
        debug_flags=0x10004,  # debugger + flirt
    )
    args = opts.build_args()
    assert args == '-c -oproject.idb -P+ -TZIP:classes.dex -z10004'

    # Test default for auto_analysis is True
    opts = IdaCommandOptions()
    assert opts.auto_analysis
    opts = IdaCommandOptions(auto_analysis=False)
    assert not opts.auto_analysis
