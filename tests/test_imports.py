import pytest

import ida_domain  # isort: skip
import ida_domain.imports


def test_imports(test_env):
    db = test_env
    import ida_domain.imports

    assert db.imports.get_module_count() == 0
    assert len(db.imports) == 0

    count = 0
    for _ in db.imports:
        count += 1
    assert count == 0

    assert list(db.imports.get_all_modules()) == []
    assert list(db.imports.get_all_imports()) == []
    assert list(db.imports.get_module_names()) == []
    assert list(db.imports.get_import_names()) == []
    assert list(db.imports.get_import_addresses()) == []
    assert db.imports.get_import_count() == 0

    assert db.imports.get_module_by_name('kernel32.dll') is None
    assert db.imports.get_import_by_name('kernel32.dll!CreateFileW') is None
    assert db.imports.get_import_by_name('kernel32.dll!#42') is None
    assert db.imports.get_import_by_name('CreateFileW') is None  # missing module prefix
    assert db.imports.get_import_at(0x1000) is None
    assert db.imports.exists('kernel32.dll!CreateFileW') is False

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(-1)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(0)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(999)

    with pytest.raises(IndexError):
        _ = db.imports[0]

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(-1))

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(0))

    imp_info = ida_domain.imports.ImportInfo(
        address=0x1000,
        name='TestFunc',
        ordinal=1,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_info.has_name() is True
    assert imp_info.address == 0x1000
    assert imp_info.name == 'TestFunc'
    assert imp_info.ordinal == 1
    assert imp_info.module_index == 0
    assert imp_info.module_name == 'test.dll'

    imp_ordinal_only = ida_domain.imports.ImportInfo(
        address=0x2000,
        name=None,
        ordinal=42,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_ordinal_only.has_name() is False

    imp_empty_name = ida_domain.imports.ImportInfo(
        address=0x3000,
        name='',
        ordinal=43,
        module_index=0,
        module_name='test.dll',
    )
    assert imp_empty_name.has_name() is False

    mod_info = ida_domain.imports.ImportModuleInfo(index=0, name='kernel32.dll')
    assert mod_info.index == 0
    assert mod_info.name == 'kernel32.dll'


def test_imports_populated(tiny_imports_env):
    """Test imports functionality with actual import data from a dynamically-linked binary."""
    db = tiny_imports_env
    import ida_domain.imports

    # Expected counts for tiny_imports.bin (libc-linked ELF64)
    # Module: .dynsym (IDA's representation of ELF dynamic symbols)
    # Imports: free, __libc_start_main, puts, malloc, exit, __gmon_start__
    expected_module_count = 1
    expected_import_count = 6

    # === Test module count and iteration ===
    module_count = db.imports.get_module_count()
    assert module_count == expected_module_count
    assert len(db.imports) == expected_module_count

    # Count via iteration
    iter_count = 0
    for _ in db.imports:
        iter_count += 1
    assert iter_count == expected_module_count

    # === Test get_all_modules() ===
    modules = list(db.imports.get_all_modules())
    assert len(modules) == expected_module_count

    # All modules should have valid index and non-empty name
    for module in modules:
        assert isinstance(module, ida_domain.imports.ImportModuleInfo)
        assert module.index >= 0
        assert module.index < module_count
        assert len(module.name) > 0

    # === Test get_module_at_index() and __getitem__ ===
    first_module = db.imports.get_module_at_index(0)
    assert first_module is not None
    assert first_module.index == 0

    # Same via subscript
    first_module_sub = db.imports[0]
    assert first_module_sub.index == first_module.index
    assert first_module_sub.name == first_module.name

    # Test last valid index
    last_module = db.imports.get_module_at_index(module_count - 1)
    assert last_module is not None
    assert last_module.index == module_count - 1

    # === Test get_module_by_name() - case insensitive ===
    # Use the first module (for ELF files, IDA uses '.dynsym' as the module name)
    test_module = first_module
    assert test_module is not None

    # Test exact name
    found = db.imports.get_module_by_name(test_module.name)
    assert found is not None
    assert found.name == test_module.name

    # Test case-insensitive
    found_upper = db.imports.get_module_by_name(test_module.name.upper())
    assert found_upper is not None
    assert found_upper.name == test_module.name

    # Test non-existent module
    assert db.imports.get_module_by_name('nonexistent_module.dll') is None

    # === Test get_module_names() ===
    module_names = list(db.imports.get_module_names())
    assert len(module_names) == expected_module_count
    for name in module_names:
        assert isinstance(name, str)
        assert len(name) > 0

    # === Test get_all_imports() ===
    all_imports = list(db.imports.get_all_imports())
    assert len(all_imports) == expected_import_count

    # Verify ImportInfo structure
    for imp in all_imports:
        assert isinstance(imp, ida_domain.imports.ImportInfo)
        assert imp.module_index >= 0
        assert imp.module_index < module_count
        assert len(imp.module_name) > 0
        # Address should be valid (not 0 for real imports in IAT)
        assert imp.address != 0

    # === Test get_import_count() ===
    import_count = db.imports.get_import_count()
    assert import_count == expected_import_count

    # === Test get_imports_for_module() ===
    total_from_modules = 0
    for module in modules:
        module_imports = list(db.imports.get_imports_for_module(module.index))
        total_from_modules += len(module_imports)
        # Each import should belong to this module
        for imp in module_imports:
            assert imp.module_index == module.index
            assert imp.module_name == module.name
    assert total_from_modules == expected_import_count

    # === Test get_import_names() - qualified format ===
    import_names = list(db.imports.get_import_names())
    assert len(import_names) == expected_import_count

    for name in import_names:
        assert '!' in name, "Import names should be in 'module!symbol' format"
        parts = name.split('!')
        assert len(parts) == 2
        assert len(parts[0]) > 0  # module name
        assert len(parts[1]) > 0  # symbol name or ordinal

    # === Test get_import_addresses() ===
    addresses = list(db.imports.get_import_addresses())
    assert len(addresses) == expected_import_count

    # All addresses should be unique
    unique_addresses = set(addresses)
    assert len(unique_addresses) == len(addresses), 'Import addresses should be unique'

    # === Test get_import_by_name() - find known imports ===
    # Look for common libc imports. ELF import names include version suffix
    # (e.g., malloc@@GLIBC_2.2.5)
    known_imports = ['malloc', 'free', 'puts', 'exit']
    found_any = False

    for imp in all_imports:
        # Check if import name starts with any known import
        # (handles version suffixes like @@GLIBC_2.2.5)
        if imp.name:
            for known in known_imports:
                if imp.name.startswith(known):
                    # Test exact qualified name lookup
                    qualified = f'{imp.module_name}!{imp.name}'
                    found = db.imports.get_import_by_name(qualified)
                    assert found is not None, f'Should find import by qualified name: {qualified}'
                    assert found.name == imp.name
                    assert found.module_name == imp.module_name
                    assert found.address == imp.address

                    # Test case-insensitive lookup
                    found_upper = db.imports.get_import_by_name(qualified.upper())
                    assert found_upper is not None
                    assert found_upper.address == imp.address

                    found_any = True
                    break

    assert found_any, 'Should find at least one known import'

    # Test non-existent import
    assert db.imports.get_import_by_name('.dynsym!nonexistent_function') is None

    # Test invalid format (missing module prefix)
    assert db.imports.get_import_by_name('malloc') is None

    # === Test get_import_at() ===
    # Use first import's address
    first_import = all_imports[0]
    found_at = db.imports.get_import_at(first_import.address)
    assert found_at is not None
    assert found_at.address == first_import.address
    assert found_at.name == first_import.name

    # Test non-existent address
    assert db.imports.get_import_at(0xDEADBEEF) is None

    # === Test exists() ===
    if first_import.name:
        qualified = f'{first_import.module_name}!{first_import.name}'
        assert db.imports.exists(qualified) is True

    assert db.imports.exists('nonexistent.dll!fake_function') is False

    # === Test ImportInfo.has_name() ===
    for imp in all_imports:
        if imp.name and len(imp.name) > 0:
            assert imp.has_name() is True
        else:
            assert imp.has_name() is False

    # === Test IndexError for out of bounds ===
    with pytest.raises(IndexError):
        db.imports.get_module_at_index(-1)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(module_count)

    with pytest.raises(IndexError):
        db.imports.get_module_at_index(module_count + 100)

    with pytest.raises(IndexError):
        _ = db.imports[module_count]

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(-1))

    with pytest.raises(IndexError):
        list(db.imports.get_imports_for_module(module_count))
