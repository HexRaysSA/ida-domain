import logging

from packaging.version import Version

import ida_domain  # isort: skip
import conftest
from ida_segment import segment_t

from ida_domain import hooks

logger = logging.getLogger(__name__)


def test_hooks():


    class TestProcHooks(hooks.ProcessorHooks):
        def __init__(self):
            super().__init__()

    class TestUIHooks(hooks.UIHooks):
        def __init__(self):
            super().__init__()

    class TestViewHooks(hooks.ViewHooks):
        def __init__(self):
            super().__init__()

    class TestDecompHooks(hooks.DecompilerHooks):
        def __init__(self):
            super().__init__()

    class TestDatabaseHooks(hooks.DatabaseHooks):
        def __init__(self):
            super().__init__()
            self.count = 0

        def closebase(self) -> None:
            self.log()
            self.count += 1
            assert self.m_database.is_open()

        def auto_empty(self):
            self.log()
            self.count += 1
            assert self.m_database.is_open()

        def segm_added(self, s: segment_t) -> None:
            self.log()
            assert self.m_database.is_open()
            name = self.m_database.segments.get_name(s)
            assert name
            logger.info(f'added segment: {name}')

    proc_hook = TestProcHooks()
    ui_hook = TestUIHooks()
    view_hook = TestViewHooks()
    decomp_hook = TestDecompHooks()
    custom_hook1 = TestDatabaseHooks()
    custom_hook2 = TestDatabaseHooks()

    all_hooks: hooks.HooksList = [
        proc_hook,
        ui_hook,
        view_hook,
        decomp_hook,
        custom_hook1,
        custom_hook2,
    ]
    # Check hooks are automatically installed (hooked) and called if passed to open()
    with ida_domain.Database.open(path=conftest.idb_path, hooks=all_hooks) as db:
        assert db.is_open()
        for h in db.hooks:
            assert h.is_hooked

    # Check hooks are automatically uninstalled (un-hooked)
    for h in all_hooks:
        assert not h.is_hooked

    assert custom_hook1.count == 2
    assert custom_hook2.count == 2

    # Check hooks are no longer called if not passed to open()
    with ida_domain.Database.open(path=conftest.idb_path) as db:
        assert db.is_open()
        assert not db.hooks
        for h in db.hooks:
            assert not h.is_hooked

    assert custom_hook1.count == 2
    assert custom_hook2.count == 2

    # Check no hooks are installed if open() fails
    if ida_domain.__ida_version__ >= Version('9.2'):
        # This does not pass prior 9.2.0 due to IDA killing the process
        # when trying to load an inexisting file
        try:
            with ida_domain.Database.open(path='invalid', hooks=all_hooks) as _:
                assert False
        except Exception as _:
            for h in all_hooks:
                assert not h.is_hooked
