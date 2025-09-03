"""
This is equivalent of log_idb_events.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/log_idb_events.py
"""

import inspect

import ida_domain


class IdbLogger(ida_domain.hooks.DatabaseHooks):
    def __init__(self):
        ida_domain.hooks.DatabaseHooks.__init__(self)
        self.inhibit_log = 0

    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(f'>>> {msg}')
            else:
                # Auto-log from caller
                frame = inspect.currentframe().f_back
                func_name = frame.f_code.co_name
                args = inspect.getargvalues(frame)
                arg_strs = [f'{a}={args.locals[a]}' for a in args.args[1:]]
                print(f'>>> {func_name}: {", ".join(arg_strs)}')
        return 0

    # Domain API hooks
    def closebase(self):
        return self._log()

    def savebase(self):
        return self._log()

    def auto_empty(self):
        return self._log()

    def auto_empty_finally(self):
        return self._log()

    def renamed(self, ea, new_name, is_local_name, old_name):
        return self._log()

    def func_added(self, pfn):
        return self._log()

    def deleting_func(self, pfn):
        return self._log()

    def func_updated(self, pfn):
        return self._log()

    def bookmark_changed(self, index, pos, desc, op):
        print(f'>>> [Legacy] bookmark_changed: {index}, {desc}')
        return 0

    def frame_created(self, func_ea):
        print(f'>>> [Legacy] frame_created: 0x{func_ea:x}')
        return 0

    def struc_member_changed(self, sptr, mptr):
        print(f'>>> [Legacy] struc_member_changed')
        return 0


# Install both hooks
db = ida_domain.Database.open()
domain_logger = IdbLogger()
domain_logger.hook()

print('IDB event loggers installed (Domain + Legacy)')
