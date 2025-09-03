"""
This is equivalent of automatic_steps.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/debugger/automatic_steps.py
NOTE: Partially migrated - uses Domain hooks with legacy debugger control
"""

import ida_domain  # isort: skip
import ida_dbg
import ida_lines


class MyDebugHook(ida_domain.hooks.DebuggerHooks):
    def __init__(self):
        super().__init__()
        self.steps = 0

    def log(self, msg):
        print(f'>>> {msg}')

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.log(f'Process started, pid={pid} name={name}')

    def dbg_process_exit(self, pid, tid, ea, code):
        self.log(f'Process exited pid={pid} code={code}')

    def dbg_step_over(self):
        eip = ida_dbg.get_reg_val('EIP')
        disasm = ida_lines.tag_remove(ida_lines.generate_disasm_line(eip))
        self.log(f'Step over: EIP=0x{eip:x}, {disasm}')

        self.steps += 1
        if self.steps >= 5:
            ida_dbg.request_exit_process()
        else:
            ida_dbg.request_step_over()

    def dbg_run_to(self, pid, tid=0, ea=0):
        self.log(f'Run to: ea=0x{ea:x}')
        ida_dbg.request_step_over()


# Install hook and run
hook = MyDebugHook()
hook.hook()

db = ida_domain.Database.open()
ep = db.start_ip
if ida_dbg.request_run_to(ep):
    ida_dbg.run_requests()
else:
    print('Cannot start debugger - is a debugger selected?')
