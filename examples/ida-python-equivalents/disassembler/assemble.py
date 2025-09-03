"""
This is equivalent of assemble.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/assemble.py
"""

import ida_domain

# Open current database
db = ida_domain.Database.open()


class AssembleHook(ida_domain.hooks.ProcessorHooks):
    def ev_assemble(self, ea, cs, ip, use32, line):
        line = line.strip()
        if line == 'zero eax':
            return b'\x33\xc0'
        elif line == 'nothing':
            # Get current instruction to figure out its size
            insn = db.instructions.get_instruction_at(ea)
            if insn:
                # NOP all the instruction bytes
                return b'\x90' * insn.size
        return None


# Remove an existing hook on second run
try:
    print('IDP hook: checking for hook...')
    idphook
    print('IDP hook: unhooking....')
    idphook.unhook()
    del idphook
    idp_hook_stat = 'un'
except:
    print('IDP hook: not installed, installing now....')
    idp_hook_stat = ''
    idphook = AssembleHook()
    idphook.hook()

print(f'IDP hook {idp_hook_stat}installed. Run the script again to {idp_hook_stat}install')
