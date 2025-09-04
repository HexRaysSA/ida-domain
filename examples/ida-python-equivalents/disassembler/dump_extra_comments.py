"""
This is equivalent of dump_extra_comments.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/disassembler/dump_extra_comments.py
NOTE: Partially migrated - uses IDA Domain for comments, legacy API for UI actions
"""

import ida_domain  # isort: skip
import ida_kernwin


def dump_extra_comments_at_current_ea(anchor):
    """Dump extra comments using IDA Domain API"""
    db = ida_domain.Database.open()

    # Map legacy anchor values to Domain API
    kind = ida_domain.comments.ExtraCommentKind(anchor)

    # Get all extra comments
    comments = list(db.comments.get_extra_all(db.current_ea, kind))
    if comments:
        for i, comment in enumerate(comments):
            print(f"Got [{i}]: '{comment}'")
    else:
        print(f'No {kind.value} comments at 0x{db.current_ea:x}')


# Action handler - minimal legacy code for UI integration
class dump_at_point_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, anchor):
        ida_kernwin.action_handler_t.__init__(self)
        self.anchor = anchor

    def activate(self, ctx):
        dump_extra_comments_at_current_ea(self.anchor)
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == ida_kernwin.BWN_DISASM
            else ida_kernwin.AST_DISABLE_FOR_WIDGET
        )


# Register actions
for label, shortcut, anchor in [
    ('previous', 'Ctrl+Shift+Y', ida_domain.comments.ExtraCommentKind.ANTERIOR.value),
    ('next', 'Ctrl+Shift+Z', ida_domain.comments.ExtraCommentKind.POSTERIOR.value),
]:
    actname = f'dump_extra_comments:{label}'
    if ida_kernwin.unregister_action(actname):
        print(f"Unregistered previous '{actname}'")

    desc = ida_kernwin.action_desc_t(
        actname, f'Dump {label} extra comments', dump_at_point_handler_t(anchor), shortcut
    )

    if ida_kernwin.register_action(desc):
        print(f"Registered action '{actname}' with shortcut {shortcut}")
