#!/usr/bin/env python3
"""
Event handling / hook usage example for IDA Domain API.

This example demonstrates how to handle IDA events.
"""

import argparse
import logging

from ida_domain import database, hooks  # isort: skip
import ida_idaapi  # isort: skip

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')


# Processor hooks example
class MyProcHooks(hooks.ProcessorHooks):
    def __init__(self):
        super().__init__()

    def ev_creating_segm(self, seg: 'segment_t *') -> int:
        self.log()
        return super().ev_creating_segm(seg)

    def ev_moving_segm(self, seg: 'segment_t *', to: ida_idaapi.ea_t, flags: int) -> int:
        self.log()
        return super().ev_moving_segm(seg, to, flags)


# UI hooks example
class MyUIHooks(hooks.UIHooks):
    def __init__(self):
        super().__init__()

    def widget_visible(self, widget: 'TWidget *') -> None:
        self.log()

    def widget_closing(self, widget: 'TWidget *') -> None:
        self.log()

    def widget_invisible(self, widget: 'TWidget *') -> None:
        self.log()


# View hooks example
class MyViewHooks(hooks.ViewHooks):
    def __init__(self):
        super().__init__()

    def view_activated(self, view: 'TWidget *') -> None:
        self.log()

    def view_deactivated(self, view: 'TWidget *') -> None:
        self.log()


# Decompiler hooks example
class MyDecompilerHooks(hooks.DecompilerHooks):
    def __init__(self):
        super().__init__()

    def open_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().open_pseudocode(vu)

    def switch_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().switch_pseudocode(vu)

    def refresh_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().refresh_pseudocode(vu)

    def close_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().close_pseudocode(vu)


# Database hooks example
class MyDatabaseHooks(hooks.DatabaseHooks):
    def __init__(self):
        super().__init__()
        self.count = 0

    def closebase(self) -> None:
        self.log()

    def auto_empty(self):
        self.log()

    def segm_added(self, s) -> None:
        self.log()


proc_hook = MyProcHooks()
ui_hook = MyUIHooks()
view_hook = MyViewHooks()
decomp_hook = MyDecompilerHooks()
db_hook = MyDatabaseHooks()

all_hooks: hooks.HooksList = [
    proc_hook,
    ui_hook,
    view_hook,
    decomp_hook,
    db_hook,
]


def log_events(idb_path):
    with database.Database.open(path=idb_path, hooks=all_hooks) as db:
        pass


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    log_events(args.input_file)


if __name__ == '__main__':
    main()
