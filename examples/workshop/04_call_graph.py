"""
Example 4: Building a Call Graph

This script analyzes function call relationships,
helping us understand the program structure.
"""

from ida_domain import Database


def get_function_callers(db, func_ea):
    """Get all functions that call the given function."""
    callers = []
    for xref in db.xrefs.calls_to_ea(func_ea):
        caller_func = db.functions.get_at(xref.from_ea)
        if caller_func:
            callers.append((caller_func, xref.from_ea))
    return callers


def get_function_callees(db, func):
    """Get all functions called by the given function."""
    callees = []
    # Iterate through all xrefs originating from within this function
    for xref in db.xrefs.from_ea(func.start_ea):
        if xref.is_call:
            callee_func = db.functions.get_at(xref.to_ea)
            if callee_func:
                callees.append((callee_func, xref.from_ea))
    return callees


def build_call_tree(db, start_ea, depth=0, max_depth=3, visited=None):
    """Recursively build and print a call tree."""
    if visited is None:
        visited = set()

    if depth > max_depth or start_ea in visited:
        return

    visited.add(start_ea)
    func = db.functions.get_at(start_ea)
    if not func:
        return

    indent = "  " * depth
    connector = "├── " if depth > 0 else ""
    print(f"{indent}{connector}{func.name} (0x{start_ea:08x})")

    # Find all functions this one calls
    for xref in db.xrefs.from_ea(func.start_ea):
        if xref.is_call and xref.to_ea not in visited:
            build_call_tree(db, xref.to_ea, depth + 1, max_depth, visited)


def main():
    with Database() as db:
        # Find the main function (or entry point)
        # In a stripped binary, we look for the function that references our strings
        main_candidate = None

        for s in db.strings:
            if "License" in s.content:
                for xref in db.xrefs.to_ea(s.ea):
                    func = db.functions.get_at(xref.from_ea)
                    if func:
                        # Find who calls this function
                        callers = get_function_callers(db, func.start_ea)
                        for caller, _ in callers:
                            # The caller is probably main or close to it
                            main_candidate = caller
                            break
                    break
                break

        if main_candidate:
            print("Call hierarchy (starting from suspected main):")
            print("=" * 50)
            build_call_tree(db, main_candidate.start_ea)
        else:
            # Fall back to entry point
            print("Call hierarchy from entry point:")
            print("=" * 50)
            for func in db.functions:
                if "start" in func.name.lower():
                    build_call_tree(db, func.start_ea)
                    break

        # Also show reverse: who calls each function
        print("\n\nReverse call graph (who calls what):")
        print("=" * 50)

        for func in db.functions:
            callers = get_function_callers(db, func.start_ea)
            if callers:
                print(f"\n{func.name} is called by:")
                for caller, call_site in callers:
                    print(f"  {caller.name} @ 0x{call_site:08x}")


if __name__ == "__main__":
    main()
