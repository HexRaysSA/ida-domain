"""
Example 7: Adding Annotations

This script renames functions and adds comments
based on our analysis findings.
"""

from ida_domain import Database


def main():
    with Database() as db:
        print("Adding annotations based on analysis...")
        print("=" * 60)

        # Strategy: Use string references to identify function purposes
        function_hints = {
            "License Valid": "check_license",
            "License Invalid": "show_error",
            "Trial Mode": "check_trial",
            "/etc/machine-id": "get_machine_id",
        }

        # Track functions we've identified
        identified_functions = {}

        # 1. Find functions by string usage
        print("\n1. Identifying functions by string references")
        print("-" * 40)

        for hint_string, suggested_name in function_hints.items():
            for s in db.strings:
                if hint_string in s.content:
                    for xref in db.xrefs.to_ea(s.ea):
                        func = db.functions.get_at(xref.from_ea)
                        if func and func.start_ea not in identified_functions:
                            old_name = func.name
                            identified_functions[func.start_ea] = suggested_name
                            print(f"  {old_name} -> {suggested_name}")
                            print(f"    (references '{hint_string}')")
                    break

        # 2. Apply function renames
        print("\n2. Renaming functions")
        print("-" * 40)

        for func_ea, new_name in identified_functions.items():
            try:
                db.names.set_name(func_ea, new_name)
                print(f"  0x{func_ea:08x} renamed to '{new_name}'")
            except Exception as e:
                print(f"  0x{func_ea:08x} rename failed: {e}")

        # 3. Try to identify main by call pattern
        print("\n3. Looking for main function")
        print("-" * 40)

        # Main typically calls our identified functions
        if identified_functions:
            for func in db.functions:
                calls_identified = 0
                for xref in db.xrefs.from_ea(func.start_ea):
                    if xref.is_call and xref.to_ea in identified_functions:
                        calls_identified += 1

                if calls_identified >= 2:
                    try:
                        db.names.set_name(func.start_ea, "main")
                        print(f"  0x{func.start_ea:08x} appears to be main")
                        print(f"    (calls {calls_identified} identified functions)")
                    except Exception:
                        pass
                    break

        # 4. Add comments at key locations
        print("\n4. Adding comments")
        print("-" * 40)

        comments_to_add = []

        # Comment string references
        for s in db.strings:
            if any(
                kw in s.content.lower()
                for kw in ["license", "trial", "machine-id", "expired"]
            ):
                for xref in db.xrefs.to_ea(s.ea):
                    comment = f"References: {s.content!r}"
                    comments_to_add.append((xref.from_ea, comment))

        # Comment function entry points
        for func_ea, func_purpose in identified_functions.items():
            comment = f"Purpose: {func_purpose.replace('_', ' ').title()}"
            comments_to_add.append((func_ea, comment))

        # Apply comments
        for addr, comment in comments_to_add:
            try:
                existing = db.comments.get_comment(addr)
                if not existing:
                    db.comments.set_comment(addr, comment)
                    print(f"  0x{addr:08x}: {comment}")
            except Exception as e:
                print(f"  0x{addr:08x}: failed - {e}")

        # 5. Summary
        print("\n" + "=" * 60)
        print("ANNOTATION SUMMARY")
        print("-" * 40)
        print(f"Functions renamed: {len(identified_functions)}")
        print(f"Comments added:    {len(comments_to_add)}")

        print("\nUpdated function list:")
        for func in db.functions:
            if not func.name.startswith("sub_"):
                print(f"  0x{func.start_ea:08x}: {func.name}")


if __name__ == "__main__":
    main()
