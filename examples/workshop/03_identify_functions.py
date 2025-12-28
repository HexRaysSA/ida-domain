"""
Example 3: Mapping Addresses to Functions

This script takes the addresses we found from xrefs
and identifies which functions contain them.
"""

from ida_domain import Database


def main():
    with Database() as db:
        # First, find string xrefs (repeating from example 2)
        code_addresses = set()

        for s in db.strings:
            if any(
                kw in s.content.lower()
                for kw in ["license invalid", "license valid", "trial mode"]
            ):
                for xref in db.xrefs.to_ea(s.ea):
                    code_addresses.add(xref.from_ea)

        print(f"Found {len(code_addresses)} code locations referencing license strings\n")

        # Map each address to its containing function
        print("Functions containing license logic:")
        print("-" * 60)

        seen_functions = set()

        for addr in sorted(code_addresses):
            func = db.functions.get_at(addr)

            if func and func.start_ea not in seen_functions:
                seen_functions.add(func.start_ea)

                size = func.end_ea - func.start_ea
                print(f"{func.name}")
                print(f"  Start: 0x{func.start_ea:08x}")
                print(f"  End:   0x{func.end_ea:08x}")
                print(f"  Size:  {size} bytes")
                print()

        # Also list all functions for context
        print("\nAll functions in binary:")
        print("-" * 60)
        for func in db.functions:
            print(f"  0x{func.start_ea:08x}: {func.name}")


if __name__ == "__main__":
    main()
