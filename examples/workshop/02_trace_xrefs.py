"""
Example 2: Tracing String References

This script finds cross-references to license-related strings,
showing us what code uses these strings.
"""

from ida_domain import Database


def main():
    with Database() as db:
        # Find strings we care about
        target_strings = []
        for s in db.strings:
            if any(
                kw in s.content.lower()
                for kw in ["license invalid", "license valid", "trial mode", "expired"]
            ):
                target_strings.append(s)

        print(f"Found {len(target_strings)} target strings\n")

        # Trace references to each string
        for s in target_strings:
            print(f"String: {s.content!r}")
            print(f"  Address: 0x{s.ea:08x}")
            print("  Referenced by:")

            refs = list(db.xrefs.to_ea(s.ea))
            if not refs:
                print("    (no references found)")
            else:
                for xref in refs:
                    print(f"    0x{xref.from_ea:08x} (type: {xref.type.name})")

            print()


if __name__ == "__main__":
    main()
