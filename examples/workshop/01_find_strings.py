"""
Example 1: Finding Interesting Strings

This script demonstrates how to use the Domain API to find
license-related strings in the binary.

This is our first entry point into the analysis.
"""

from ida_domain import Database


def main():
    with Database() as db:
        # Count total strings
        all_strings = list(db.strings)
        print(f"Found {len(all_strings)} strings\n")

        # Define keywords to search for
        keywords = ["license", "trial", "valid", "invalid", "expired", "mode"]

        print("License-related strings:")
        print("-" * 50)

        for s in db.strings:
            content_lower = s.content.lower()
            if any(kw in content_lower for kw in keywords):
                print(f"0x{s.ea:08x}: {s.content!r}")
                print(f"           Length: {s.length}, Type: {s.string_type}")
                print()


if __name__ == "__main__":
    main()
