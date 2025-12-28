"""
Example 8: Automated Analysis Report

This script combines all previous techniques to generate
a comprehensive analysis report.
"""

from datetime import datetime

from ida_domain import Database


def generate_report(db):
    """Generate a complete analysis report."""
    lines = []

    def add(text=""):
        lines.append(text)

    def add_header(text):
        add()
        add("=" * 60)
        add(text)
        add("=" * 60)

    def add_section(text):
        add()
        add(text)
        add("-" * 40)

    # Header
    add_header("LICENSE CHECKER BINARY ANALYSIS REPORT")
    add(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"Database:  {db.path}")

    # Summary statistics
    add_header("1. BINARY OVERVIEW")

    funcs = list(db.functions)
    strings = list(db.strings)

    add(f"Address range: 0x{db.minimum_ea:08x} - 0x{db.maximum_ea:08x}")
    add(f"Total functions: {len(funcs)}")
    add(f"Total strings: {len(strings)}")

    # Function size distribution
    sizes = [f.end_ea - f.start_ea for f in funcs]
    if sizes:
        add(f"Largest function: {max(sizes)} bytes")
        add(f"Smallest function: {min(sizes)} bytes")
        add(f"Average function size: {sum(sizes) // len(sizes)} bytes")

    # String analysis
    add_header("2. STRING ANALYSIS")

    add_section("License-related strings")
    license_strings = []
    for s in strings:
        content_lower = s.content.lower()
        if any(kw in content_lower for kw in ["license", "trial", "valid", "invalid"]):
            license_strings.append(s)
            add(f"  0x{s.ea:08x}: {s.content!r}")

    add_section("Path/file strings")
    for s in strings:
        if "/" in s.content or "\\" in s.content:
            add(f"  0x{s.ea:08x}: {s.content!r}")

    # Cross-reference analysis
    add_header("3. CROSS-REFERENCE ANALYSIS")

    add_section("String usage in code")
    string_to_funcs = {}
    for s in license_strings:
        for xref in db.xrefs.to_ea(s.ea):
            func = db.functions.get_at(xref.from_ea)
            if func:
                if s.content not in string_to_funcs:
                    string_to_funcs[s.content] = []
                string_to_funcs[s.content].append(func)

    for string_content, funcs_using in string_to_funcs.items():
        add(f"  '{string_content}':")
        for f in funcs_using:
            add(f"    -> {f.name} (0x{f.start_ea:08x})")

    # Function analysis
    add_header("4. FUNCTION ANALYSIS")

    add_section("Functions by purpose (inferred)")

    # Categorize functions
    categories = {
        "likely_main": [],
        "validation": [],
        "utility": [],
        "unknown": [],
    }

    for func in db.functions:
        # Check what strings this function references
        refs_license = False
        refs_trial = False
        refs_path = False

        for xref in db.xrefs.from_ea(func.start_ea):
            for s in strings:
                if s.ea == xref.to_ea:
                    if "license" in s.content.lower():
                        refs_license = True
                    if "trial" in s.content.lower():
                        refs_trial = True
                    if "/" in s.content:
                        refs_path = True

        # Categorize based on behavior
        if refs_license and refs_trial:
            categories["likely_main"].append(func)
        elif refs_license or refs_trial:
            categories["validation"].append(func)
        elif refs_path:
            categories["utility"].append(func)
        else:
            categories["unknown"].append(func)

    for category, funcs_list in categories.items():
        if funcs_list:
            add(f"\n  {category.upper()}:")
            for f in funcs_list:
                size = f.end_ea - f.start_ea
                add(f"    {f.name}: 0x{f.start_ea:08x} ({size} bytes)")

    # Control flow summary
    add_header("5. CONTROL FLOW SUMMARY")

    add_section("Functions with conditional branches")
    for func in db.functions:
        try:
            flowchart = db.functions.get_flowchart(func)
            branch_count = sum(1 for b in flowchart if len(list(b.succs())) == 2)
            if branch_count > 0:
                add(f"  {func.name}: {branch_count} branch point(s)")
        except Exception:
            pass

    # Critical findings
    add_header("6. CRITICAL FINDINGS")

    add_section("Key decision points")
    for func in categories.get("validation", []) + categories.get("likely_main", []):
        try:
            flowchart = db.functions.get_flowchart(func)
            for block in flowchart:
                succs = list(block.succs())
                if len(succs) == 2:
                    add(f"  Branch in {func.name}:")
                    add(f"    Block: 0x{block.start_ea:08x} - 0x{block.end_ea:08x}")
                    add(f"    True:  -> 0x{succs[0].start_ea:08x}")
                    add(f"    False: -> 0x{succs[1].start_ea:08x}")
        except Exception:
            pass

    add_section("Recommendations")
    add("  1. Focus analysis on functions in 'validation' category")
    add("  2. Examine branch conditions in identified decision points")
    add("  3. Look for XOR/hash constants in utility functions")
    add("  4. Trace data flow from machine-id to validation check")

    # Footer
    add()
    add("=" * 60)
    add("END OF REPORT")
    add("=" * 60)

    return "\n".join(lines)


def main():
    with Database() as db:
        report = generate_report(db)

        # Print to console
        print(report)

        # Save to file
        report_path = "/tmp/license_checker_analysis.txt"
        with open(report_path, "w") as f:
            f.write(report)

        print(f"\n\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
