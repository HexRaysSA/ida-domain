"""
Example 5: Analyzing Control Flow

This script examines basic blocks and branch points
within the validation function.
"""

from ida_domain import Database


def analyze_function_flow(db, func):
    """Analyze the control flow of a function."""
    print(f"Control flow analysis of {func.name}")
    print(f"  Address range: 0x{func.start_ea:08x} - 0x{func.end_ea:08x}")
    print("=" * 60)

    # Get the flowchart (basic blocks)
    flowchart = db.functions.get_flowchart(func)

    print(f"\nBasic blocks: {len(flowchart)}")
    print("-" * 40)

    conditional_branches = []

    for i, block in enumerate(flowchart):
        block_size = block.end_ea - block.start_ea
        successors = list(block.succs())
        predecessors = list(block.preds())

        print(f"\nBlock {i}:")
        print(f"  Range: 0x{block.start_ea:08x} - 0x{block.end_ea:08x}")
        print(f"  Size:  {block_size} bytes")
        print(f"  Predecessors: {len(predecessors)}")
        print(f"  Successors:   {len(successors)}")

        # Identify block type
        if len(successors) == 0:
            print("  Type: Exit block (function return)")
        elif len(successors) == 1:
            print(f"  Type: Sequential flow -> 0x{successors[0].start_ea:08x}")
        elif len(successors) == 2:
            print("  Type: CONDITIONAL BRANCH")
            print(f"    True branch:  -> 0x{successors[0].start_ea:08x}")
            print(f"    False branch: -> 0x{successors[1].start_ea:08x}")
            conditional_branches.append(block)
        else:
            print(f"  Type: Multi-way branch ({len(successors)} targets)")

    # Summary of decision points
    print("\n" + "=" * 60)
    print(f"DECISION POINTS FOUND: {len(conditional_branches)}")
    print("-" * 40)

    for block in conditional_branches:
        # The branch instruction is at the end of the block
        branch_addr = block.end_ea - 1  # Approximate
        print(f"  Branch at ~0x{branch_addr:08x}")
        print(f"    (Block 0x{block.start_ea:08x} - 0x{block.end_ea:08x})")


def main():
    with Database() as db:
        # Find the function that references "License Invalid"
        target_func = None

        for s in db.strings:
            if s.content == "License Invalid":
                for xref in db.xrefs.to_ea(s.ea):
                    target_func = db.functions.get_at(xref.from_ea)
                    if target_func:
                        break
                break

        if target_func:
            analyze_function_flow(db, target_func)

            # Also analyze functions it calls
            print("\n\nAnalyzing called functions:")
            print("=" * 60)

            analyzed = {target_func.start_ea}
            for xref in db.xrefs.from_ea(target_func.start_ea):
                if xref.is_call and xref.to_ea not in analyzed:
                    called_func = db.functions.get_at(xref.to_ea)
                    if called_func:
                        analyzed.add(xref.to_ea)
                        print(f"\n\n>>> {called_func.name}")
                        analyze_function_flow(db, called_func)
        else:
            print("Could not find target function. Analyzing all functions:")
            for func in db.functions:
                analyze_function_flow(db, func)
                print("\n")


if __name__ == "__main__":
    main()
