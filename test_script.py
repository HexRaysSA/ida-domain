#!/usr/bin/env python3
"""Simple IDA Python SDK test script"""

import idaapi  # noqa: I001
import idc

def main():
    print("IDA Python Script Test")
    print("-" * 40)

    # Get IDA version
    version = idaapi.get_kernel_version()
    print(f"IDA Version: {version}")

    # Get number of segments
    num_segments = idaapi.get_segm_qty()
    print(f"Number of segments: {num_segments}")

    # Get number of functions
    num_functions = idaapi.get_func_qty()
    print(f"Number of functions: {num_functions}")

    # List first 5 functions
    print("\nFirst 5 functions:")
    for i in range(min(5, num_functions)):
        func = idaapi.getn_func(i)
        if func:
            func_name = idc.get_func_name(func.start_ea)
            print(f"  {hex(func.start_ea)}: {func_name}")

    print("\nScript completed successfully!")

if __name__ == "__main__":
    main()
