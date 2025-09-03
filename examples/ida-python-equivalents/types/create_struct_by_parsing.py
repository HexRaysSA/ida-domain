"""
This is equivalent of create_struct_by_parsing.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/types/create_struct_by_parsing.py
"""

import ida_domain

db = ida_domain.Database.open()

# Create a struct with parsing
struct_name = 'pcap_hdr_s'
struct_str = """
typedef int int32_t;
typedef unsigned int uint32_t;

struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};
"""

# Parse the structure declaration into the local type library
result = db.types.parse_declarations(None, struct_str)
if result == 0:
    print(f"Successfully created structure '{struct_name}' in local types")
else:
    print(f'Failed to parse structure declaration, {result} errors')
