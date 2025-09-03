"""
This is equivalent of create_libssh2_til.py from IDAPython examples
Original: https://github.com/idapython/src/blob/master/examples/types/create_libssh2_til.py
"""

from pathlib import Path

import ida_domain
import ida_domain.types

db = ida_domain.Database.open()

libssh2_types = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef __int64 size_t;

struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
{
    unsigned char *text;
    size_t length;
    unsigned char echo;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_PROMPT LIBSSH2_USERAUTH_KBDINT_PROMPT;

struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
{
    char *text;
    unsigned int length;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE LIBSSH2_USERAUTH_KBDINT_RESPONSE;

struct _LIBSSH2_SK_SIG_INFO {
    uint8_t flags;
    uint32_t counter;
    unsigned char *sig_r;
    size_t sig_r_len;
    unsigned char *sig_s;
    size_t sig_s_len;
};
typedef struct _LIBSSH2_SK_SIG_INFO LIBSSH2_SK_SIG_INFO;

"""


def create_libssh2_til():
    # Create a new til file
    til = db.types.create_library(Path('libssh2-64'), 'Some libssh2 types')

    # Parse the declarations
    errors = db.types.parse_declarations(
        til,
        libssh2_types,
        (
            ida_domain.types.TypeFormattingFlags.HTI_DCL
            | ida_domain.types.TypeFormattingFlags.HTI_PAKDEF
        ),
    )

    if errors != 0:
        raise Exception(f'Failed to parse the libssh2 declarations. {errors} errors\n')

    return til


til = create_libssh2_til()

print('Created type library with the following types')
for tif in db.types.get_all(library=til):
    print(f'\t{tif.get_type_name()}')

# Save the til file
if db.types.save_library(til, Path('libssh2-64.til')):
    print('TIL file stored on disk.\n')

# Unload the library
db.types.unload_library(til)
