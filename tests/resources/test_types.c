/**
 * Test binary for Types entity.
 * Contains various type definitions and usages.
 *
 * Compile: zig cc -target x86_64-linux-gnu -O0 -g -o test_types.bin test_types.c
 * Note: -g adds debug info which helps IDA extract type information.
 */

#include <stdint.h>
#include <stddef.h>

volatile int64_t sink;

// ============================================================================
// Basic type aliases
// ============================================================================

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef uint64_t       u64;

typedef signed char  s8;
typedef signed short s16;
typedef signed int   s32;
typedef int64_t      s64;

// ============================================================================
// Enums
// ============================================================================

typedef enum {
    COLOR_RED   = 0,
    COLOR_GREEN = 1,
    COLOR_BLUE  = 2,
    COLOR_ALPHA = 3
} ColorChannel;

typedef enum {
    STATE_IDLE    = 0x00,
    STATE_RUNNING = 0x01,
    STATE_PAUSED  = 0x02,
    STATE_STOPPED = 0x04,
    STATE_ERROR   = 0x80
} ProcessState;

// Enum with explicit values and gaps
typedef enum {
    ERR_OK         = 0,
    ERR_NOT_FOUND  = -1,
    ERR_INVALID    = -2,
    ERR_NO_MEMORY  = -100,
    ERR_IO         = -200,
    ERR_TIMEOUT    = -300
} ErrorCode;

// ============================================================================
// Structs
// ============================================================================

// Simple struct
typedef struct {
    int x;
    int y;
} Point2D;

// Struct with various member types
typedef struct {
    u8  flags;
    u16 id;
    u32 count;
    u64 timestamp;
    char name[32];
} Record;

// Struct with padding
typedef struct {
    char  a;     // offset 0
    // 3 bytes padding
    int   b;     // offset 4
    char  c;     // offset 8
    // 7 bytes padding
    double d;    // offset 16
} PaddedStruct;

// Packed struct (no padding)
typedef struct __attribute__((packed)) {
    char  a;
    int   b;
    char  c;
    double d;
} PackedStruct;

// Nested struct
typedef struct {
    Point2D position;
    Point2D velocity;
    int mass;
} PhysicsBody;

// Self-referential struct (linked list)
typedef struct Node {
    int value;
    struct Node *next;
    struct Node *prev;
} Node;

// Struct with function pointer
typedef int (*Callback)(int, int);

typedef struct {
    int id;
    Callback handler;
    void *user_data;
} EventHandler;

// ============================================================================
// Unions
// ============================================================================

typedef union {
    u32 as_u32;
    float as_float;
    u8 bytes[4];
} FloatBits;

typedef union {
    u64 as_u64;
    double as_double;
    u8 bytes[8];
    struct {
        u32 lo;
        u32 hi;
    } parts;
} DoubleBits;

// Tagged union (discriminated union)
typedef enum {
    VALUE_INT,
    VALUE_FLOAT,
    VALUE_STRING,
    VALUE_POINTER
} ValueType;

typedef struct {
    ValueType type;
    union {
        int64_t as_int;
        double as_float;
        char as_string[24];
        void *as_ptr;
    } data;
} TaggedValue;

// ============================================================================
// Complex nested types
// ============================================================================

typedef struct {
    char name[64];
    u32 age;
    struct {
        char street[128];
        char city[64];
        char country[32];
        u32 zip;
    } address;
    struct {
        char number[16];
        char type[16];
    } phones[4];
    u32 phone_count;
} Person;

// ============================================================================
// Bitfields
// ============================================================================

typedef struct {
    u32 flag_a : 1;
    u32 flag_b : 1;
    u32 flag_c : 1;
    u32 reserved : 5;
    u32 value : 8;
    u32 count : 16;
} BitfieldStruct;

typedef struct {
    u64 enabled : 1;
    u64 mode : 3;
    u64 priority : 4;
    u64 id : 24;
    u64 timestamp : 32;
} BitfieldStruct64;

// ============================================================================
// Arrays
// ============================================================================

typedef int IntArray16[16];
typedef Point2D PointArray8[8];
typedef char StringBuffer[256];

typedef struct {
    int matrix[4][4];
} Matrix4x4;

// ============================================================================
// Function pointer types
// ============================================================================

typedef void (*VoidFunc)(void);
typedef int (*IntFunc)(int);
typedef int (*BinaryFunc)(int, int);
typedef void *(*AllocFunc)(size_t);
typedef void (*FreeFunc)(void *);

typedef struct {
    AllocFunc alloc;
    FreeFunc free;
    void *context;
} Allocator;

// ============================================================================
// Functions that use these types
// ============================================================================

int use_enum(ColorChannel channel) {
    switch (channel) {
        case COLOR_RED:   return 0xFF0000;
        case COLOR_GREEN: return 0x00FF00;
        case COLOR_BLUE:  return 0x0000FF;
        case COLOR_ALPHA: return 0xFFFFFF;
        default:          return 0;
    }
}

ErrorCode process_state(ProcessState state) {
    if (state & STATE_ERROR) {
        return ERR_INVALID;
    }
    if (state == STATE_IDLE) {
        return ERR_OK;
    }
    return ERR_NOT_FOUND;
}

int use_point(Point2D p) {
    return p.x + p.y;
}

int use_record(Record *r) {
    if (!r) return -1;
    r->count++;
    r->timestamp = 12345;
    return r->id;
}

int check_padding(void) {
    PaddedStruct ps;
    PackedStruct pk;

    sink = sizeof(ps);  // Should be 24 (with padding)
    sink = sizeof(pk);  // Should be 14 (packed)

    sink = offsetof(PaddedStruct, d);  // Should be 16
    sink = offsetof(PackedStruct, d);  // Should be 6

    return sizeof(ps) - sizeof(pk);
}

int use_nested_struct(PhysicsBody *body) {
    if (!body) return 0;
    return body->position.x + body->position.y +
           body->velocity.x + body->velocity.y +
           body->mass;
}

int list_sum(Node *head) {
    int sum = 0;
    Node *current = head;
    while (current) {
        sum += current->value;
        current = current->next;
    }
    return sum;
}

int use_callback(EventHandler *handler, int a, int b) {
    if (handler && handler->handler) {
        return handler->handler(a, b);
    }
    return -1;
}

float use_float_union(u32 bits) {
    FloatBits fb;
    fb.as_u32 = bits;
    return fb.as_float;
}

u32 use_double_union(double value) {
    DoubleBits db;
    db.as_double = value;
    return db.parts.hi ^ db.parts.lo;
}

int64_t use_tagged_value(TaggedValue *tv) {
    if (!tv) return 0;
    switch (tv->type) {
        case VALUE_INT:
            return tv->data.as_int;
        case VALUE_FLOAT:
            return (int64_t)tv->data.as_float;
        case VALUE_STRING:
            return tv->data.as_string[0];
        case VALUE_POINTER:
            return (int64_t)(intptr_t)tv->data.as_ptr;
        default:
            return -1;
    }
}

int use_person(Person *p) {
    if (!p) return 0;
    return p->age + p->address.zip + p->phone_count;
}

u32 use_bitfield(BitfieldStruct *bf) {
    if (!bf) return 0;
    bf->flag_a = 1;
    bf->flag_b = 0;
    bf->value = 0x42;
    bf->count = 1000;
    return bf->value + bf->count;
}

int use_matrix(Matrix4x4 *m) {
    if (!m) return 0;
    int sum = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sum += m->matrix[i][j];
        }
    }
    return sum;
}

int use_allocator(Allocator *alloc, size_t size) {
    if (!alloc || !alloc->alloc || !alloc->free) return 0;

    void *p = alloc->alloc(size);
    if (p) {
        alloc->free(p);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    sink = use_enum(COLOR_RED);
    sink = process_state(STATE_RUNNING);

    Point2D pt = {10, 20};
    sink = use_point(pt);

    Record rec = {0};
    sink = use_record(&rec);

    sink = check_padding();

    PhysicsBody body = {{0, 0}, {1, 1}, 100};
    sink = use_nested_struct(&body);

    Node n1 = {1, NULL, NULL};
    Node n2 = {2, NULL, &n1};
    n1.next = &n2;
    sink = list_sum(&n1);

    sink = use_float_union(0x40490FDB);  // ~3.14159
    sink = use_double_union(3.14159);

    TaggedValue tv = {VALUE_INT, {.as_int = 42}};
    sink = use_tagged_value(&tv);

    BitfieldStruct bf = {0};
    sink = use_bitfield(&bf);

    Matrix4x4 m = {{{1, 0, 0, 0}, {0, 1, 0, 0}, {0, 0, 1, 0}, {0, 0, 0, 1}}};
    sink = use_matrix(&m);

    return 0;
}
