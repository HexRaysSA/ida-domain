/**
 * Test binary for StackFrames entity.
 * Contains functions with various stack frame layouts.
 *
 * Compile: zig cc -target x86_64-linux-gnu -O0 -g -o test_stack_frames.bin test_stack_frames.c
 * Note: -O0 preserves stack frame structure, -g adds debug info.
 */

#include <stdint.h>
#include <string.h>

volatile int64_t sink;

// Simple function with few locals
int simple_locals(int a, int b) {
    int x = a + b;
    int y = a - b;
    return x * y;
}

// Many arguments (some on stack in x86_64 ABI after 6th arg)
int many_arguments(int a, int b, int c, int d, int e, int f, int g, int h) {
    return a + b + c + d + e + f + g + h;
}

// Large local array
int large_array(int n) {
    int arr[256];
    for (int i = 0; i < 256 && i < n; i++) {
        arr[i] = i * i;
    }
    int sum = 0;
    for (int i = 0; i < 256 && i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

// Mixed types in locals
int64_t mixed_types(int a) {
    int8_t  b8  = (int8_t)a;
    int16_t b16 = (int16_t)a;
    int32_t b32 = (int32_t)a;
    int64_t b64 = (int64_t)a;

    float  f32 = (float)a;
    double f64 = (double)a;

    return b8 + b16 + b32 + b64 + (int64_t)f32 + (int64_t)f64;
}

// Struct as local variable
typedef struct {
    int x;
    int y;
    int z;
    char name[32];
} Point3D;

int struct_local(int a, int b, int c, const char *name) {
    Point3D pt;
    pt.x = a;
    pt.y = b;
    pt.z = c;

    if (name) {
        strncpy(pt.name, name, sizeof(pt.name) - 1);
        pt.name[sizeof(pt.name) - 1] = '\0';
    }

    return pt.x + pt.y + pt.z;
}

// Nested structs
typedef struct {
    Point3D start;
    Point3D end;
    int color;
} Line3D;

int nested_struct_local(int x1, int y1, int z1, int x2, int y2, int z2) {
    Line3D line;
    line.start.x = x1;
    line.start.y = y1;
    line.start.z = z1;
    line.end.x = x2;
    line.end.y = y2;
    line.end.z = z2;
    line.color = 0xFF0000;

    return (line.end.x - line.start.x) +
           (line.end.y - line.start.y) +
           (line.end.z - line.start.z);
}

// Pointer arguments
int pointer_args(int *a, int *b, int *result) {
    if (a && b && result) {
        *result = *a + *b;
        return 1;
    }
    return 0;
}

// Array of structs
int array_of_structs(int count) {
    Point3D points[16];

    for (int i = 0; i < 16 && i < count; i++) {
        points[i].x = i;
        points[i].y = i * 2;
        points[i].z = i * 3;
        points[i].name[0] = 'A' + i;
        points[i].name[1] = '\0';
    }

    int sum = 0;
    for (int i = 0; i < 16 && i < count; i++) {
        sum += points[i].x + points[i].y + points[i].z;
    }
    return sum;
}

// Variable length array simulation (alloca-like behavior)
int variable_frame(int n) {
    // Use a fixed max but access based on n
    int buffer[64];
    int count = (n < 64) ? n : 64;

    for (int i = 0; i < count; i++) {
        buffer[i] = i;
    }

    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += buffer[i];
    }
    return sum;
}

// Recursive function with stack frames
int factorial(int n) {
    if (n <= 1) return 1;
    int result = n * factorial(n - 1);
    return result;
}

// Deep nesting with many locals at each level
int deep_nesting(int depth) {
    if (depth <= 0) return 0;

    int local1 = depth;
    int local2 = depth * 2;
    int local3 = depth * 3;
    char buffer[16];
    buffer[0] = 'A' + (depth % 26);

    int nested_result = deep_nesting(depth - 1);
    return local1 + local2 + local3 + nested_result;
}

// Leaf function (no calls, may be optimized differently)
int leaf_function(int a, int b, int c, int d) {
    int sum = a + b + c + d;
    int product = a * b * c * d;
    return sum + product;
}

// Saved registers test (use many registers)
int64_t many_registers(int64_t a, int64_t b, int64_t c, int64_t d,
                       int64_t e, int64_t f) {
    int64_t r1 = a + b;
    int64_t r2 = c + d;
    int64_t r3 = e + f;
    int64_t r4 = r1 * r2;
    int64_t r5 = r2 * r3;
    int64_t r6 = r1 + r3;
    int64_t r7 = r4 - r5;
    int64_t r8 = r6 * r7;

    sink = r8;  // Force use of all values

    return r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
}

int main(int argc, char **argv) {
    sink = simple_locals(argc, argc + 1);
    sink = many_arguments(1, 2, 3, 4, 5, 6, 7, 8);
    sink = large_array(argc * 10);
    sink = mixed_types(argc);
    sink = struct_local(1, 2, 3, "test");
    sink = nested_struct_local(0, 0, 0, 10, 10, 10);

    int a = 5, b = 3, result;
    sink = pointer_args(&a, &b, &result);

    sink = array_of_structs(argc);
    sink = variable_frame(argc * 8);
    sink = factorial(10);
    sink = deep_nesting(5);
    sink = leaf_function(1, 2, 3, 4);
    sink = many_registers(1, 2, 3, 4, 5, 6);

    return 0;
}
