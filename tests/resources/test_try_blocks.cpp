/**
 * Test binary for TryBlocks entity.
 * Contains C++ exception handling patterns.
 *
 * Compile: zig c++ -target x86_64-linux-gnu -O0 -fexceptions -o test_try_blocks.bin test_try_blocks.cpp
 */

#include <stdexcept>
#include <cstdio>

volatile int sink;

// Custom exception classes for type-specific catching
class CustomException {
public:
    int code;
    CustomException(int c) : code(c) {}
};

class DerivedExceptionA : public CustomException {
public:
    DerivedExceptionA(int c) : CustomException(c) {}
};

class DerivedExceptionB : public CustomException {
public:
    DerivedExceptionB(int c) : CustomException(c) {}
};

// Simple try-catch with single handler
int simple_try_catch(int x) {
    try {
        if (x < 0) {
            throw std::runtime_error("negative value");
        }
        return x * 2;
    } catch (const std::exception& e) {
        return -1;
    }
}

// Multiple catch handlers
int multiple_catch(int x) {
    try {
        if (x == 0) {
            throw std::invalid_argument("zero");
        } else if (x < 0) {
            throw std::out_of_range("negative");
        } else if (x > 100) {
            throw std::runtime_error("too large");
        }
        return x;
    } catch (const std::invalid_argument& e) {
        return -1;
    } catch (const std::out_of_range& e) {
        return -2;
    } catch (const std::runtime_error& e) {
        return -3;
    }
}

// Catch-all handler
int catch_all(int x) {
    try {
        if (x < 0) {
            throw CustomException(x);
        } else if (x == 0) {
            throw 42;  // throw int
        }
        return x;
    } catch (...) {
        return -1;
    }
}

// Nested try-catch blocks
int nested_try(int x, int y) {
    try {
        try {
            if (x < 0) {
                throw std::runtime_error("x negative");
            }
            if (y < 0) {
                throw std::invalid_argument("y negative");
            }
            return x + y;
        } catch (const std::invalid_argument& e) {
            // Handle inner exception
            return -1;
        }
    } catch (const std::runtime_error& e) {
        // Handle outer exception
        return -2;
    }
}

// Re-throwing exceptions
int rethrow_example(int x) {
    try {
        try {
            if (x < 0) {
                throw CustomException(x);
            }
            return x;
        } catch (const CustomException& e) {
            sink = e.code;
            throw;  // rethrow
        }
    } catch (const CustomException& e) {
        return e.code;
    }
}

// Exception with cleanup (RAII simulation via catch)
class Resource {
public:
    int id;
    Resource(int i) : id(i) { sink = id; }
    ~Resource() { sink = -id; }
};

int exception_with_cleanup(int x) {
    try {
        Resource r(x);
        if (x < 0) {
            throw std::runtime_error("cleanup test");
        }
        return r.id * 2;
    } catch (const std::exception& e) {
        return -1;
    }
}

// Custom exception hierarchy catching
int custom_exception_hierarchy(int x) {
    try {
        if (x == 1) {
            throw DerivedExceptionA(100);
        } else if (x == 2) {
            throw DerivedExceptionB(200);
        } else if (x == 3) {
            throw CustomException(300);
        }
        return 0;
    } catch (const DerivedExceptionA& e) {
        return e.code + 1;
    } catch (const DerivedExceptionB& e) {
        return e.code + 2;
    } catch (const CustomException& e) {
        return e.code + 3;
    }
}

// Function that always throws
[[noreturn]] void always_throws(int x) {
    throw CustomException(x);
}

// Catch exception from called function
int catch_from_callee(int x) {
    try {
        always_throws(x);
    } catch (const CustomException& e) {
        return e.code;
    }
    return 0;  // unreachable
}

// Exception specification (noexcept)
int noexcept_function(int x) noexcept {
    // This won't throw - if it does, std::terminate is called
    return x * 2;
}

int call_noexcept(int x) {
    try {
        return noexcept_function(x);
    } catch (...) {
        return -1;
    }
}

int main(int argc, char **argv) {
    sink = simple_try_catch(argc);
    sink = multiple_catch(argc);
    sink = catch_all(argc);
    sink = nested_try(argc, argc - 1);
    sink = rethrow_example(argc);
    sink = exception_with_cleanup(argc);
    sink = custom_exception_hierarchy(argc);
    sink = catch_from_callee(argc);
    sink = call_noexcept(argc);

    return 0;
}
