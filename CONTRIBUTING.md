# Contributing to IDA Domain

Thank you for your interest in contributing to IDA Domain! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to support@hex-rays.com.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Your environment (OS, Python version, IDA version, ida-domain version)
- Any relevant log output or error messages
- Sample binary or code that reproduces the issue (if applicable)

### Suggesting Features

Feature requests are welcome! Please provide:

- A clear and descriptive title
- A detailed description of the proposed feature
- Use cases and motivation for the feature
- Any relevant examples or mockups
- How it would integrate with existing IDA Domain functionality

## 🛠️ Development

### Prerequisites for Development

- Python 3.9+
- IDA Pro (for testing)
- UV for dependency management
- pytest for testing (included in dev dependencies)

### Setting up Development Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/HexRaysSA/ida-domain.git
   cd ida-domain
   ```

2. **Set up environment variables**:
   ```bash
   export IDADIR="[Your IDA Installation Directory]"
   ```

3. **Install dependencies using UV**:
   ```bash
   uv sync --extra dev
   uv run pre-commit install
   ```

### Running Tests

```bash
uv run pytest tests/
```

### Building Documentation

```bash
cd docs
uv run --with sphinx --with sphinx-rtd-theme --with sphinx-autodoc-typehints make html
```

The generated documentation will be available at `docs/_build/html/index.html`.

## Making Changes

### Development Workflow

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below.

3. **Test your changes** thoroughly:
   ```bash
   # Run existing tests
   uv run pytest tests/

   # Test with actual IDA binaries if possible
   python examples/explore_database.py -f /path/to/test/binary
   ```

4. **Update documentation** if needed:
   ```bash
   cd docs && make html
   ```

5. **Commit your changes** with a clear commit message:
   ```bash
   git commit -m "Add feature: description of your changes"
   ```

6. **Push to your fork and create a Pull Request**.

## Coding Standards

### Python Code Style

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Use descriptive variable and function names
- Keep functions focused and small
- Add docstrings to all public functions and classes

### IDA Domain Specific Guidelines

- **Domain Model Patterns**: Follow existing patterns for domain entities
- **IDA Integration**: Ensure compatibility with IDA Python SDK
- **Error Handling**: Use appropriate exception handling for IDA operations
- **Resource Management**: Properly handle database connections and cleanup
- **Cross-Platform**: Ensure code works on Windows, macOS, and Linux

### Code Organization

- Keep related functionality in the same module
- Follow the existing package structure in `ida_domain/`
- Add appropriate error handling and user feedback
- Include examples for new functionality

### Documentation

- Add docstrings to all public functions and classes
- Update README.md template if adding new features
- Include examples in docstrings where helpful
- Keep inline comments concise and meaningful
- Update the examples directory with relevant usage patterns

## Testing

### Test Requirements

- **Write tests for new functionality**: Every new feature must include comprehensive tests
- **Add checks to existing tests**: When modifying existing functionality, enhance existing tests with additional checks
- Ensure existing tests continue to pass
- Test both success and error cases
- Include integration tests where appropriate
- Test with different binary formats when possible
- Write unit tests for individual functions and methods
- Include edge case testing (empty inputs, invalid parameters, etc.)

### Test Structure

```bash
tests/
├── ida_domain_test.py          # Main test suite
└── resources/                  # Test binaries and resources
    ├── README.md               # Instructions for rebuilding test binaries
    ├── tiny_asm.asm            # Comprehensive assembly test source
    ├── tiny_asm.bin            # Compiled test binary (from tiny_asm.asm)
    ├── tiny_c.c                # C test source for complex patterns
    ├── tiny_c.bin              # Compiled C test binary
    └── example.til             # Type information library
```

### Working with Test Resources

The project includes test binaries for different testing needs:

**Assembly binary (`tiny_asm.bin`)** - built from `tiny_asm.asm`, covers:
- All x64 operand types (register, immediate, memory, SIB addressing)
- Various instruction patterns and data sizes
- Function calls, string operations, and vector instructions
- Edge cases for thorough API testing

**C binary (`tiny_c.bin`)** - built from `tiny_c.c`, covers:
- Complex variable access patterns (HIWORD, LOWORD macros)
- Pointer cast assignments
- Patterns that test decompiler output analysis

To rebuild the test binaries:
```bash
cd tests/resources
nasm -f elf64 tiny_asm.asm -o tiny_asm.bin
gcc -O0 -fno-pie -c tiny_c.c -o tiny_c.bin
```

**Important**: After updating the test binary, ensure you make the necessary changes to existing tests to accommodate any new functionality or changes in the binary structure.

When adding new functionality, consider whether `tiny_asm.asm` needs updates to test new operand types or instruction patterns.

### Running Specific Tests

```bash
# Run all tests
uv run pytest tests/

# Run specific test file
uv run pytest tests/ida_domain_test.py

# Run with verbose output
uv run pytest tests/ -v
```

## Examples

### Adding New Examples

When adding new functionality, include examples in the `examples/` directory:

1. Create a new Python file in `examples/`
2. Follow the existing pattern with proper argument parsing
3. Include comprehensive docstrings
4. Test the example with real binaries
5. Update documentation to reference the new example
6. Update the unit tests to run also the new example

### Example Template

```python
#!/usr/bin/env python3
"""
Brief description of what this example demonstrates.

This example shows how to use IDA Domain to [specific functionality].
"""

import argparse
import ida_domain


def main_functionality(db_path):
    """Main function demonstrating the feature."""
    # Your implementation here
    pass


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Example description')
    parser.add_argument(
        '-f', '--input-file',
        help='Binary input file to be loaded',
        type=str,
        required=True
    )
    args = parser.parse_args()
    main_functionality(args.input_file)


if __name__ == '__main__':
    main()
```

## Pull Request Guidelines

### Before Submitting

- [ ] Code follows the project's coding standards
- [ ] Tests pass locally
- [ ] New functionality is tested
- [ ] Documentation is updated if needed
- [ ] Examples are provided for new features
- [ ] Commit messages are clear and descriptive

### Pull Request Description

1. **Title**: Use a clear, descriptive title
2. **Description**: Explain what changes you made and why
3. **Testing**: Describe how you tested your changes
4. **Breaking Changes**: Clearly mark any breaking changes
5. **Related Issues**: Reference any related issues

### Review Process

- All pull requests require review before merging
- Address feedback promptly and professionally
- Be prepared to make changes based on review comments
- Ensure CI/CD checks pass
- For running the full test suite on CI in forked repositories, if you have an IDA license, configure these repository secrets:
  - `HCLI_API_KEY`: Generate an API key from your My Hex-Rays account [API Keys](https://my.hex-rays.com/dashboard/account-settings/api-keys) section
  - `IDA_LICENSE_ID`: Get your license ID from your My Hex-Rays account [licenses](https://my.hex-rays.com/dashboard/licenses) section
- Without these secrets, only code quality checks (linting) will run on your fork
- The full test suite will automatically run on merge to the main repository

## Development Tips

### Working with IDA

```bash
# Set IDA directory for development
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS/"

# Test with different binary types
python examples/explore_database.py -f tests/resources/tiny_asm.bin
```

### Common Development Tasks

```bash
# Format code
uv run black ida_domain/ examples/ tests/

# Run linting
uv run ruff check ida_domain/ examples/ tests/

# Type checking
uv run mypy ida_domain/

# Build package
uv build
```

### Debugging

- Use IDA's built-in debugging capabilities
- Add logging for complex operations
- Test with various binary formats and architectures
- Use the examples directory for quick testing

## Getting Help

- Check existing issues and documentation first
- Ask questions in GitHub Discussions
- Contact support@hex-rays.com for sensitive issues
- Join the community discussions for general questions

## Release Process

Releases are handled by maintainers using the automated GitHub Actions workflow. Contributors don't need to worry about versioning or releases.

## License

By contributing to IDA Domain, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to IDA Domain! Your efforts help make reverse engineering more accessible and efficient for the community.
