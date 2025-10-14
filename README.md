# IDA Domain

[![PyPI version](https://badge.fury.io/py/ida-domain.svg)](https://badge.fury.io/py/ida-domain)
[![Python Support](https://img.shields.io/pypi/pyversions/ida-domain.svg)](https://pypi.org/project/ida-domain/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The IDA Domain API is a new open-source Python API designed to make scripting in IDA simpler, more consistent, and more natural.

This is a first step in a much longer journey. It’s not the finish line, but a foundation for ongoing collaboration between Hex-Rays and the reverse engineering community. Over time, the Domain API will expand to cover more areas of IDA, gradually becoming the main entry point for scripting and plugin development.

The **Domain** in Domain API refers to the domain of reverse engineering. Concepts like functions, types, cross-references, and more are first-class citizens in this API, giving you cleaner, domain-focused abstractions for common tasks.

The Domain API sits on top of the IDA Python SDK, complementing it rather than replacing it. You can use both side by side—combining the clarity and simplicity of Domain API calls with the full flexibility of the SDK when needed.

> **Compatibility:** Requires IDA Pro 9.1.0 or later

## 🚀 Key Features

- **Domain-focused design** – Work directly with core reverse engineering concepts like functions, types, and xrefs as first-class citizens.  
- **Open source from day one** – Read the code, suggest improvements, or contribute new ideas.  
- **Pure Python implementation** – No compilation required, works with modern Python versions.  
- **Compatible by design** – Use alongside the IDA Python SDK without conflicts.  
- **Developer-centric** – Reduce boilerplate and streamline frequent tasks.  
- **Independently versioned** – Upgrade at your own pace and pin versions for stability.  
- **Simple installation** – Get started with a single `pip install`.  

## 📦 Installation

### Prerequisites

**IDA Pro Version:** The IDA Domain library requires IDA Pro 9.1.0 or later.

Set the `IDADIR` environment variable to point to your IDA installation directory:

```bash
export IDADIR="[IDA Installation Directory]"
```

**Example:**
```bash
export IDADIR="/Applications/IDA Professional 9.1.app/Contents/MacOS/"
```

> **Note:** If you have already installed and configured the `idapro` Python package, setting `IDADIR` is not required.

### Install from PyPI

```bash
pip install ida-domain
```

## 🎯 Usage Example

Here is an example showing how to use IDA Domain to analyze a binary:

```python
#!/usr/bin/env python3
"""
Database exploration example for IDA Domain API.

This example demonstrates how to open an IDA database and explore its basic properties.
"""

import argparse
from dataclasses import asdict

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def explore_database(db_path):
    """Explore basic database information."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(db_path, ida_options) as db:
        # Get basic information
        print(f'Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

        # Get metadata
        print('Database metadata:')
        metadata_dict = asdict(db.metadata)
        for key, value in metadata_dict.items():
            print(f'  {key}: {value}')

        # Count functions
        function_count = 0
        for _ in db.functions:
            function_count += 1
        print(f'Total functions: {function_count}')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    explore_database(args.input_file)


if __name__ == '__main__':
    main()

```

## 📖 Documentation

Complete documentation is available at: [https://ida-domain.docs.hex-rays.com/](https://ida-domain.docs.hex-rays.com/)

- **[API Reference](https://ida-domain.docs.hex-rays.com/ref/database/)**: Documentation of available classes and methods
- **[Getting Started](https://ida-domain.docs.hex-rays.com/getting_started/)**: Complete setup guide including installation and first steps
- **[Examples](https://ida-domain.docs.hex-rays.com/examples/)**: Usage examples for common tasks


## 🛠️ Development

For development, we use a **[uv](https://docs.astral.sh/uv/)** based workflow:

```bash
git clone https://github.com/HexRaysSA/ida-domain.git
cd ida-domain
uv sync --extra dev
uv run pre-commit install
```

## 🧪 Testing

Set the `IDADIR` environment variable to point to your IDA installation directory:

Run the test suite using pytest:

```bash
uv sync --extra dev
uv run pytest
```

## 📚 Build Documentation

To build the documentation locally:

```bash
uv sync --extra docs
uv run mkdocs serve
```

Or to just build it,

```bash
uv run mkdocs build
```

The documentation is available in site/

### Online Documentation

The latest documentation is available at: https://ida-domain.docs.hex-rays.com/

## 📝 Examples

Check the [`examples/`](https://github.com/HexRaysSA/ida-domain/tree/main/examples) directory for usage examples:

```bash
uv run python examples/analyze_database.py
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](https://github.com/HexRaysSA/ida-domain/blob/main/CONTRIBUTING.md) for details on how to:

- Report bugs and suggest features
- Submit pull requests with proper testing

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/HexRaysSA/ida-domain/blob/main/LICENSE) file for details.
