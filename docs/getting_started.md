# Getting Started

This guide will take you from nothing to a working first script with the IDA Domain API.

## Prerequisites

- **Python 3.10 or higher**
- **IDA Pro 9.1 or higher**

## Installation

### Step 1: Set up IDA SDK Access

The `idapro` Python module needs to know where IDA Pro is installed. The location is stored in a per-user config file (`%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` on Windows, `~/.idapro/ida-config.json` on Linux/macOS).

- **If IDA was installed via [HCLI](https://hcli.docs.hex-rays.com/):** the install path is configured automatically — no further setup is required.
- **Otherwise:** run the `py-activate-idalib.py` activation script that ships with IDA once. It auto-detects the install directory from its own location and writes it to the per-user config. The script normally lives in `<IDA install dir>/idalib/python/`:

    === "macOS"
        ```bash
        python3 "/Applications/IDA Professional 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
        ```

    === "Linux"
        ```bash
        python3 "/opt/ida-9.2/idalib/python/py-activate-idalib.py"
        ```

    === "Windows"
        ```cmd
        python "C:\Program Files\IDA Professional 9.2\idalib\python\py-activate-idalib.py"
        ```

    You can also pass `-d <ida-install-dir>` to point at a specific IDA installation explicitly.

### Step 2: Install the Package

For a clean environment, use a virtual environment:

```bash
# Create and activate virtual environment
python -m venv ida-env
source ida-env/bin/activate  # On Windows: ida-env\Scripts\activate

# Install the package
pip install ida-domain
```

### Step 3: Verify Installation

```python
# test_install.py
try:
    from ida_domain import Database
    print("✓ Installation successful!")
except ImportError as e:
    print(f"✗ Installation failed: {e}")
```

## Your First Script

Create a simple script to explore an IDA database:

```python
--8<-- "examples/my_first_script.py"
```

**To run this script:**

Run: `python my_first_script.py -f <binary input file>`

**Expected output:**
```
✓ Opened: /path/to/sample.idb
  Architecture: x86_64
  Entry point: 0x1000
  Address range: 0x1000 - 0x2000
  Functions: 42
  Strings: 15
✓ Database closed
```

## Running Scripts Inside IDA

The examples above show **library mode** - running standalone Python scripts outside IDA. You can also use IDA Domain from **inside the IDA GUI** for interactive analysis.

When running inside IDA, call `Database.open()` with no arguments to get a handle to the currently open database:

```python
--8<-- "examples/ida_console_example.py"
```

**Key difference from library mode:**

- No file path argument - database is already open

## Troubleshooting

**ImportError: No module named 'ida_domain'**
- Run `pip install ida-domain`
- Check you're in the correct virtual environment

**IDA SDK not found**
- Ensure you have run `py-activate-idalib.py` (or installed IDA via HCLI) so the install path is registered
- Verify IDA Pro is properly installed

**Database won't open**
- Check the file path exists
- Ensure the database was created with IDA Pro 9.0+

## Advanced Usage

### Overriding the IDA install directory with `IDADIR`

To override the configured install directory for a single session or script — for example to test a specific IDA build, switch between multiple installed versions, or in CI — set the `IDADIR` environment variable before importing `idapro`:

=== "macOS"
    ```bash
    export IDADIR="/Applications/IDA Professional 9.2.app/Contents/MacOS/"
    ```

=== "Linux"
    ```bash
    export IDADIR="/opt/ida-9.2/"
    ```

=== "Windows"
    ```cmd
    set "IDADIR=C:\Program Files\IDA Professional 9.2"
    ```

!!! warning
    Set `IDADIR` only for the current shell session or inside the script that uses `idapro` — do **not** set it as a persistent/global environment variable (e.g. via `~/.bashrc`, `~/.zshrc`, or Windows System Properties). A globally exported `IDADIR` can interfere with the IDA GUI and other IDA tools on your system.

## Next Steps

1. **[Examples](examples.md)** - Complete examples for real-world tasks
2. **[API Reference](usage.md)** - Detailed API documentation
3. **Start your project** - Apply these concepts to your reverse engineering work!
