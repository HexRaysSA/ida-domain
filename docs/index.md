# IDA Domain API

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

## ⚙️ Quick Example

```python
--8<-- "examples/quick_example.py"
```

## 📖 Documentation

- **[Getting Started](getting_started.md)** - Installation and your first script
- **[Examples](examples.md)** - Practical examples for common tasks
- **[API Reference](usage.md)** - Complete API documentation
- **[Migration Guide](migration-guide.md)** - Migrate from IDA Python SDK

## 🔗 Additional Resources

- **PyPI Package**: [ida-domain on PyPI](https://pypi.org/project/ida-domain/)
- **Source Code**: [GitHub Repository](https://github.com/HexRaysSA/ida-domain)
- **Issues**: [Bug Reports](https://github.com/HexRaysSA/ida-domain/issues)
- **License**: MIT License
