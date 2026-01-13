---
description: Update the ida-domain-scripting skill when the API changes
allowed-tools: Bash(uv:*), Read, Write, Edit
argument-hint: [ida-domain-path]
---

# Update IDA Domain Scripting Skill

Automatically regenerate the ida-domain-scripting skill documentation from source code.

## Quick Update

Run the auto-generator:

```bash
uv run python .claude/skills/ida-domain-scripting/generate_skill_docs.py --ida-domain-path $ARGUMENTS
```

If no path provided, use current directory:

```bash
uv run python .claude/skills/ida-domain-scripting/generate_skill_docs.py --ida-domain-path .
```

## What Gets Generated

The generator parses Python source using AST (no runtime needed) and creates:

- `SKILL.md` - Main skill file with handlers table
- `references/api-handlers.md` - All handler methods with signatures
- `references/enums-types.md` - All enum values

## Manual Updates Still Needed

The generator does NOT update:
- `references/patterns.md` - Code examples and patterns (update manually)
- Docstring descriptions for enum values (add to source code)

## After Regeneration

1. Review the generated files for accuracy
2. Update `references/patterns.md` if new features were added
3. Test a few API calls to verify documentation matches reality

## Troubleshooting

If generator misses methods:
- Check the handler class inherits from `DatabaseEntity`
- Check the class name matches handler name (e.g., `Functions` for `functions`)
- Methods starting with `_` are excluded (private)

To debug, add print statements in `generate_skill_docs.py`.
