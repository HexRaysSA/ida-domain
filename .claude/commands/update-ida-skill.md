---
description: Update the ida-domain-scripting skill when the API changes
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(wc:*)
argument-hint: [ida-domain-path]
---

# Update IDA Domain Scripting Skill

Update the ida-domain-scripting skill to reflect changes in the ida-domain API.

## Source Code Location

The ida-domain source code is at: **$ARGUMENTS**

If no path provided, use the current working directory.

## Current Skill Files

The skill is located at `~/.claude/skills/ida-domain-scripting/` or `.claude/skills/ida-domain-scripting`:
- `SKILL.md` - Main skill file with overview, handlers table, conventions
- `references/api-handlers.md` - Complete handler method reference
- `references/enums-types.md` - Enum values reference
- `references/patterns.md` - Code patterns and examples

## Update Process

### Step 1: Analyze Source Changes

Read the ida-domain source files to identify:

1. **All handlers** in `database.py`:
   - Look for `@property` methods returning handler classes
   - Each handler is accessed via `db.<handler_name>`

2. **Handler methods** in each handler file (e.g., `functions.py`, `xrefs.py`):
   - Public methods (not starting with `_`)
   - Method signatures and return types
   - Docstrings for descriptions

3. **Enums and types**:
   - `xrefs.py`: XrefType, XrefKind
   - `operands.py`: OperandType, OperandDataType, AccessType
   - `functions.py`: FunctionFlags, LocalVariableAccessType, LocalVariableContext
   - `search.py`: SearchDirection, SearchTarget
   - Any new enums added

4. **New patterns** from:
   - Examples in `examples/` directory if present
   - Test files showing usage patterns
   - Docstrings with code examples

### Step 2: Compare with Current Skill

Read the current skill files and identify:
- Missing handlers (new handlers not documented)
- Missing methods (new methods on existing handlers)
- Missing enum values
- Outdated information

### Step 3: Update Skill Files

Update each file as needed:

#### SKILL.md
- Update the handlers table if new handlers added
- Update API conventions if patterns changed
- Keep it concise (<200 lines)

#### references/api-handlers.md
- Add new handlers with their methods
- Add new methods to existing handlers
- Update method signatures if changed
- Keep the table format consistent

#### references/enums-types.md
- Add new enum values
- Add entirely new enums
- Update descriptions if changed

#### references/patterns.md
- Add patterns for new functionality
- Update existing patterns if API changed
- Add new sections for major new features

### Step 4: Verify Updates

After updates, verify:
- All handlers from database.py are in SKILL.md
- All public methods are in api-handlers.md
- All enum values are in enums-types.md
- Code examples use correct API

## Important Guidelines

1. **Preserve structure** - Keep the existing file organization
2. **Be accurate** - Extract info directly from source code, don't guess
3. **Stay concise** - Don't bloat files with unnecessary details
4. **Document new features** - Any new handler or significant method needs coverage
5. **Maintain consistency** - Use same formatting as existing content

## Output

After completing updates, summarize:
- Number of new handlers added
- Number of new methods documented
- Number of new enum values added
- Any significant API changes noted
