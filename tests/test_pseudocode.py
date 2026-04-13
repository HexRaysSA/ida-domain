import ida_hexrays
import pytest

import ida_domain  # isort: skip

from ida_domain.microcode import MicroLocalVar  # noqa: E402
from ida_domain.pseudocode import (  # noqa: E402
    PseudocodeBlock,
    PseudocodeExpression,
    PseudocodeExpressionOp,
    PseudocodeExpressionVisitor,
    PseudocodeFunction,
    PseudocodeIf,
    PseudocodeInstruction,
    PseudocodeInstructionOp,
    PseudocodeInstructionVisitor,
    PseudocodeMaturity,
    PseudocodeNumber,
    PseudocodeParentVisitor,
    PseudocodeVisitor,
)

# ---------------------------------------------------------------------------
# PseudocodeBlock: is_empty, first, last
# ---------------------------------------------------------------------------


def test_block_is_empty_on_real_function(test_env):
    """The body block of a real function is never empty."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)  # add_numbers
    block = func.body.block
    assert block is not None
    assert not block.is_empty
    assert bool(block)


def test_block_first_and_last(test_env):
    """first/last return PseudocodeInstructions matching iteration order."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)  # add_numbers
    block = func.body.block
    assert block is not None

    first = block.first
    last = block.last
    assert first is not None
    assert last is not None
    assert isinstance(first, PseudocodeInstruction)
    assert isinstance(last, PseudocodeInstruction)

    items = list(block)
    assert first.ea == items[0].ea
    assert last.ea == items[-1].ea


def test_block_first_last_single_statement(test_env):
    """When block has one statement, first and last point to it."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    assert block is not None
    items = list(block)
    if len(items) == 1:
        assert block.first.ea == block.last.ea


# ---------------------------------------------------------------------------
# PseudocodeExpression.negate
# ---------------------------------------------------------------------------


def test_expression_negate(test_env):
    """negate() inverts a condition expression in place and is reversible."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number — has a loop

    ifs = func.find_if_instructions()
    loops = func.find_loops()
    targets = ifs + loops
    assert len(targets) > 0, "print_number should have at least one if or loop"

    for insn in targets:
        if insn.is_if:
            cond = insn.if_details.condition
        elif insn.op == PseudocodeInstructionOp.DO:
            cond = insn.do_details.condition
        elif insn.op == PseudocodeInstructionOp.WHILE:
            cond = insn.while_details.condition
        elif insn.op == PseudocodeInstructionOp.FOR:
            cond = insn.for_details.condition
        else:
            continue

        original_text = cond.to_text()

        cond.negate()
        negated_text = cond.to_text()
        assert negated_text != original_text, (
            f"negate() didn't change the expression text: {original_text}"
        )

        # Negate again — should restore the original
        cond.negate()
        double_negated_text = cond.to_text()
        assert double_negated_text == original_text, (
            f"double negate didn't restore: {original_text!r} vs {double_negated_text!r}"
        )
        return

    pytest.fail("No suitable condition found in print_number")


# ---------------------------------------------------------------------------
# PseudocodeIf.swap_branches
# ---------------------------------------------------------------------------


def test_swap_branches_with_else(tiny_pseudocode_env):
    """swap_branches() swaps then/else and negates the condition."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if — has 2 if/else
    ifs = func.find_if_instructions()
    assert len(ifs) >= 2

    det = ifs[0].if_details
    assert det.has_else

    orig_cond_text = det.condition.to_text()
    orig_then_ea = det.then_branch.ea
    orig_else_ea = det.else_branch.ea

    result = det.swap_branches()
    assert result is True

    assert det.then_branch.ea == orig_else_ea
    assert det.else_branch.ea == orig_then_ea
    assert det.condition.to_text() != orig_cond_text


# ---------------------------------------------------------------------------
# PseudocodeFunction.find_parent_of
# ---------------------------------------------------------------------------


def test_find_parent_of_expression(tiny_pseudocode_env):
    """find_parent_of() returns the parent of a leaf expression in the ctree."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if — has variables and numbers

    for expr in func.walk_expressions():
        if expr.is_number or expr.is_variable:
            parent = func.find_parent_of(expr)
            assert parent is not None, (
                f"Expected a parent for {expr.op.name} at 0x{expr.ea:x}"
            )
            assert isinstance(parent, (PseudocodeExpression, PseudocodeInstruction))
            return

    pytest.fail("No number or variable expression found in nested_if")


def test_find_parent_of_if_condition(tiny_pseudocode_env):
    """find_parent_of() on a condition sub-expression returns its parent."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if
    ifs = func.find_if_instructions()
    assert len(ifs) >= 1

    # The if-condition is an expression inside the if instruction.
    # Its sub-expressions (e.g. the variable being compared) should have
    # the comparison expression as parent.
    cond = ifs[0].if_details.condition
    sub = cond.x or cond.y
    assert sub is not None

    parent = func.find_parent_of(sub)
    assert parent is not None
    assert isinstance(parent, PseudocodeExpression)


def test_find_parent_of_call_target(test_env):
    """find_parent_of() on a call's callee expression returns the call itself."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func — calls two functions
    calls = func.find_calls()
    assert len(calls) > 0, "level1_func should have calls"

    call_expr = calls[0]
    callee = call_expr.x
    assert callee is not None

    parent = func.find_parent_of(callee)
    assert parent is not None
    assert isinstance(parent, PseudocodeExpression)
    assert parent.is_call


# ---------------------------------------------------------------------------
# MicroLocalVar.set_user_comment
# ---------------------------------------------------------------------------


def test_set_user_comment(test_env):
    """set_user_comment() sets the comment on a local variable."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    args = func.arguments
    assert len(args) > 0

    arg = args[0]
    old_comment = arg.comment

    arg.set_user_comment("test comment from ida-domain")
    assert arg.comment == "test comment from ida-domain"

    # Reset
    arg.set_user_comment(old_comment)
    assert arg.comment == old_comment


# ---------------------------------------------------------------------------
# PseudocodeFunction.save_local_variable_info
# ---------------------------------------------------------------------------


def test_save_local_variable_info_name(test_env):
    """save_local_variable_info persists a variable rename across re-decompilation."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    arg = func.arguments[0]
    original_name = arg.name

    arg.set_user_name("my_test_param")
    result = func.save_local_variable_info(arg, save_name=True)
    assert result is True

    # Re-decompile and verify the name persisted
    func2 = db.pseudocode.decompile(0x2A3)
    assert func2.arguments[0].name == "my_test_param"

    # Restore
    func2.arguments[0].set_user_name(original_name)
    func2.save_local_variable_info(func2.arguments[0], save_name=True)


def test_save_local_variable_info_no_flags(test_env):
    """save_local_variable_info returns True immediately when no flags are set."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    assert func.save_local_variable_info(func.arguments[0]) is True


def test_save_local_variable_info_comment(test_env):
    """save_local_variable_info can persist a comment across re-decompilation."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    arg = func.arguments[0]
    arg.set_user_comment("persisted comment")
    result = func.save_local_variable_info(arg, save_comment=True)
    assert result is True

    func2 = db.pseudocode.decompile(0x2A3)
    assert func2.arguments[0].comment == "persisted comment"

    # Cleanup
    func2.arguments[0].set_user_comment("")
    func2.save_local_variable_info(func2.arguments[0], save_comment=True)


# ---------------------------------------------------------------------------
# Context-manager user annotation read-back
# ---------------------------------------------------------------------------


def test_user_labels_empty(test_env):
    """user_labels() yields None when no user labels exist."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    with func.user_labels() as labels:
        assert labels is None


def test_user_comments_empty(test_env):
    """user_comments() yields None when no user comments exist."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    with func.user_comments() as cmts:
        assert cmts is None


def test_user_iflags_empty(test_env):
    """user_iflags() yields None when no user iflags exist."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    with func.user_iflags() as iflags:
        assert iflags is None


def test_user_numforms_empty(test_env):
    """user_numforms() yields None when no user numforms exist."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    with func.user_numforms() as numforms:
        assert numforms is None


def test_user_comments_roundtrip(test_env):
    """Save a user comment via add_comment, then read it back via the context manager."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    func.add_comment(func.entry_ea, "test cmt")

    func2 = db.pseudocode.decompile(0x2A3)
    with func2.user_comments() as cmts:
        assert cmts is not None
        found = any(str(cmt) == "test cmt" for _, cmt in cmts.items())
        assert found, "Saved comment not found in user_comments()"

    # Cleanup
    func2.remove_comment(func2.entry_ea)


# ---------------------------------------------------------------------------
# user_lvar_settings
# ---------------------------------------------------------------------------


def test_user_lvar_settings_after_rename(test_env):
    """After saving a variable name, user_lvar_settings yields it."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    arg = func.arguments[0]
    original_name = arg.name

    arg.set_user_name("lvar_test_name")
    func.save_local_variable_info(arg, save_name=True)

    func2 = db.pseudocode.decompile(0x2A3)
    with func2.user_lvar_settings() as lvinf:
        assert lvinf is not None
        names = [str(lv.name) for lv in lvinf.lvvec]
        assert "lvar_test_name" in names

    # Cleanup
    func2.arguments[0].set_user_name(original_name)
    func2.save_local_variable_info(func2.arguments[0], save_name=True)


def test_user_lvar_settings_structure(test_env):
    """Entries in user_lvar_settings have name, type, cmt, size, defea."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    arg = func.arguments[0]
    original_name = arg.name

    arg.set_user_name("struct_check")
    func.save_local_variable_info(arg, save_name=True)

    func2 = db.pseudocode.decompile(0x2A3)
    with func2.user_lvar_settings() as lvinf:
        assert lvinf is not None
        entry = next(lv for lv in lvinf.lvvec if str(lv.name) == 'struct_check')
        assert hasattr(entry, 'name')
        assert hasattr(entry, 'type')
        assert hasattr(entry, 'cmt')
        assert hasattr(entry, 'size')
        assert hasattr(entry.ll, 'defea')

    # Cleanup
    func2.arguments[0].set_user_name(original_name)
    func2.save_local_variable_info(func2.arguments[0], save_name=True)


# ---------------------------------------------------------------------------
# Semantic accuracy: structural checks on decompiled functions
# ---------------------------------------------------------------------------


def test_print_number_has_loop(test_env):
    """print_number has a div loop for digit conversion — ctree should contain one."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)
    loops = func.find_loops()
    assert len(loops) >= 1, "print_number should have at least one loop"

    loop = loops[0]
    if loop.op == PseudocodeInstructionOp.DO:
        cond = loop.do_details.condition
    elif loop.op == PseudocodeInstructionOp.WHILE:
        cond = loop.while_details.condition
    elif loop.op == PseudocodeInstructionOp.FOR:
        cond = loop.for_details.condition
    else:
        pytest.fail(f"Unexpected loop type: {loop.op.name}")

    assert cond is not None
    assert len(cond.to_text()) > 0


def test_add_numbers_has_two_arguments(test_env):
    """add_numbers(a, b) should have exactly 2 arguments, both marked is_arg."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    args = func.arguments
    assert len(args) == 2
    assert all(isinstance(a, MicroLocalVar) for a in args)
    assert all(a.is_arg for a in args)


def test_add_numbers_has_add_expression(test_env):
    """add_numbers computes a + b — ctree should contain an ADD with two operands."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    add_exprs = [
        e for e in func.walk_expressions()
        if e.op == PseudocodeExpressionOp.ADD
    ]
    assert len(add_exprs) >= 1, "add_numbers should contain an ADD expression"

    add_expr = add_exprs[0]
    assert add_expr.x is not None
    assert add_expr.y is not None


def test_add_numbers_find_local_variable(test_env):
    """find_local_variable finds arguments by name, returns None for unknown."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    first_arg_name = func.arguments[0].name

    found = func.find_local_variable(first_arg_name)
    assert found is not None
    assert found.name == first_arg_name

    assert func.find_local_variable("__nonexistent__") is None


def test_level1_func_has_two_calls(test_env):
    """level1_func calls level2_func_a and level2_func_b — exactly 2 calls."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)
    calls = func.find_calls()
    assert len(calls) == 2, f"level1_func should have 2 calls, got {len(calls)}"


# ---------------------------------------------------------------------------
# SWIG lifecycle: parent chain integrity
# ---------------------------------------------------------------------------


def test_walker_items_have_parent(test_env):
    """Items from walk_expressions hold a parent ref."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    exprs = list(func.walk_expressions())
    assert len(exprs) > 0
    for expr in exprs:
        assert expr._parent is not None


def test_block_first_last_have_parent(test_env):
    """first/last on a block carry parent references back to the block."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    assert block is not None

    assert block.first._parent is block
    assert block.last._parent is block


def test_if_details_children_have_parent(tiny_pseudocode_env):
    """condition/then_branch/else_branch on PseudocodeIf carry parent refs."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if — has if/else
    ifs = func.find_if_instructions()
    assert len(ifs) >= 1

    det = ifs[0].if_details
    assert det is not None
    assert det.condition._parent is det
    assert det.then_branch._parent is det
    assert det.has_else
    assert det.else_branch._parent is det


# ---------------------------------------------------------------------------
# PseudocodeExpressionOp / PseudocodeInstructionOp category properties
# ---------------------------------------------------------------------------


def test_expression_op_categories():
    """Verify expression operator category properties against known values."""
    Op = PseudocodeExpressionOp
    # arithmetic
    assert Op.ADD.is_arithmetic
    assert Op.MUL.is_arithmetic
    assert not Op.FADD.is_arithmetic
    # floating point
    assert Op.FADD.is_floating_point
    assert Op.FDIV.is_floating_point
    assert not Op.ADD.is_floating_point
    # binary vs unary
    assert Op.ADD.is_binary
    assert Op.NEG.is_unary
    assert not Op.NEG.is_binary
    assert not Op.ADD.is_unary
    # leaf
    assert Op.NUM.is_leaf
    assert Op.VAR.is_leaf
    assert Op.STR.is_leaf
    assert not Op.ADD.is_leaf
    # call
    assert Op.CALL.is_call
    assert not Op.ADD.is_call
    # assignment
    assert Op.ASG.is_assignment
    assert Op.ASG_ADD.is_assignment
    assert not Op.ADD.is_assignment
    # relational
    assert Op.EQ.is_relational
    assert Op.SLE.is_relational
    assert not Op.ADD.is_relational
    # prepost
    assert Op.POSTINC.is_prepost
    assert Op.PREDEC.is_prepost
    assert not Op.ADD.is_prepost


def test_instruction_op_categories():
    """Verify instruction operator category properties."""
    IOp = PseudocodeInstructionOp
    assert IOp.FOR.is_loop
    assert IOp.WHILE.is_loop
    assert IOp.DO.is_loop
    assert not IOp.IF.is_loop
    assert IOp.BREAK.is_control_flow
    assert IOp.CONTINUE.is_control_flow
    assert IOp.RETURN.is_control_flow
    assert IOp.GOTO.is_control_flow
    assert not IOp.IF.is_control_flow


# ---------------------------------------------------------------------------
# PseudocodeNumber numeric protocol
# ---------------------------------------------------------------------------


def test_number_protocol(test_env):
    """PseudocodeNumber supports comparison, arithmetic, and conversion."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number — has literals 0, 1, 10, 48

    numbers = []
    for e in func.walk_expressions():
        if e.is_number:
            numbers.append(e.number)
    assert len(numbers) >= 4

    # Find the number with value 10 (0xA divisor)
    ten = next(n for n in numbers if n.value == 10)
    assert int(ten) == 10
    assert float(ten) == 10.0
    assert bool(ten) is True
    assert str(ten) == '10'
    assert hash(ten) == hash(10)

    # Comparisons
    assert ten == 10
    assert not (ten == 11)
    assert ten > 5
    assert ten < 100
    assert ten >= 10
    assert ten <= 10

    # Arithmetic
    assert ten + 1 == 11
    assert 1 + ten == 11
    assert ten - 3 == 7
    assert 20 - ten == 10

    # Find the zero
    zero = next(n for n in numbers if n.value == 0)
    assert bool(zero) is False
    assert zero == 0

    # Cross-number comparison
    assert ten > zero


def test_number_signed_value(tiny_pseudocode_env):
    """value returns signed interpretation for negative constants."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x157)  # use_negative — has 'a1 >= -1'

    neg_one = func.find_expression(
        lambda e: e.is_number and e.number == -1
    )
    assert neg_one is not None
    assert neg_one.number.value == -1
    assert neg_one.number.unsigned_value == 0xFFFFFFFFFFFFFFFF
    assert neg_one.number == -1
    assert neg_one.number < 0
    assert int(neg_one.number) == -1


def test_number_unsigned_value(test_env):
    """unsigned_value always returns the raw 64-bit unsigned storage."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number

    ten = func.find_expression(lambda e: e.is_number and e.number.unsigned_value == 10)
    assert ten is not None
    assert ten.number.unsigned_value == 10
    assert ten.number.value == 10  # positive values agree


def test_number_factory_no_type_fallback(test_env):
    """Factory-created numbers without type fall back to unsigned."""
    neg = PseudocodeExpression.from_number(-1)
    # No parent type → falls back to unsigned
    assert neg.number.value == 0xFFFFFFFFFFFFFFFF
    assert neg.number.unsigned_value == 0xFFFFFFFFFFFFFFFF
    assert neg.number == 0xFFFFFFFFFFFFFFFF

    pos = PseudocodeExpression.from_number(42)
    assert pos.number.value == 42
    assert int(pos.number) == 42


# ---------------------------------------------------------------------------
# PseudocodeFunction basic properties
# ---------------------------------------------------------------------------


def test_function_properties(test_env):
    """Verify basic PseudocodeFunction properties on add_numbers."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    assert func.entry_ea == 0x2A3
    assert func.maturity == PseudocodeMaturity.FINAL
    assert func.body.op == PseudocodeInstructionOp.BLOCK
    assert func.header_lines == 0
    assert func.get_func_type() is not None
    assert func.eamap is not None
    assert func.boundaries is not None
    assert func.mba is not None


def test_function_to_text(test_env):
    """to_text() returns the expected pseudocode for add_numbers."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    lines = func.to_text()
    assert len(lines) == 4
    assert 'add_numbers' in lines[0]
    assert 'return' in lines[2]

    # __str__ returns the same content joined
    assert str(func) == '\n'.join(lines)


def test_get_text_shortcut(test_env):
    """db.pseudocode.get_text() returns same lines as decompile().to_text()."""
    db = test_env
    lines = db.pseudocode.get_text(0x2A3)
    assert len(lines) == 4
    assert 'add_numbers' in lines[0]


# ---------------------------------------------------------------------------
# Expression type-specific accessors
# ---------------------------------------------------------------------------


def test_expression_variable_access(test_env):
    """Variable expressions expose variable_index and variable ref."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    vars_found = [e for e in func.walk_expressions() if e.is_variable]
    assert len(vars_found) == 2  # a1 and a2 in "a2 + a1"

    for v in vars_found:
        assert v.variable is not None
        assert v.variable_index is not None
        assert v.variable_index in (0, 1)
        # Non-variable properties should be None
        assert v.number is None
        assert v.string is None
        assert v.obj_ea is None


def test_expression_number_access(test_env):
    """Number expressions expose PseudocodeNumber with correct value."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number
    nums = [e for e in func.walk_expressions() if e.is_number]
    assert len(nums) >= 4

    values = {e.number.value for e in nums}
    assert 0 in values
    assert 1 in values
    assert 10 in values
    assert 48 in values  # ASCII '0'


def test_expression_object_access(test_env):
    """Object expressions expose obj_ea and obj_name."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func — calls named functions
    objs = func.find_objects()
    assert len(objs) == 2

    names = {o.obj_name for o in objs}
    assert 'level2_func_a' in names
    assert 'level2_func_b' in names

    for o in objs:
        assert o.obj_ea is not None
        assert o.is_object
        # Non-object properties should be None
        assert o.number is None
        assert o.variable is None


def test_expression_call_args(tiny_pseudocode_env):
    """Call expressions expose call_args with correct argument count."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x170)  # main — calls all functions
    calls = func.find_calls()
    assert len(calls) == 9

    # Find nested_if call (2 args)
    nested_call = next(c for c in calls if c.call_args and len(c.call_args) == 2)
    args = nested_call.call_args
    assert len(args) == 2
    assert not args[0].is_vararg
    assert args[0].expression is not None
    assert args[0].formal_type is not None

    # Indexing
    assert args[0].expression.to_text() != args[1].expression.to_text()

    # Iteration
    arg_list = list(args)
    assert len(arg_list) == 2


# ---------------------------------------------------------------------------
# Instruction detail accessors
# ---------------------------------------------------------------------------


def test_instruction_block_detail(test_env):
    """Body instruction has block detail; non-block instructions return None."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    body = func.body
    assert body.op == PseudocodeInstructionOp.BLOCK
    assert body.block is not None
    assert body.is_block

    # block detail on a non-block instruction should be None
    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.RETURN:
            assert insn.block is None
            assert insn.is_return
            assert not insn.is_block
            break


def test_instruction_expression_detail(test_env):
    """Expression-statement instructions expose their expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func
    # level1_func body: EXPR(level2_func_a()), RETURN(level2_func_b())
    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.EXPR:
            expr = insn.expression
            assert expr is not None
            assert expr.is_call
            break


def test_instruction_return_detail(test_env):
    """Return instructions expose return_details with the returned expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func returns level2_func_b()
    rets = func.find_return_instructions()
    assert len(rets) == 1
    rd = rets[0].return_details
    assert rd is not None
    assert 'level2_func_b' in rd.expression.to_text()


def test_instruction_if_detail(tiny_pseudocode_env):
    """If instructions expose if_details with condition, then, and else."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if

    ifs = func.find_if_instructions()
    assert len(ifs) == 2

    # Outer if: "a1 <= 0"
    outer = ifs[0].if_details
    assert 'a1' in outer.condition.to_text()
    assert outer.condition.op == PseudocodeExpressionOp.SLE
    assert outer.then_branch.op == PseudocodeInstructionOp.BLOCK
    assert outer.has_else
    assert outer.else_branch.op == PseudocodeInstructionOp.BLOCK

    # Inner if: "a2 <= 0"
    inner = ifs[1].if_details
    assert 'a2' in inner.condition.to_text()


def test_instruction_do_loop_detail(test_env):
    """Do-while loops expose do_details with body and condition."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number — has do-while
    loops = func.find_loops()
    assert len(loops) == 1
    assert loops[0].op == PseudocodeInstructionOp.DO

    do = loops[0].do_details
    assert do is not None
    assert do.body.op == PseudocodeInstructionOp.BLOCK
    assert do.condition is not None
    assert len(do.condition.to_text()) > 0


def test_instruction_is_ordinary_flow(test_env):
    """is_ordinary_flow distinguishes sequential from branching instructions."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func
    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.EXPR:
            assert insn.is_ordinary_flow() is True
        elif insn.op == PseudocodeInstructionOp.RETURN:
            assert insn.is_ordinary_flow() is False


# ---------------------------------------------------------------------------
# Instruction-level walk methods
# ---------------------------------------------------------------------------


def test_instruction_walk_expressions(tiny_pseudocode_env):
    """walk_expressions on an if-instruction collects all nested expressions."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    outer_if = func.find_if_instructions()[0]

    exprs = list(outer_if.walk_expressions())
    # nested_if's outer if contains: 3 assignments (sink_a/b/c), 2 comparisons,
    # NEG, SUB, ADD, VARs, OBJs, NUMs — 23 total
    assert len(exprs) == 23
    ops = {e.op.name for e in exprs}
    assert 'ASG' in ops
    assert 'SLE' in ops
    assert 'VAR' in ops


def test_instruction_walk_instructions(tiny_pseudocode_env):
    """walk_instructions on an if-instruction collects nested instructions."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    outer_if = func.find_if_instructions()[0]

    insns = list(outer_if.walk_instructions())
    assert len(insns) == 12  # from exploration
    ops = {i.op.name for i in insns}
    assert 'IF' in ops
    assert 'BLOCK' in ops
    assert 'RETURN' in ops
    assert 'EXPR' in ops


def test_instruction_walk_all(tiny_pseudocode_env):
    """walk_all collects both expressions and instructions."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    outer_if = func.find_if_instructions()[0]

    items = list(outer_if.walk_all())
    n_expr = sum(1 for i in items if isinstance(i, PseudocodeExpression))
    n_insn = sum(1 for i in items if isinstance(i, PseudocodeInstruction))
    assert n_expr == 23
    assert n_insn == 12


# ---------------------------------------------------------------------------
# Visitor classes
# ---------------------------------------------------------------------------


def test_expression_visitor(test_env):
    """PseudocodeExpressionVisitor collects expressions via visit_expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    class CollectVars(PseudocodeExpressionVisitor):
        def __init__(self):
            super().__init__()
            self.vars = []

        def visit_expression(self, expr):
            if expr.is_variable:
                self.vars.append(expr.to_text())
            return 0

    v = CollectVars()
    v.apply_to(func.body)
    assert len(v.vars) == 2  # a1, a2
    assert 'a1' in v.vars
    assert 'a2' in v.vars


def test_instruction_visitor(tiny_pseudocode_env):
    """PseudocodeInstructionVisitor collects instructions via visit_instruction."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)

    class CountReturns(PseudocodeInstructionVisitor):
        def __init__(self):
            super().__init__()
            self.count = 0

        def visit_instruction(self, insn):
            if insn.is_return:
                self.count += 1
            return 0

    v = CountReturns()
    v.apply_to(func.body)
    assert v.count == 3  # nested_if has 3 return paths


def test_combined_visitor(test_env):
    """PseudocodeVisitor visits both expressions and instructions."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    class CountAll(PseudocodeVisitor):
        def __init__(self):
            super().__init__()
            self.exprs = 0
            self.insns = 0

        def visit_expression(self, expr):
            self.exprs += 1
            return 0

        def visit_instruction(self, insn):
            self.insns += 1
            return 0

    v = CountAll()
    v.apply_to(func.body)
    # add_numbers: 3 expressions (ADD, VAR, VAR), 2 instructions (BLOCK, RETURN)
    assert v.exprs == 3
    assert v.insns == 2


def test_parent_visitor(tiny_pseudocode_env):
    """PseudocodeParentVisitor tracks parent expressions during traversal."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)

    class FindAssignTargets(PseudocodeParentVisitor):
        def __init__(self):
            super().__init__()
            self.targets = []

        def visit_expression(self, expr):
            if expr.is_object:
                parent = self.parent_expression()
                if parent and parent.is_assignment:
                    self.targets.append(expr.obj_name)
            return 0

    v = FindAssignTargets()
    v.apply_to(func.body)
    # nested_if assigns to sink_a, sink_b, sink_c (one per branch)
    assert sorted(v.targets) == ['sink_a', 'sink_b', 'sink_c']


# ---------------------------------------------------------------------------
# Convenience finders with semantic checks
# ---------------------------------------------------------------------------


def test_find_calls_by_name(test_env):
    """find_calls(target_name=...) filters by callee name."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)  # level1_func
    a_calls = func.find_calls(target_name='level2_func_a')
    b_calls = func.find_calls(target_name='level2_func_b')
    no_calls = func.find_calls(target_name='nonexistent')

    assert len(a_calls) == 1
    assert len(b_calls) == 1
    assert len(no_calls) == 0


def test_find_calls_by_ea(test_env):
    """find_calls(target_ea=...) filters by callee address."""
    db = test_env
    func = db.pseudocode.decompile(0x2F7)
    calls = func.find_calls(target_ea=0x307)  # level2_func_a address
    assert len(calls) == 1


def test_find_assignments(tiny_pseudocode_env):
    """find_assignments returns all assignment expressions."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if — 3 assignments to sink
    asgns = func.find_assignments()
    assert len(asgns) == 3
    for a in asgns:
        assert a.is_assignment
        assert a.x is not None  # lhs
        assert a.y is not None  # rhs


def test_find_objects_by_ea(tiny_pseudocode_env):
    """find_objects(obj_ea=...) filters by object address."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    # nested_if references three distinct sinks (sink_a/b/c), one per branch
    all_objs = func.find_objects()
    assert len(all_objs) == 3
    addrs = {o.obj_ea for o in all_objs}
    assert len(addrs) == 3
    # Filtering by one of the actual object addresses returns exactly that one
    one_addr = next(iter(addrs))
    filtered = func.find_objects(obj_ea=one_addr)
    assert len(filtered) == 1
    assert filtered[0].obj_ea == one_addr
    empty = func.find_objects(obj_ea=0xDEAD)
    assert len(empty) == 0


def test_find_variables_by_name(test_env):
    """find_variables(var_name=...) filters by variable name."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    a1_refs = func.find_variables(var_name='a1')
    a2_refs = func.find_variables(var_name='a2')
    assert len(a1_refs) == 1
    assert len(a2_refs) == 1
    assert func.find_variables(var_name='nope') == []


def test_find_variables_by_index(test_env):
    """find_variables(var_index=...) filters by variable index."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    idx0 = func.find_variables(var_index=0)
    idx1 = func.find_variables(var_index=1)
    assert len(idx0) == 1
    assert len(idx1) == 1


def test_find_return_instructions(tiny_pseudocode_env):
    """nested_if has 3 return instructions (one per branch)."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    rets = func.find_return_instructions()
    assert len(rets) == 3
    for r in rets:
        assert r.is_return
        rd = r.return_details
        assert rd is not None
        assert len(rd.expression.to_text()) > 0


# ---------------------------------------------------------------------------
# multiply_numbers: MUL expression
# ---------------------------------------------------------------------------


def test_multiply_numbers_has_mul(test_env):
    """multiply_numbers produces a MUL expression for a * b."""
    db = test_env
    func = db.pseudocode.decompile(0x2B3)
    exprs = list(func.walk_expressions())
    mul_exprs = [e for e in exprs if e.op == PseudocodeExpressionOp.MUL]
    assert len(mul_exprs) == 1
    assert mul_exprs[0].x is not None
    assert mul_exprs[0].y is not None


# ---------------------------------------------------------------------------
# Expression query methods
# ---------------------------------------------------------------------------


def test_expression_contains_operator(test_env):
    """contains_operator detects ops in sub-expressions."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    # The return expression "a2 + a1" should contain ADD
    add_expr = next(e for e in func.walk_expressions() if e.op == PseudocodeExpressionOp.ADD)
    assert add_expr.contains_operator(PseudocodeExpressionOp.ADD)
    assert not add_expr.contains_operator(PseudocodeExpressionOp.MUL)


def test_expression_repr(test_env):
    """Expression __repr__ includes op name and ea."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    for e in func.walk_expressions():
        r = repr(e)
        assert 'PseudocodeExpression' in r
        assert '0x' in r
        break


def test_instruction_repr(test_env):
    """Instruction __repr__ includes op name and ea."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    for i in func.walk_instructions():
        r = repr(i)
        assert 'PseudocodeInstruction' in r
        assert '0x' in r
        break


def test_function_repr(test_env):
    """PseudocodeFunction __repr__ includes ea and maturity."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    r = repr(func)
    assert 'PseudocodeFunction' in r
    assert '0x2a3' in r
    assert 'FINAL' in r


# ---------------------------------------------------------------------------
# FOR loop details (use_for at 0xC9)
# ---------------------------------------------------------------------------


def test_for_loop_details(tiny_pseudocode_env):
    """use_for has a FOR loop with init, condition, step, and body."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xC9)  # use_for
    loops = func.find_loops()
    assert len(loops) == 1
    assert loops[0].op == PseudocodeInstructionOp.FOR

    fdet = loops[0].for_details
    assert fdet is not None
    # init: "i = 0"
    assert '0' in fdet.init.to_text()
    # condition: empty (the break is inside the loop body)
    # step: "++i"
    assert fdet.step is not None
    assert fdet.body is not None
    assert fdet.body.op == PseudocodeInstructionOp.BLOCK


def test_for_loop_has_break(tiny_pseudocode_env):
    """use_for's for-loop body contains a break instruction."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xC9)
    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.BREAK:
            return
    pytest.fail("Expected a BREAK instruction in use_for")


# ---------------------------------------------------------------------------
# WHILE loop details (use_while at 0xFA)
# ---------------------------------------------------------------------------


def test_while_loop_details(tiny_pseudocode_env):
    """use_while has a WHILE loop with condition 'a1 > 0' and a body."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xFA)  # use_while
    loops = func.find_loops()
    assert len(loops) == 1
    assert loops[0].op == PseudocodeInstructionOp.WHILE

    wdet = loops[0].while_details
    assert wdet is not None
    assert 'a1' in wdet.condition.to_text()
    assert '0' in wdet.condition.to_text()
    assert wdet.body is not None
    assert wdet.body.op == PseudocodeInstructionOp.BLOCK


def test_while_has_postdec(tiny_pseudocode_env):
    """use_while decrements with a1-- — ctree should contain POSTDEC."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xFA)
    ops = {e.op for e in func.walk_expressions()}
    assert PseudocodeExpressionOp.POSTDEC in ops


# ---------------------------------------------------------------------------
# GOTO instruction (use_switch at 0x76 — compiler generates goto)
# ---------------------------------------------------------------------------


def test_goto_instruction(tiny_pseudocode_env):
    """use_switch's if-chain includes a GOTO instruction with a label."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x76)  # use_switch

    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.GOTO:
            gd = insn.goto_details
            assert gd is not None
            assert gd.label_num >= 0
            return

    pytest.fail("Expected a GOTO instruction in use_switch")


# ---------------------------------------------------------------------------
# PTR and IDX expressions (use_struct at 0x137)
# ---------------------------------------------------------------------------


def test_struct_ptr_and_idx(tiny_pseudocode_env):
    """use_struct accesses *a1 and a1[1] — produces PTR and IDX expressions."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x137)  # use_struct
    ops = {e.op for e in func.walk_expressions()}
    assert PseudocodeExpressionOp.PTR in ops
    assert PseudocodeExpressionOp.IDX in ops


def test_ptr_expression_has_operand(tiny_pseudocode_env):
    """PTR expressions have an x operand (the dereferenced pointer)."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x137)
    for e in func.walk_expressions():
        if e.op == PseudocodeExpressionOp.PTR:
            assert e.x is not None
            assert e.ptr_size is not None
            assert e.ptr_size > 0
            return
    pytest.fail("Expected a PTR expression in use_struct")


def test_idx_expression_has_operands(tiny_pseudocode_env):
    """IDX expressions have x (base) and y (index) operands."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x137)
    for e in func.walk_expressions():
        if e.op == PseudocodeExpressionOp.IDX:
            assert e.x is not None  # base pointer
            assert e.y is not None  # index
            return
    pytest.fail("Expected an IDX expression in use_struct")


# ---------------------------------------------------------------------------
# CAST expressions (use_for, use_while, use_struct, use_negative all have casts)
# ---------------------------------------------------------------------------


def test_cast_expression(tiny_pseudocode_env):
    """CAST is a unary expression — x is the inner expression, y is None."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xC9)  # use_for has (unsigned int) loop-counter casts
    for e in func.walk_expressions():
        if e.op == PseudocodeExpressionOp.CAST:
            assert e.x is not None
            assert e.y is None  # unary
            assert e.type_info is not None
            return
    pytest.fail("Expected a CAST expression in use_for")


# ---------------------------------------------------------------------------
# Expression type-check shortcuts with known values
# ---------------------------------------------------------------------------


def test_expression_type_checks_on_use_switch(tiny_pseudocode_env):
    """use_switch has EQ comparisons, numbers, variables, objects, and assignments."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x76)

    has_eq = any(e.op == PseudocodeExpressionOp.EQ for e in func.walk_expressions())
    has_sgt = any(e.op == PseudocodeExpressionOp.SGT for e in func.walk_expressions())
    assert has_eq  # case comparisons
    assert has_sgt  # "a1 > 3"

    # Verify number values: 0, 1, 2, 3, 10, 20, 30
    values = {e.number.value for e in func.walk_expressions() if e.is_number}
    assert {0, 1, 2, 3, 10, 20, 30} <= values


# ---------------------------------------------------------------------------
# Instruction is_* shortcuts
# ---------------------------------------------------------------------------


def test_instruction_is_shortcuts(tiny_pseudocode_env):
    """Verify is_if, is_loop, is_return, is_goto, is_block on real instructions."""
    db = tiny_pseudocode_env

    # use_for has FOR, IF, BREAK, RETURN, BLOCK, EXPR
    func = db.pseudocode.decompile(0xC9)
    ops_seen = set()
    for insn in func.walk_instructions():
        if insn.is_block:
            ops_seen.add('BLOCK')
        if insn.is_if:
            ops_seen.add('IF')
        if insn.is_loop:
            ops_seen.add('LOOP')
        if insn.is_return:
            ops_seen.add('RETURN')
        if insn.is_goto:
            ops_seen.add('GOTO')
        if insn.is_switch:
            ops_seen.add('SWITCH')

    assert 'BLOCK' in ops_seen
    assert 'IF' in ops_seen
    assert 'LOOP' in ops_seen
    assert 'RETURN' in ops_seen


# ---------------------------------------------------------------------------
# PseudocodeBlock repr and indexing
# ---------------------------------------------------------------------------


def test_block_repr(test_env):
    """PseudocodeBlock repr includes count."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    r = repr(block)
    assert 'PseudocodeBlock' in r
    assert 'count=' in r


def test_block_indexing(test_env):
    """PseudocodeBlock supports positive and negative indexing."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    assert block is not None

    first = block[0]
    last = block[-1]
    assert first.ea == block.first.ea
    assert last.ea == block.last.ea

    with pytest.raises(IndexError):
        block[999]


# ---------------------------------------------------------------------------
# PseudocodeIf repr
# ---------------------------------------------------------------------------


def test_if_repr(tiny_pseudocode_env):
    """PseudocodeIf repr includes has_else."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    det = func.find_if_instructions()[0].if_details
    r = repr(det)
    assert 'PseudocodeIf' in r
    assert 'has_else=True' in r


# ---------------------------------------------------------------------------
# PseudocodeReturn repr
# ---------------------------------------------------------------------------


def test_return_repr(tiny_pseudocode_env):
    """PseudocodeReturn repr includes ea."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)
    rets = func.find_return_instructions()
    rd = rets[0].return_details
    r = repr(rd)
    assert 'PseudocodeReturn' in r
    assert '0x' in r


# ---------------------------------------------------------------------------
# PseudocodeGoto repr
# ---------------------------------------------------------------------------


def test_goto_repr(tiny_pseudocode_env):
    """PseudocodeGoto repr includes label number."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x76)
    for insn in func.walk_instructions():
        if insn.op == PseudocodeInstructionOp.GOTO:
            gd = insn.goto_details
            r = repr(gd)
            assert 'PseudocodeGoto' in r
            assert 'label=' in r
            return
    pytest.fail("No GOTO found")


# ---------------------------------------------------------------------------
# PseudocodeFor / PseudocodeWhile / PseudocodeDo repr
# ---------------------------------------------------------------------------


def test_for_repr(tiny_pseudocode_env):
    """PseudocodeFor repr includes ea."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xC9)
    loop = func.find_loops()[0]
    r = repr(loop.for_details)
    assert 'PseudocodeFor' in r


def test_while_repr(tiny_pseudocode_env):
    """PseudocodeWhile repr includes ea."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xFA)
    loop = func.find_loops()[0]
    r = repr(loop.while_details)
    assert 'PseudocodeWhile' in r


def test_do_repr(test_env):
    """PseudocodeDo repr includes ea."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number has do-while
    loop = func.find_loops()[0]
    r = repr(loop.do_details)
    assert 'PseudocodeDo' in r


# ---------------------------------------------------------------------------
# Expression factories
# ---------------------------------------------------------------------------


def test_expression_from_number(test_env):
    """from_number creates a NUM expression with the correct value."""
    expr = PseudocodeExpression.from_number(42, ea=0x2A3)
    assert expr.op == PseudocodeExpressionOp.NUM
    assert expr.number.value == 42


def test_expression_from_string(test_env):
    """from_string creates a STR expression with the correct content."""
    expr = PseudocodeExpression.from_string("hello")
    assert expr.op == PseudocodeExpressionOp.STR
    assert expr.string == "hello"


def test_expression_from_object(test_env):
    """from_object creates an OBJ expression with the correct address."""
    expr = PseudocodeExpression.from_object(0xDEAD)
    assert expr.op == PseudocodeExpressionOp.OBJ
    assert expr.obj_ea == 0xDEAD


def test_expression_from_variable(test_env):
    """from_variable creates a VAR expression with correct index and type."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    mba = func.mba
    expr = PseudocodeExpression.from_variable(0, mba)
    assert expr.op == PseudocodeExpressionOp.VAR
    assert expr.variable_index == 0
    assert expr.type_info is not None


def test_expression_from_helper(test_env):
    """from_helper creates a HELPER expression with the correct name."""
    expr = PseudocodeExpression.from_helper("LOWORD")
    assert expr.op == PseudocodeExpressionOp.HELPER
    assert expr.helper_name == "LOWORD"


def test_expression_set_type(test_env):
    """set_type returns self for chaining and sets the type."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    arg_type = func.arguments[0].raw_var.tif
    result = PseudocodeExpression.from_number(1).set_type(arg_type)
    assert result.type_info is not None
    assert result.op == PseudocodeExpressionOp.NUM  # chaining returns self


# ---------------------------------------------------------------------------
# Expression mutation
# ---------------------------------------------------------------------------


def test_expression_replace_with(test_env):
    """replace_with swaps expression content in-place."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number

    # Find a number expression with value 10
    target = None
    for e in func.walk_expressions():
        if e.is_number and e.number.value == 10:
            target = e
            break
    assert target is not None

    # Replace with 99 — pass the type inline via the factory's type_info=
    new_expr = PseudocodeExpression.from_number(99, type_info=target.type_info)
    target.replace_with(new_expr)
    assert target.number.value == 99

    # Swap back
    target.replace_with(new_expr)
    assert target.number.value == 10


def test_expression_replace_with_string(test_env):
    """replace_with can swap a number for a string (stack-strings pattern)."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)

    # Find the number 48 (ASCII '0')
    target = None
    for e in func.walk_expressions():
        if e.is_number and e.number.value == 48:
            target = e
            break
    assert target is not None

    new_str = PseudocodeExpression.from_string("0")
    target.replace_with(new_str)
    assert target.op == PseudocodeExpressionOp.STR
    assert target.string == "0"

    # Swap back to restore the tree
    target.replace_with(new_str)


def test_replace_then_refresh_renders_substitution(tiny_pseudocode_env):
    """Typed factory + replace_with + refresh must render the substitution.

    Without ``type_info``, refresh silently invalidates the cfunc and
    ``to_text`` returns an empty body — see the warning in the
    ``from_*`` factory docstrings.
    """
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x170)  # main

    cl = func.find_calls(target_name='classify')[0]
    old_arg = cl.call_args[0].expression

    # Build a number with the type carried inline and swap it in.
    new_arg = PseudocodeExpression.from_number(
        0x42, ea=old_arg.ea, type_info=old_arg.type_info,
    )
    old_arg.replace_with(new_arg)
    func.refresh()

    text = func.to_text()
    # Rendering must not be silently invalidated: body is non-empty AND
    # contains the new literal in the call we mutated.
    assert text, 'refresh() produced an empty body — silent invalidation'
    classify_lines = [line for line in text if 'classify' in line]
    assert len(classify_lines) == 1
    assert '0x42' in classify_lines[0] or '66' in classify_lines[0]


# ---------------------------------------------------------------------------
# Instruction factories
# ---------------------------------------------------------------------------


def test_instruction_make_nop(test_env):
    """make_nop creates an empty instruction."""
    insn = PseudocodeInstruction.make_nop(0x1000)
    assert insn.op == PseudocodeInstructionOp.EMPTY
    assert insn.ea == 0x1000


def test_instruction_make_goto(test_env):
    """make_goto creates a GOTO with correct label number."""
    insn = PseudocodeInstruction.make_goto(0x1000, 5)
    assert insn.op == PseudocodeInstructionOp.GOTO
    assert insn.goto_details is not None
    assert insn.goto_details.label_num == 5


def test_instruction_make_block(test_env):
    """make_block creates a BLOCK instruction with an empty block."""
    insn = PseudocodeInstruction.make_block(0x1000)
    assert insn.op == PseudocodeInstructionOp.BLOCK
    assert insn.block is not None
    assert insn.block.is_empty


def test_instruction_make_expr(test_env):
    """make_expr wraps an expression as a statement."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    expr = PseudocodeExpression.from_number(42)
    insn = PseudocodeInstruction.make_expr(0x2A3, expr)
    assert insn.op == PseudocodeInstructionOp.EXPR
    assert insn.expression is not None


def test_instruction_make_return(test_env):
    """make_return creates a RETURN with optional expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    expr = PseudocodeExpression.from_number(0)
    insn = PseudocodeInstruction.make_return(0x2A3, expr)
    assert insn.op == PseudocodeInstructionOp.RETURN
    assert insn.return_details is not None


def test_instruction_make_if(test_env):
    """make_if creates an IF instruction with condition and branches."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    cond = PseudocodeExpression.from_number(1)
    then_block = PseudocodeInstruction.make_block()
    else_block = PseudocodeInstruction.make_block()

    insn = PseudocodeInstruction.make_if(0x2A3, cond, then_block, else_block)
    assert insn.op == PseudocodeInstructionOp.IF
    assert insn.if_details is not None
    assert insn.if_details.has_else


def test_instruction_make_if_no_else(test_env):
    """make_if without else_branch creates IF without else."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    cond = PseudocodeExpression.from_number(1)
    then_block = PseudocodeInstruction.make_block()

    insn = PseudocodeInstruction.make_if(0x2A3, cond, then_block)
    assert insn.op == PseudocodeInstructionOp.IF
    assert insn.if_details is not None
    assert not insn.if_details.has_else


# ---------------------------------------------------------------------------
# Block mutation
# ---------------------------------------------------------------------------


def test_block_append(test_env):
    """append appends an instruction and returns a valid reference."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    original_len = len(block)

    nop = PseudocodeInstruction.make_nop(0x2A3)
    new_ref = block.append(nop)
    assert len(block) == original_len + 1
    assert new_ref is not None
    assert new_ref.op == PseudocodeInstructionOp.EMPTY
    assert new_ref.ea == 0x2A3


def test_block_append_then_remove(test_env):
    """append followed by remove restores original length."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    block = func.body.block
    original_len = len(block)

    nop = PseudocodeInstruction.make_nop(0x2A3)
    new_ref = block.append(nop)
    assert len(block) == original_len + 1

    block.remove(new_ref)
    assert len(block) == original_len


# ---------------------------------------------------------------------------
# Comment Placement API
# ---------------------------------------------------------------------------


def test_add_comment_and_get_comment(test_env):
    """add_comment persists a comment, get_comment retrieves it."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    ret = func.find_return_instructions()[0]

    func.add_comment(ret.ea, "return value here")
    assert func.get_comment(ret.ea) == "return value here"

    # Cleanup
    func.remove_comment(ret.ea)
    assert func.get_comment(ret.ea) is None


def test_add_comment_survives_redecompile(test_env):
    """A comment added via add_comment survives re-decompilation."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    ea = func.entry_ea

    func.add_comment(ea, "persisted cmt")

    func2 = db.pseudocode.decompile(0x2A3)
    assert func2.get_comment(ea) == "persisted cmt"

    # Cleanup
    func2.remove_comment(ea)


def test_add_comment_appears_in_pseudocode(tiny_pseudocode_env):
    """A comment appears in the pseudocode text output."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if

    # Add comment at first return
    ret = func.find_return_instructions()[0]
    func.add_comment(ret.ea, "negative branch")
    func.refresh()

    text = '\n'.join(func.to_text())
    assert "negative branch" in text

    # Cleanup
    func.remove_comment(ret.ea)


def test_remove_comment(test_env):
    """remove_comment deletes a previously added comment."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    ea = func.entry_ea

    func.add_comment(ea, "temp comment")
    assert func.get_comment(ea) == "temp comment"

    func.remove_comment(ea)
    assert func.get_comment(ea) is None


def test_get_comment_returns_none_when_absent(test_env):
    """get_comment returns None for an address with no comment."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    assert func.get_comment(0xDEADBEEF) is None


def test_add_comment_replaces_existing(test_env):
    """Calling add_comment twice at the same location replaces the comment."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    ea = func.entry_ea

    func.add_comment(ea, "first")
    func.add_comment(ea, "second")
    assert func.get_comment(ea) == "second"

    # Cleanup
    func.remove_comment(ea)


# ---------------------------------------------------------------------------
# Expression builders: from_binary, from_call
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# find_expression / find_instruction
# ---------------------------------------------------------------------------


def test_find_expression_match(test_env):
    """find_expression returns the first matching expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number — has number 10

    expr = func.find_expression(lambda e: e.is_number and e.number == 10)
    assert expr is not None
    assert expr.is_number
    assert expr.number.value == 10


def test_find_expression_no_match(test_env):
    """find_expression returns None when nothing matches."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)

    expr = func.find_expression(lambda e: e.is_string)
    assert expr is None


def test_find_expression_variable(test_env):
    """find_expression can find a variable by name."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    lvars = func.local_variables

    expr = func.find_expression(
        lambda e: e.is_variable and lvars[e.variable_index].name == 'a1'
    )
    assert expr is not None
    assert expr.is_variable


def test_find_instruction_match(test_env):
    """find_instruction returns the first matching instruction."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number — has a do-while loop

    loop = func.find_instruction(lambda i: i.is_loop)
    assert loop is not None
    assert loop.op == PseudocodeInstructionOp.DO


def test_find_instruction_no_match(test_env):
    """find_instruction returns None when nothing matches."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)  # add_numbers — no loops

    loop = func.find_instruction(lambda i: i.is_loop)
    assert loop is None


def test_find_instruction_return(tiny_pseudocode_env):
    """find_instruction finds the first return in nested_if."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0x26)  # nested_if — 3 returns

    ret = func.find_instruction(lambda i: i.is_return)
    assert ret is not None
    assert ret.is_return
    assert ret.return_details is not None


def test_find_expression_stops_early(test_env):
    """find_expression returns only the first match, not all."""
    db = test_env
    func = db.pseudocode.decompile(0x2BC)  # print_number has multiple NUMs

    all_nums = [e for e in func.walk_expressions() if e.is_number]
    assert len(all_nums) > 1  # there are many numbers

    first = func.find_expression(lambda e: e.is_number)
    assert first is not None
    assert first.is_number
    assert first._parent is not None
    # Should match the first one from walk order
    assert first.ea == all_nums[0].ea


def test_find_instruction_for_loop(tiny_pseudocode_env):
    """find_instruction finds a FOR loop with accessible details."""
    db = tiny_pseudocode_env
    func = db.pseudocode.decompile(0xC9)  # use_for

    insn = func.find_instruction(lambda i: i.op == PseudocodeInstructionOp.FOR)
    assert insn is not None
    assert insn.op == PseudocodeInstructionOp.FOR
    assert insn.is_loop
    assert insn.for_details is not None
    assert insn.for_details.body is not None
    assert insn._parent is not None


# ---------------------------------------------------------------------------
# Expression builders: from_binary, from_call
# ---------------------------------------------------------------------------


def test_from_binary_add(test_env):
    """from_binary creates an ADD expression with two operands."""
    left = PseudocodeExpression.from_number(10)
    right = PseudocodeExpression.from_number(20)
    expr = PseudocodeExpression.from_binary(
        PseudocodeExpressionOp.ADD, left, right,
    )
    assert expr.op == PseudocodeExpressionOp.ADD
    assert expr.x is not None
    assert expr.y is not None


def test_from_binary_asg(test_env):
    """from_binary creates an assignment expression."""
    db = test_env
    func = db.pseudocode.decompile(0x2A3)
    mba = func.mba
    lhs = PseudocodeExpression.from_variable(0, mba)
    rhs = PseudocodeExpression.from_number(42)
    expr = PseudocodeExpression.from_binary(
        PseudocodeExpressionOp.ASG, lhs, rhs,
    )
    assert expr.op == PseudocodeExpressionOp.ASG
    assert expr.is_assignment


def test_from_call_no_args(test_env):
    """from_call creates a call expression with no arguments."""
    callee = PseudocodeExpression.from_helper("my_func")
    call = PseudocodeExpression.from_call(callee)
    assert call.op == PseudocodeExpressionOp.CALL
    assert call.call_args is not None
    assert len(call.call_args) == 0


def test_from_call_with_args(test_env):
    """from_call creates a call expression with arguments."""
    callee = PseudocodeExpression.from_helper("CONTAINING_RECORD")
    arg1 = PseudocodeExpression.from_number(1)
    arg2 = PseudocodeExpression.from_helper("MyStruct")
    arg3 = PseudocodeExpression.from_helper("field_x")
    call = PseudocodeExpression.from_call(callee, [arg1, arg2, arg3])
    assert call.op == PseudocodeExpressionOp.CALL
    assert call.call_args is not None
    assert len(call.call_args) == 3


def test_from_call_callee_is_object(test_env):
    """from_call works with an object callee (function by address)."""
    callee = PseudocodeExpression.from_object(0x2A3)
    arg = PseudocodeExpression.from_number(5)
    call = PseudocodeExpression.from_call(callee, [arg])
    assert call.op == PseudocodeExpressionOp.CALL
    assert call.call_args is not None
    assert len(call.call_args) == 1


def test_from_binary_nested(test_env):
    """from_binary can nest: (a + b) * c."""
    a = PseudocodeExpression.from_number(1)
    b = PseudocodeExpression.from_number(2)
    c = PseudocodeExpression.from_number(3)
    add = PseudocodeExpression.from_binary(PseudocodeExpressionOp.ADD, a, b)
    mul = PseudocodeExpression.from_binary(PseudocodeExpressionOp.MUL, add, c)
    assert mul.op == PseudocodeExpressionOp.MUL
    assert mul.x.op == PseudocodeExpressionOp.ADD


def test_from_unary_rejects_binary_op(test_env):
    """from_unary raises InvalidParameterError for binary operators."""
    from ida_domain.base import InvalidParameterError

    a = PseudocodeExpression.from_number(1)
    with pytest.raises(InvalidParameterError, match="not a unary"):
        PseudocodeExpression.from_unary(PseudocodeExpressionOp.ADD, a)


def test_from_unary_rejects_leaf_op(test_env):
    """from_unary raises InvalidParameterError for leaf operators."""
    from ida_domain.base import InvalidParameterError

    a = PseudocodeExpression.from_number(1)
    with pytest.raises(InvalidParameterError, match="not a unary"):
        PseudocodeExpression.from_unary(PseudocodeExpressionOp.NUM, a)


def test_from_binary_rejects_unary_op(test_env):
    """from_binary raises InvalidParameterError for unary operators."""
    from ida_domain.base import InvalidParameterError

    a = PseudocodeExpression.from_number(1)
    b = PseudocodeExpression.from_number(2)
    with pytest.raises(InvalidParameterError, match="not a binary"):
        PseudocodeExpression.from_binary(PseudocodeExpressionOp.NEG, a, b)


