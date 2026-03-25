import pytest

import ida_domain  # isort: skip
import ida_domain.flowchart
from ida_domain.base import InvalidEAError, InvalidParameterError
from ida_domain.flowchart import FlowChartFlags


def test_basic_block(test_env):
    db = test_env
    func = db.functions.get_at(0x29E)
    assert func is not None

    blocks = db.functions.get_flowchart(func)
    assert blocks.size == 4

    # Validate expected blocks
    expected_blocks = [(0xC4, 0x262), (0x262, 0x26B), (0x26B, 0x272), (0x272, 0x2A3)]

    for i, block in enumerate(blocks):
        assert expected_blocks[i][0] == block.start_ea, (
            f'Block start ea mismatch at index {i}, '
            f'{hex(expected_blocks[i][0])} != {hex(block.start_ea)}'
        )
        assert expected_blocks[i][1] == block.end_ea, (
            f'Block end ea mismatch at index {i}, '
            f'{hex(expected_blocks[i][1])} != {hex(block.end_ea)}'
        )

    # Validate expected instructions and their addresses
    expected_instructions = [
        (0x262, 'call    rax'),
        (0x264, 'call    qword ptr [rbx]'),
        (0x266, 'call    qword ptr [rbx+rcx*4]'),
        (0x269, 'jmp     rax'),
    ]

    instructions = db.instructions.get_between(blocks[1].start_ea, blocks[1].end_ea)
    for i, instruction in enumerate(instructions):
        assert expected_instructions[i][0] == instruction.ea
        assert expected_instructions[i][1] == db.instructions.get_disassembly(instruction)

    # Test FlowChart iteration and length
    assert len(blocks) == 4
    block_count = 0
    for block in blocks:
        assert hasattr(block, 'start_ea')
        assert hasattr(block, 'end_ea')
        block_count += 1
    assert block_count == 4

    # Test FlowChart indexing with __getitem__
    assert blocks[0].start_ea == 0xC4
    assert blocks[3].end_ea == 0x2A3
    with pytest.raises(IndexError):
        blocks[4]  # Should raise IndexError

    # Test successor and predecessor relationships
    # First block (0xC4-0x262) should have one successor
    first_block = blocks[0]
    successors = list(first_block.get_successors())
    assert len(successors) == 1
    assert successors[0].start_ea == 0x272

    instructions = list(first_block.get_instructions())
    assert len(instructions) == 77

    # Count successors
    assert first_block.count_successors() == 1

    # Last block (0x272-0x2A3) should have predecessors
    last_block = blocks[3]
    predecessors = list(last_block.get_predecessors())
    assert len(predecessors) >= 1
    # Check that at least one predecessor is from our function
    assert any(pred.start_ea == 0xC4 for pred in predecessors)

    # Count predecessors
    assert last_block.count_predecessors() >= 1

    # Test get_between method
    flowchart = ida_domain.flowchart.FlowChart(db, None, (0xC4, 0x2A3))
    assert len(flowchart) == 4
    assert flowchart[0].start_ea == 0xC4
    assert flowchart[3].end_ea == 0x2A3

    # Test get_between error handling
    from ida_domain.base import InvalidEAError, InvalidParameterError

    with pytest.raises(InvalidEAError):
        ida_domain.flowchart.FlowChart(db, None, (0xFFFFFFFF, 0xFFFFFFFF))

    with pytest.raises(InvalidParameterError):
        ida_domain.flowchart.FlowChart(db, None, (0x200, 0x100))

    # Test function_flowchart method (same as db.functions.get_basic_blocks)
    func_blocks = db.functions.get_flowchart(func)
    assert len(func_blocks) == 4
    assert func_blocks[0].start_ea == blocks[0].start_ea
    assert func_blocks[3].end_ea == blocks[3].end_ea

    # Test with flags parameter
    from ida_domain.flowchart import FlowChartFlags

    func_blocks_with_flags = db.functions.get_flowchart(func, flags=FlowChartFlags.NONE)
    assert len(func_blocks_with_flags) == 4

    # Test with NOEXT flag
    func_blocks_noext = db.functions.get_flowchart(func, flags=FlowChartFlags.NOEXT)
    assert len(func_blocks_noext) == 4

    # Test flowchart iteration for a different range
    small_flowchart = ida_domain.flowchart.FlowChart(db, None, (0x10, 0x20))
    # Just verify iteration works regardless of block count
    count = 0
    for block in small_flowchart:
        assert hasattr(block, 'start_ea')
        assert hasattr(block, 'end_ea')
        count += 1
    assert count == len(small_flowchart)

    # Test that successor/predecessor references are properly maintained
    # Use the first block which we know has a successor
    test_block_with_successor = blocks[0]
    test_successors = list(test_block_with_successor.get_successors())
    assert len(test_successors) > 0

    for succ in test_successors:
        # Check that we can get predecessors of the successor
        succ_preds = list(succ.get_predecessors())
        assert any(pred.start_ea == test_block_with_successor.start_ea for pred in succ_preds)
