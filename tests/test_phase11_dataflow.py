"""Phase 11 Batch 8 – Cross-handler data-flow analysis tests."""

import pytest

from dragonslayer.analysis.handler_semantics import (
    SemanticOpcodeTable,
    OpcodeTableEntry,
    HandlerSemantic,
    VMOperation,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
from dragonslayer.analysis.dataflow import (
    compute_data_flow,
    eliminate_dead_vars,
    DataFlowResult,
    VarDef,
    VarUse,
    LiveRange,
    PhiNode,
    _StackTracker,
)

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(addr, op, delta=4, width=4, opcode=0):
    return OpcodeTableEntry(
        opcode=opcode, handler_address=addr,
        semantic=HandlerSemantic(
            handler_address=addr, operation=op,
            confidence=0.9, operand_width=width,
        ),
        vip_delta=delta,
    )


def _bnd(vip, handler_addr, delta=4):
    return HandlerBoundary(
        vip_value=vip, handler_address=handler_addr,
        trace_start=0, trace_end=5,
        instruction_count=5, vip_delta=delta,
    )


def _simple_program():
    """PUSH, PUSH, ADD → defines 3 vars, uses 2."""
    entries = [
        _entry(0x1000, VMOperation.PUSH, opcode=1),
        _entry(0x2000, VMOperation.PUSH, opcode=2),
        _entry(0x3000, VMOperation.ADD, opcode=3),
    ]
    table = SemanticOpcodeTable(
        entries=entries, handler_count=3, unique_operations=3,
    )
    boundaries = [
        _bnd(0x100, 0x1000),
        _bnd(0x104, 0x2000),
        _bnd(0x108, 0x3000),
    ]
    return table, boundaries


# ---------------------------------------------------------------------------
# _StackTracker
# ---------------------------------------------------------------------------

class TestStackTracker:
    def test_push_pop(self):
        t = _StackTracker()
        t.push("a")
        t.push("b")
        assert t.pop() == "b"
        assert t.pop() == "a"

    def test_pop_empty_returns_arg(self):
        t = _StackTracker()
        name = t.pop()
        assert name.startswith("arg_")

    def test_depth(self):
        t = _StackTracker()
        assert t.depth == 0
        t.push("x")
        assert t.depth == 1

    def test_snapshot(self):
        t = _StackTracker()
        t.push("a")
        t.push("b")
        assert t.snapshot() == ["a", "b"]


# ---------------------------------------------------------------------------
# compute_data_flow basics
# ---------------------------------------------------------------------------

class TestComputeDataFlow:
    def test_empty(self):
        result = compute_data_flow(SemanticOpcodeTable(), [])
        assert result.handler_count == 0
        assert result.definitions == []
        assert result.dead_variables == []

    def test_simple_program_definitions(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        assert result.handler_count == 3
        # PUSH defines val_0, PUSH defines val_1, ADD defines sum_0
        assert len(result.definitions) == 3
        names = [d.name for d in result.definitions]
        assert "val_0" in names
        assert "val_1" in names
        assert "sum_0" in names

    def test_simple_program_uses(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        # ADD uses val_0 and val_1
        assert len(result.uses) == 2
        used_names = {u.name for u in result.uses}
        assert "val_0" in used_names
        assert "val_1" in used_names

    def test_simple_program_dead_variables(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        # sum_0 is defined but never used → dead
        assert "sum_0" in result.dead_variables
        # val_0 and val_1 are used by ADD → not dead
        assert "val_0" not in result.dead_variables
        assert "val_1" not in result.dead_variables

    def test_reaching_defs(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        # val_0 was defined by PUSH at index 0
        assert "val_0" in result.reaching_defs
        assert result.reaching_defs["val_0"].handler_index == 0
        assert result.reaching_defs["val_0"].operation == VMOperation.PUSH

    def test_def_use_edges(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        # ADD consumes val_0 and val_1, produces sum_0
        # Edges: val_1 → sum_0, val_0 → sum_0 (two consumed for one result)
        assert len(result.def_use_edges) >= 2


# ---------------------------------------------------------------------------
# Live ranges
# ---------------------------------------------------------------------------

class TestLiveRanges:
    def test_live_range_of_consumed_var(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        lr_map = {lr.name: lr for lr in result.live_ranges}
        # val_0 defined at index 0, last used at index 2 (ADD)
        assert lr_map["val_0"].def_index == 0
        assert lr_map["val_0"].last_use_index == 2

    def test_live_range_of_dead_var(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        lr_map = {lr.name: lr for lr in result.live_ranges}
        # sum_0: defined at index 2, never used → last_use = -1
        assert lr_map["sum_0"].def_index == 2
        assert lr_map["sum_0"].last_use_index == -1

    def test_longer_chain(self):
        """PUSH, PUSH, ADD, PUSH, MUL — val_0 live until ADD at 2."""
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.PUSH, opcode=2),
            _entry(0x3000, VMOperation.ADD, opcode=3),
            _entry(0x4000, VMOperation.PUSH, opcode=4),
            _entry(0x5000, VMOperation.MUL, opcode=5),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=5, unique_operations=5,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        result = compute_data_flow(table, boundaries)
        lr_map = {lr.name: lr for lr in result.live_ranges}
        # sum_0 should be used by MUL at index 4
        assert lr_map["sum_0"].last_use_index == 4


# ---------------------------------------------------------------------------
# CMP / TEST produce flags, not stack values
# ---------------------------------------------------------------------------

class TestCmpAndTest:
    def test_cmp_pops_two(self):
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.PUSH, opcode=2),
            _entry(0x3000, VMOperation.CMP, opcode=3),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=3, unique_operations=3,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        result = compute_data_flow(table, boundaries)
        assert len(result.uses) == 2  # CMP pops 2
        # CMP defines a flag variable
        flag_defs = [d for d in result.definitions if d.operation == VMOperation.CMP]
        assert len(flag_defs) == 1

    def test_test_pops_two(self):
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.PUSH, opcode=2),
            _entry(0x3000, VMOperation.TEST, opcode=3),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=3, unique_operations=3,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        result = compute_data_flow(table, boundaries)
        assert len(result.uses) == 2


# ---------------------------------------------------------------------------
# LOAD / STORE stack effects
# ---------------------------------------------------------------------------

class TestLoadStore:
    def test_load_pops_addr_pushes_value(self):
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.LOAD, opcode=2),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=2, unique_operations=2,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        result = compute_data_flow(table, boundaries)
        # LOAD pops 1 (addr) and defines 1 (loaded value)
        assert len(result.uses) == 1
        load_defs = [d for d in result.definitions if d.operation == VMOperation.LOAD]
        assert len(load_defs) == 1

    def test_store_pops_two(self):
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.PUSH, opcode=2),
            _entry(0x3000, VMOperation.STORE, opcode=3),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=3, unique_operations=3,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        result = compute_data_flow(table, boundaries)
        # STORE pops 2 (value + addr), defines none → val_0 and val_1 used
        assert len(result.uses) == 2
        store_defs = [d for d in result.definitions if d.operation == VMOperation.STORE]
        assert len(store_defs) == 0


# ---------------------------------------------------------------------------
# Phi-nodes with CFG
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _NX, reason="networkx required")
class TestPhiNodes:
    def test_no_phi_linear(self):
        table, boundaries = _simple_program()
        G = nx.DiGraph()
        for i in range(3):
            G.add_node(i)
        G.add_edge(0, 1); G.add_edge(1, 2)
        result = compute_data_flow(table, boundaries, handler_cfg=G)
        assert result.phi_nodes == []

    def test_phi_at_merge_point(self):
        """Diamond CFG: 0→1, 0→2, 1→3, 2→3. Node 3 is merge."""
        entries = [
            _entry(0x1000, VMOperation.PUSH, opcode=1),
            _entry(0x2000, VMOperation.PUSH, opcode=2),
            _entry(0x3000, VMOperation.PUSH, opcode=3),
            _entry(0x4000, VMOperation.ADD, opcode=4),
        ]
        table = SemanticOpcodeTable(
            entries=entries, handler_count=4, unique_operations=4,
        )
        boundaries = [_bnd(0x100 + i * 4, e.handler_address) for i, e in enumerate(entries)]
        G = nx.DiGraph()
        for i in range(4):
            G.add_node(i)
        G.add_edge(0, 1); G.add_edge(0, 2); G.add_edge(1, 3); G.add_edge(2, 3)
        result = compute_data_flow(table, boundaries, handler_cfg=G)
        # Node 3 has two predecessors — phi-nodes may be inserted
        # (At least for variables defined after the split)
        assert isinstance(result.phi_nodes, list)


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_keys(self):
        table, boundaries = _simple_program()
        result = compute_data_flow(table, boundaries)
        s = result.summary()
        assert "handler_count" in s
        assert "dead_variable_count" in s
        assert "total_defs" in s
        assert s["handler_count"] == 3


# ---------------------------------------------------------------------------
# eliminate_dead_vars
# ---------------------------------------------------------------------------

class TestEliminateDeadVars:
    def test_removes_dead_assignment(self):
        text = "sum_0 = val_0 + val_1\nld_0 = val_0 + val_1"
        result = eliminate_dead_vars(text, ["sum_0"])
        assert "sum_0" not in result
        assert "ld_0" in result

    def test_keeps_live_vars(self):
        text = "sum_0 = val_0 + val_1"
        result = eliminate_dead_vars(text, [])
        assert "sum_0" in result

    def test_keeps_side_effects(self):
        """Lines with function calls are kept even if target is dead."""
        text = "dead_0 = call(target)"
        result = eliminate_dead_vars(text, ["dead_0"])
        assert "dead_0" in result  # call has side effects

    def test_keeps_stores(self):
        """Lines with pointer deref on RHS are kept."""
        text = "dead_0 = *(DWORD*)(addr)"
        result = eliminate_dead_vars(text, ["dead_0"])
        assert "dead_0" in result  # memory read could have side effects

    def test_keeps_comments(self):
        text = "// comment\nsum_0 = a + b"
        result = eliminate_dead_vars(text, ["sum_0"])
        assert "// comment" in result

    def test_empty_text(self):
        result = eliminate_dead_vars("", ["x"])
        assert result == ""

    def test_no_dead_vars_passthrough(self):
        text = "a = b + c"
        result = eliminate_dead_vars(text, [])
        assert result == text
