"""Smoke test — loop_bounds rule module API is accessible."""

from src.core.api4_resource_consumption.rules.loop_bounds import LoopBoundsRule


def test_rule_has_analyze_python():
    assert callable(getattr(LoopBoundsRule, "analyze_python", None))


def test_rule_has_analyze_javascript():
    assert callable(getattr(LoopBoundsRule, "analyze_javascript", None))


def test_rule_ids_defined():
    assert LoopBoundsRule.rule_id.startswith("RC-")
    assert LoopBoundsRule.cwe_id.startswith("CWE-")
    assert LoopBoundsRule.severity in ("HIGH", "MEDIUM", "LOW")


def test_python_while_loop_tainted():
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    lang = Language(tspython.language())
    parser = Parser(lang)
    src = """
def process():
    items = request.json.get("items")
    while len(items) > 0:
        handle(items.pop())
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_python(tree.root_node, "test.py")
    assert any(f.rule_id == "RC-005" for f in findings)


def test_python_list_comprehension_tainted():
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    lang = Language(tspython.language())
    parser = Parser(lang)
    src = """
def process():
    items = request.json["items"]
    res = [heavy_computation(x) for x in items]
    return res
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_python(tree.root_node, "test.py")
    assert any(f.rule_id == "RC-005" for f in findings)


def test_python_list_comprehension_guarded():
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    lang = Language(tspython.language())
    parser = Parser(lang)
    src = """
def process():
    items = request.json["items"]
    if len(items) > 100:
        abort(400)
    res = [heavy_computation(x) for x in items]
    return res
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_python(tree.root_node, "test.py")
    assert not findings


def test_js_array_foreach_tainted():
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser

    lang = Language(tsjs.language())
    parser = Parser(lang)
    src = """
function handler(req, res) {
    const items = req.body.items;
    items.forEach(item => {
        heavy(item);
    });
}
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_javascript(tree.root_node, "test.js")
    assert any(f.rule_id == "RC-005" and "forEach" in f.missing_guard for f in findings)


def test_js_array_map_tainted():
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser

    lang = Language(tsjs.language())
    parser = Parser(lang)
    src = """
function handler(req, res) {
    const items = req.body.items;
    const transformed = items.map(x => heavy(x));
    res.json(transformed);
}
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_javascript(tree.root_node, "test.js")
    assert any(f.rule_id == "RC-005" and "map" in f.missing_guard for f in findings)


def test_js_array_foreach_guarded():
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser

    lang = Language(tsjs.language())
    parser = Parser(lang)
    src = """
function handler(req, res) {
    const items = req.body.items;
    if (items.length > 50) return res.status(400).send("Too many");
    items.forEach(item => {
        heavy(item);
    });
}
"""
    tree = parser.parse(src.encode())
    findings = LoopBoundsRule.analyze_javascript(tree.root_node, "test.js")
    assert not findings
