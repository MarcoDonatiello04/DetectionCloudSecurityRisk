"""
How source code reads or writes an object property (BOPLA inference, B.7).

The inference phase asks this module which discovered properties a syntax node touches, so
that an access found inside an authorization context marks the property as protected.
Recognized forms:
  - attribute / member / selector access: `user.salary`;
  - Python: subscript with a literal string key (`user["salary"]`, also as assignment
    target), `user.get("salary")`, `getattr(user, "salary")`, `setattr(user, "salary", v)`,
    literal string keys of a dictionary (`{"salary": ...}`);
  - JavaScript/TypeScript: `user["salary"]`, destructuring (`const { salary } = user`, with
    renaming `{ salary: s }` and defaults), keys of an object literal (`{ salary: ... }`,
    `{ "salary": ... }`, `{ salary }`);
  - Go: map indexing with a literal string key (`m["salary"]`).
A string by itself is never an access (`print("salary")`): it counts only as the key of a
subscript, get/getattr/setattr or of a dictionary/object literal. A dictionary key is
attributed to every inventory property with that name (known limit B.8).

Entry points:
  node_property_accesses(node, lang) -> list[str]   tree-sitter node, one language
  line_mentions_property(line, prop) -> bool         regex fallback, one source line
"""

from __future__ import annotations

import re

# Python calls whose literal string argument at the given position names an attribute
_PY_ATTR_BUILTINS = {"getattr": 1, "setattr": 1}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _string_value(node, lang: str) -> str | None:
    """Content of a plain string literal (no interpolation), otherwise None."""
    if node is None:
        return None
    if lang == "python":
        if node.type != "string":
            return None
        parts = [c for c in node.children if c.type not in ("string_start", "string_end")]
        if len(parts) == 1 and parts[0].type == "string_content":
            return _text(parts[0])
    elif lang in ("javascript", "typescript"):
        if node.type not in ("string", "template_string"):
            return None
        parts = [c for c in node.children if c.type not in ('"', "'", "`")]
        if len(parts) == 1 and parts[0].type == "string_fragment":
            return _text(parts[0])
    elif lang == "go":
        if node.type == "interpreted_string_literal":
            parts = [c for c in node.children if c.type != '"']
            if len(parts) == 1 and parts[0].type == "interpreted_string_literal_content":
                return _text(parts[0])
        elif node.type == "raw_string_literal":
            parts = [c for c in node.children if c.type != "`"]
            if len(parts) == 1 and parts[0].type == "raw_string_literal_content":
                return _text(parts[0])
    return None


def _as_list(value: str | None) -> list[str]:
    return [value] if value else []


def _python_accesses(node) -> list[str]:
    if node.type == "attribute":
        for child in reversed(node.children):
            if child.type == "identifier":
                return [_text(child)]
    elif node.type == "subscript":
        # x["salary"]: a single literal key (x["a", "b"] or x[i] are not property accesses)
        keys = node.children_by_field_name("subscript")
        if len(keys) == 1:
            return _as_list(_string_value(keys[0], "python"))
    elif node.type == "pair":
        # {"salary": ...}: literal key of a dictionary
        return _as_list(_string_value(node.child_by_field_name("key"), "python"))
    elif node.type == "call":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or arguments.type != "argument_list":
            return []
        positional = [c for c in arguments.children if c.is_named and c.type != "keyword_argument"]
        if function.type == "identifier":
            position = _PY_ATTR_BUILTINS.get(_text(function))
            if position is not None and len(positional) > position:
                return _as_list(_string_value(positional[position], "python"))
        elif function.type == "attribute":
            method = function.child_by_field_name("attribute")
            if method is not None and _text(method) == "get" and positional:
                return _as_list(_string_value(positional[0], "python"))
    return []


def _js_property_key(key) -> str | None:
    if key is None:
        return None
    if key.type == "property_identifier":
        return _text(key)
    return _string_value(key, "javascript")


def _js_accesses(node) -> list[str]:
    if node.type == "member_expression":
        for child in node.children:
            if child.type == "property_identifier":
                return [_text(child)]
    elif node.type == "subscript_expression":
        return _as_list(_string_value(node.child_by_field_name("index"), "javascript"))
    elif node.type in ("shorthand_property_identifier_pattern", "shorthand_property_identifier"):
        # const { salary } = user  /  { salary = 0 }  /  object literal shorthand { salary }
        return [_text(node)]
    elif node.type in ("pair", "pair_pattern"):
        # { salary: 1 }, { "salary": 1 }  /  const { salary: s } = user
        return _as_list(_js_property_key(node.child_by_field_name("key")))
    return []


def _go_accesses(node) -> list[str]:
    if node.type == "selector_expression":
        for child in node.children:
            if child.type == "field_identifier":
                return [_text(child)]
    elif node.type == "index_expression":
        return _as_list(_string_value(node.child_by_field_name("index"), "go"))
    return []


def node_property_accesses(node, lang: str) -> list[str]:
    """Property names accessed by this tree-sitter node (not by its descendants)."""
    if lang == "python":
        return _python_accesses(node)
    if lang in ("javascript", "typescript"):
        return _js_accesses(node)
    if lang == "go":
        return _go_accesses(node)
    return []


# One destructured/shorthand entry: `name`, `name = default`, `name: alias`, `...rest`
_ENTRY = r"(?:\.\.\.)?[\w$]+(?:\s*[:=]\s*[^,{}]+?)?"


def line_mentions_property(line: str, prop: str) -> bool:
    """
    Regex fallback: the line accesses `prop` as `.prop` / `->prop`, `["prop"]` / `['prop']`,
    `.get("prop")`, key `prop:` of an object literal or entry of a destructuring `{ prop }`.
    """
    p = re.escape(prop)
    patterns = (
        r"[\.\-\>\b]" + p + r"\b",
        r"\[\s*([\"'`])" + p + r"\1\s*\]",
        r"\.get\(\s*([\"'])" + p + r"\1",
        # key of an object literal: `{ salary: ...`, `, "salary": ...`, a line `salary: ...`
        r"(?:^|[{,])\s*([\"']?)" + p + r"\1\s*:(?!:)",
        # destructuring / shorthand: `{ salary }`, `{ id, salary = 0, ...rest }`
        r"\{\s*(?:" + _ENTRY + r"\s*,\s*)*" + p + r"(?:\s*[:=]\s*[^,{}]+?)?"
        r"\s*(?:,\s*" + _ENTRY + r"\s*)*,?\s*\}",
    )
    return any(re.search(pattern, line) for pattern in patterns)


def node_receiver(node, lang: str) -> str | None:
    """
    Source text of the object whose property this node accesses (`user` in `user.salary`,
    `request.user` in `request.user["role"]`), or None when the access has no receiver
    (a dictionary literal key, a destructuring pattern).
    """
    target = None
    if lang == "python":
        if node.type == "attribute":
            target = node.child_by_field_name("object")
        elif node.type == "subscript":
            target = node.child_by_field_name("value")
        elif node.type == "call":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None and function.type == "attribute":
                target = function.child_by_field_name("object")  # x.get("k")
            elif function is not None and arguments is not None:
                positional = [c for c in arguments.children if c.is_named]
                target = positional[0] if positional else None  # getattr(x, "k")
    elif lang in ("javascript", "typescript"):
        if node.type in ("member_expression", "subscript_expression"):
            target = node.child_by_field_name("object")
    elif lang == "go" and node.type in ("selector_expression", "index_expression"):
        target = node.child_by_field_name("operand")
    return _text(target) if target is not None else None
