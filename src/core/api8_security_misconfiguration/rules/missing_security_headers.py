import ast
import re
from pathlib import Path
from typing import List
from src.core.api8_security_misconfiguration.models import MisconfigFinding

def check_file_for_signals(file_path: Path) -> bool:
    """Returns True if any positive security headers signal is found in the file."""
    try:
        content = file_path.read_text(errors='replace')
    except Exception:
        return False

    # 1. Simple text check for helmet (JS)
    if file_path.suffix in (".js", ".ts"):
        if "helmet(" in content or "helmet " in content:
            return True

    # 2. Check for flask_talisman / Talisman
    if "Talisman(" in content:
        return True

    # 3. Check for add_middleware with Security/Header in the name
    if "add_middleware" in content:
        if re.search(r'add_middleware\(\s*([A-Za-z0-9_]+)', content):
            middleware_matches = re.findall(r'add_middleware\(\s*([A-Za-z0-9_]+)', content)
            for mw in middleware_matches:
                if "Security" in mw or "Header" in mw:
                    return True

    # 4. Check for @app.after_request / response.headers
    if file_path.suffix == ".py":
        try:
            tree = ast.parse(content)
        except Exception:
            return False

        class SecurityHeadersVisitor(ast.NodeVisitor):
            def __init__(self):
                self.found = False

            def visit_FunctionDef(self, node: ast.FunctionDef):
                is_after_request = False
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Attribute) and dec.attr == "after_request":
                        is_after_request = True
                    elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "after_request":
                        is_after_request = True

                if is_after_request:
                    for subnode in ast.walk(node):
                        if isinstance(subnode, ast.Assign):
                            for target in subnode.targets:
                                if isinstance(target, ast.Subscript):
                                    if isinstance(target.value, ast.Attribute) and target.value.attr == "headers":
                                        if isinstance(target.slice, ast.Constant):
                                            header_name = str(target.slice.value).lower()
                                            if header_name in (
                                                "x-content-type-options", 
                                                "x-frame-options", 
                                                "strict-transport-security", 
                                                "content-security-policy"
                                            ):
                                                self.found = True
                self.generic_visit(node)

        visitor = SecurityHeadersVisitor()
        visitor.visit(tree)
        if visitor.found:
            return True

    return False

def analyze_global(target_path: str) -> List[MisconfigFinding]:
    target_dir = Path(target_path)
    if not target_dir.exists():
        return []

    # Walk all files under target_path
    py_files = list(target_dir.rglob("*.py"))
    js_files = list(target_dir.rglob("*.js"))
    ts_files = list(target_dir.rglob("*.ts"))
    all_files = py_files + js_files + ts_files

    for f in all_files:
        if "test/" in f.as_posix() or "tests/" in f.as_posix():
            continue
        if check_file_for_signals(f):
            return []

    # If no files contain any positive security header signals
    return [MisconfigFinding(
        rule_id="SC-004",
        cwe_id="CWE-693",
        category="missing_security_headers",
        severity="MEDIUM",
        file_path="global_codebase",
        line_number=None,
        evidence="No security headers middleware or talisman usage found in codebase",
        missing_guard="Implement Talisman (Flask), SecurityHeadersMiddleware (FastAPI/Django), or Helmet (Express)",
        confidence=0.70,
        layer="ast"
    )]
