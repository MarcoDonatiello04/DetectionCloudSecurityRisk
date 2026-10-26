import json
import re
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from src.core.api8_security_misconfig.models import MisconfigFinding

# Database offline di pacchetti noti con vulnerabilità critiche/alte
KNOWN_VULNERABILITIES = {
    "flask": {
        "affected": "<2.2.5",
        "cve": "CVE-2023-30861",
        "description": "Cookie disclosure and session hijacking vulnerability",
        "fixed": ">=2.2.5",
    },
    "werkzeug": {
        "affected": "<2.2.3",
        "cve": "CVE-2023-25577",
        "description": "DoS via high multipart field counts and parse error",
        "fixed": ">=2.2.3",
    },
    "pyyaml": {
        "affected": "<5.4",
        "cve": "CVE-2020-14343",
        "description": "Arbitrary code execution via full_load/FullLoader",
        "fixed": ">=5.4",
    },
    "urllib3": {
        "affected": "<1.26.18",
        "cve": "CVE-2023-45803",
        "description": "Request body and auth header leak on cross-site redirect",
        "fixed": ">=1.26.18",
    },
    "requests": {
        "affected": "<2.31.0",
        "cve": "CVE-2023-32681",
        "description": "Sensitive Proxy-Authorization header leak to destination",
        "fixed": ">=2.31.0",
    },
    "jinja2": {
        "affected": "<3.1.3",
        "cve": "CVE-2024-22195",
        "description": "Cross-site scripting (XSS) via xmlattr filter",
        "fixed": ">=3.1.3",
    },
    "cryptography": {
        "affected": "<41.0.6",
        "cve": "CVE-2023-49083",
        "description": "NULL-dereference crash during PKCS#7 certificate loading",
        "fixed": ">=41.0.6",
    },
    "django": {
        "affected": "<3.2.20",
        "cve": "CVE-2023-38039",
        "description": "DoS and multiple high-severity security vulnerabilities",
        "fixed": ">=3.2.20",
    },
    "express": {
        "affected": "<4.19.2",
        "cve": "CVE-2024-29041",
        "description": "Open redirect and header injection vulnerability in express",
        "fixed": ">=4.19.2",
    },
    "axios": {
        "affected": "<1.6.0",
        "cve": "CVE-2023-45857",
        "description": "Cross-site request forgery and header leak",
        "fixed": ">=1.6.0",
    },
}


def _walk_dependency_files(target_path: str):
    path = Path(target_path)
    if path.is_file():
        if path.name in ("requirements.txt", "package.json", "Pipfile", "pyproject.toml"):
            yield path
        return
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
    }
    for p in path.rglob("*"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.is_file() and p.name in (
            "requirements.txt",
            "package.json",
            "Pipfile",
            "pyproject.toml",
        ):
            yield p


def analyze(target_path: str) -> list[MisconfigFinding]:
    """
    Regola SC-007 (CWE-1395 / CWE-1104):
    Scansiona file di dipendenze per rilevare pacchetti non fissati (wildcard/unpinned)
    o librerie obsolete affette da vulnerabilità e CVE note.
    """
    findings: list[MisconfigFinding] = []

    for dep_file in _walk_dependency_files(target_path):
        # Escludi file di test interni
        if "test/" in dep_file.as_posix() or "tests/" in dep_file.as_posix():
            if not ("vulnerable_app" in dep_file.parts or "test_targets" in dep_file.parts):
                continue

        try:
            if dep_file.name == "requirements.txt":
                findings.extend(_analyze_requirements(dep_file))
            elif dep_file.name == "package.json":
                findings.extend(_analyze_package_json(dep_file))
        except Exception:
            continue

    return findings


def _analyze_requirements(file_path: Path) -> list[MisconfigFinding]:
    findings = []
    lines = file_path.read_text(errors="replace").splitlines()

    for idx, line in enumerate(lines, 1):
        clean_line = line.strip().split("#")[0].strip()
        if not clean_line or clean_line.startswith(("-", "git+", "http://", "https://")):
            continue

        # Estrai nome e versione (es: flask==1.1.2 o requests>=2.20.0 o solo urllib3)
        match = re.match(r"^([a-zA-Z0-9_\-]+)(.*)$", clean_line)
        if not match:
            continue

        pkg_name = match.group(1).lower()
        version_spec = match.group(2).strip()

        # 1. Dipendenza non fissata (wildcard o nessun vincolo)
        if not version_spec or version_spec in ("*", ">=*", "==*"):
            findings.append(
                MisconfigFinding(
                    rule_id="SC-007",
                    cwe_id="CWE-1104",
                    category="vulnerable_dependency",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=idx,
                    evidence=f"Unpinned dependency '{pkg_name}' without fixed version constraint",
                    missing_guard=f"Pin dependency to a specific verified version (e.g. {pkg_name}==x.y.z)",
                    confidence=0.85,
                    layer="ast",
                )
            )
            continue

        # 2. Verifica versione specifica contro database CVE
        if pkg_name in KNOWN_VULNERABILITIES:
            vuln_info = KNOWN_VULNERABILITIES[pkg_name]
            # Estrai versione esatta da ==
            exact_match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", version_spec)
            if exact_match:
                ver_str = exact_match.group(1)
                try:
                    ver = Version(ver_str)
                    spec = SpecifierSet(vuln_info["affected"])
                    if ver in spec:
                        findings.append(
                            MisconfigFinding(
                                rule_id="SC-007",
                                cwe_id="CWE-1395",
                                category="vulnerable_dependency",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=idx,
                                evidence=f"Package '{pkg_name}=={ver_str}' is vulnerable to {vuln_info['cve']}: {vuln_info['description']}",
                                missing_guard=f"Upgrade '{pkg_name}' to patched version {vuln_info['fixed']}",
                                confidence=0.95,
                                layer="ast",
                            )
                        )
                except InvalidVersion:
                    pass

    return findings


def _analyze_package_json(file_path: Path) -> list[MisconfigFinding]:
    findings = []
    try:
        data = json.loads(file_path.read_text(errors="replace"))
    except Exception:
        return findings

    all_deps = {}
    if isinstance(data.get("dependencies"), dict):
        all_deps.update(data["dependencies"])
    if isinstance(data.get("devDependencies"), dict):
        all_deps.update(data["devDependencies"])

    for pkg_name, ver_spec in all_deps.items():
        pkg_lower = pkg_name.lower()
        if not isinstance(ver_spec, str):
            continue

        if ver_spec in ("*", "latest"):
            findings.append(
                MisconfigFinding(
                    rule_id="SC-007",
                    cwe_id="CWE-1104",
                    category="vulnerable_dependency",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=None,
                    evidence=f"Unpinned dependency '{pkg_name}': '{ver_spec}' in package.json",
                    missing_guard=f"Pin '{pkg_name}' to a specific semantic version",
                    confidence=0.85,
                    layer="ast",
                )
            )
            continue

        if pkg_lower in KNOWN_VULNERABILITIES:
            vuln_info = KNOWN_VULNERABILITIES[pkg_lower]
            clean_ver = ver_spec.lstrip("^~= ")
            try:
                ver = Version(clean_ver)
                spec = SpecifierSet(vuln_info["affected"])
                if ver in spec:
                    findings.append(
                        MisconfigFinding(
                            rule_id="SC-007",
                            cwe_id="CWE-1395",
                            category="vulnerable_dependency",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=None,
                            evidence=f"Package '{pkg_name}@{clean_ver}' is vulnerable to {vuln_info['cve']}: {vuln_info['description']}",
                            missing_guard=f"Upgrade '{pkg_name}' to patched version {vuln_info['fixed']}",
                            confidence=0.95,
                            layer="ast",
                        )
                    )
            except InvalidVersion:
                pass

    return findings
