"""Smoke test and client-side gating tests for timeout rule module."""

from pathlib import Path

import tree_sitter_javascript as tsjavascript
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.unrestricted_resource_consumption.rules.timeout import TimeoutRule


def test_rule_has_analyze_python():
    assert callable(getattr(TimeoutRule, "analyze_python", None))


def test_rule_has_analyze_javascript():
    assert callable(getattr(TimeoutRule, "analyze_javascript", None))


def test_rule_ids_defined():
    assert TimeoutRule.rule_id.startswith("RC-")
    assert TimeoutRule.cwe_id.startswith("CWE-")
    assert TimeoutRule.severity in ("HIGH", "MEDIUM", "LOW")


def analyze_rule(content: str, file_path: Path):
    ext = file_path.suffix.lower()
    if ext in (".py",):
        lang = Language(tspython.language())
        parser = Parser(lang)
        tree = parser.parse(content.encode())
        findings = TimeoutRule.analyze_python(tree.root_node, str(file_path))
    else:
        lang = Language(tsjavascript.language())
        parser = Parser(lang)
        tree = parser.parse(content.encode())
        findings = TimeoutRule.analyze_javascript(tree.root_node, str(file_path))

    # De-duplicate findings like the AST layer does
    seen = {}
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def test_rc003_no_finding_on_redux_saga():
    """fetch() in Redux Saga non deve produrre RC-003"""
    content = """
function* loginSaga(action) {
    const response = yield call(fetch, "/api/login", {
        method: "POST",
        body: JSON.stringify(action.payload)
    });
    yield put(loginSuccess(response));
}
export function* watchLogin() {
    yield takeEvery("LOGIN_REQUEST", loginSaga);
}
"""
    findings = analyze_rule(content, file_path=Path("userSaga.ts"))
    assert len(findings) == 0, f"FP: RC-003 su Redux Saga: {findings}"


def test_rc003_no_finding_on_react_component():
    """fetch() in componente React non deve produrre RC-003"""
    content = """
import React, { useState, useEffect } from 'react';

function UserProfile({ userId }) {
    const [user, setUser] = useState(null);
    useEffect(() => {
        fetch(`/api/users/${userId}`)
            .then(r => r.json())
            .then(setUser);
    }, [userId]);
    return <div>{user?.name}</div>;
}
"""
    findings = analyze_rule(content, file_path=Path("UserProfile.tsx"))
    assert len(findings) == 0, f"FP: RC-003 su React component: {findings}"


def test_rc003_tp_on_backend_typescript():
    """fetch() in backend TypeScript (Express) senza timeout → RC-003"""
    content = """
import express from 'express';
const app = express();

app.post('/notify', async (req, res) => {
    const response = await fetch('https://api.sms-provider.com/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: req.body.phone })
    });
    res.json({ ok: true });
});
"""
    findings = analyze_rule(content, file_path=Path("routes/notify.ts"))
    assert len(findings) == 1
    assert findings[0].rule_id == "RC-003"


def test_rc003_no_finding_on_service_worker():
    """fetch() in Service Worker non deve produrre RC-003"""
    content = """
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            if (response) return response;
            return fetch(event.request, {
                headers: { "Service-Worker": "script" }
            });
        })
    );
});
self.skipWaiting();
"""
    findings = analyze_rule(content, file_path=Path("serviceWorker.js"))
    assert len(findings) == 0, f"FP: RC-003 su Service Worker: {findings}"
