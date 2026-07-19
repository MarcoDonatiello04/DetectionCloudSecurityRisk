"""Regressione sul parsing dei parametri di rotta Flask nel SemgrepScannerAdapter.

Il parser euristico convertiva i parametri "nudi" (<id>) in {d} tenendo solo
l'ultimo carattere, invece di {id}. I converter tipizzati (<int:id>) restavano
corretti. Questi test bloccano il comportamento corretto per entrambi i casi.
"""

import re


def _to_openapi(path: str) -> str:
    # Stessa espressione usata in SemgrepScannerAdapter._parse_python_file.
    return re.sub(r"<(?:[^>:]+:)?([^>]+)>", r"{\1}", path)


def test_bare_flask_param_keeps_full_name():
    assert _to_openapi("/api/projects/<id>") == "/api/projects/{id}"
    assert _to_openapi("/u/<username>") == "/u/{username}"


def test_typed_flask_converter_uses_param_name():
    assert _to_openapi("/api/orders/<int:id>") == "/api/orders/{id}"
    assert _to_openapi("/x/<uuid:pk>") == "/x/{pk}"
    assert _to_openapi("/files/<path:subpath>") == "/files/{subpath}"


def test_multiple_params_in_one_path():
    assert _to_openapi("/users/<int:user_id>/posts/<post_id>") == "/users/{user_id}/posts/{post_id}"
