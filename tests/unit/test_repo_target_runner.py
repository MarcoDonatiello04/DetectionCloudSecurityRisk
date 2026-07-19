"""Test della conversione OpenAPI -> inventario usata dal runner BOLA repo-target."""

from entrypoints.runners.run_bola_repo_target import build_inventory_from_openapi


def test_build_inventory_extracts_methods_and_paths():
    spec = {
        "paths": {
            "/api/projects/{id}": {"get": {}, "delete": {}},
            "/api/invoices/{id}": {"get": {}},
        }
    }
    inv = build_inventory_from_openapi(spec)
    entries = {(e["api"]["method"], e["api"]["endpoint"]) for e in inv}
    assert entries == {
        ("GET", "/api/projects/{id}"),
        ("DELETE", "/api/projects/{id}"),
        ("GET", "/api/invoices/{id}"),
    }


def test_build_inventory_ignores_non_http_keys():
    # 'parameters' e altri campi a livello di path non sono metodi HTTP.
    spec = {"paths": {"/x/{id}": {"parameters": [{"name": "id"}], "get": {}}}}
    inv = build_inventory_from_openapi(spec)
    assert inv == [{"api": {"endpoint": "/x/{id}", "method": "GET"}}]


def test_build_inventory_empty_spec():
    assert build_inventory_from_openapi({}) == []
    assert build_inventory_from_openapi({"paths": {}}) == []
