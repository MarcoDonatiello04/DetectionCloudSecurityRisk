"""
Metriche di accuratezza (src/application/evaluation/accuracy.py).

Riferimenti, evidenze e codice sono sintetici e scritti in cartelle temporanee: i test non
leggono i bersagli dell'insieme di prova né i loro riferimenti di verità.
"""

import json

import pytest

from src.application.evaluation import accuracy as acc

GROUND_TRUTH = """
bersaglio: finto
voci:
  - id: X01
    nome_autore: "BOLA sui libri"
    punto_esposizione: {metodo: GET, percorso: "/books/v1/{book}"}
    categoria_owasp_2023: API1
  - id: X02
    nome_autore: "Cambio password altrui"
    punto_esposizione: {metodo: PUT, percorso: "/users/v1/{username}/password"}
    posizione_dichiarata: "api_views/users.py, update_password [BLOG]"
    categoria_owasp_2023: API1
    alternativa_accettata: API2
  - id: X03
    nome_autore: "Nessun limite di frequenza"
    punto_esposizione: globale
    categoria_owasp_2023: API4
  - id: X04
    nome_autore: "Iniezione SQL"
    punto_esposizione: {metodo: GET, percorso: "/users/v1/{username}"}
    categoria_owasp_2023: FUORI_TOP10
  - id: X05
    nome_autore: "Mass assignment"
    punto_esposizione: {metodo: POST, percorso: "/users/v1/register"}
    categoria_owasp_2023: API3
"""

USERS_PY = """
def login_user():
    return 1


def update_password(username):
    user = find(username)
    user.password = request.json["password"]
    return user
"""


@pytest.fixture
def setup(tmp_path):
    gt = tmp_path / "finto.yaml"
    gt.write_text(GROUND_TRUTH, encoding="utf-8")
    code = tmp_path / "code"
    (code / "api_views").mkdir(parents=True)
    (code / "api_views" / "users.py").write_text(USERS_PY, encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    core = {
        "findings": {
            "bola": [
                {"method": "GET", "endpoint": "/books/v1/libro_di_bob", "is_vulnerable": True},
                {"method": "GET", "endpoint": "/users/v1/bob", "is_vulnerable": False},
            ],
            "broken_authentication": [
                {"test_id": "T03", "nome": "Brute force", "stato": "FAIL"},
                {"test_id": "T01", "nome": "JWT", "stato": "PASS"},
            ],
            # Cambio password: segnalazione statica su file e riga, dentro update_password
            "bfla": [
                {
                    "rule_id": "BF-002",
                    "category": "auth_without_authz",
                    "file_path": str(code / "api_views" / "users.py"),
                    "line_number": 8,
                }
            ],
            "unrestricted_resource_consumption": [
                {"rule_id": "RC-007", "category": "no_container_resource_limit"}
            ],
            "ssrf": [{"rule_id": "SS-001", "file_path": "api_views/books.py", "line_number": 3}],
        }
    }
    (evidence / "core_findings.json").write_text(json.dumps(core), encoding="utf-8")
    static = [
        {
            "source": "SPECTRAL",
            "rule_id": "owasp-api2-operation-security",
            "raw_data": {"path": ["paths", "/users/v1/{username}/password", "put"]},
            "location": {"start_line": 40},
        },
        {
            "source": "SEMGREP",
            "rule_id": "api-route-discovery",
            "raw_data": {},
            "api": {"endpoint": "/users/v1/register", "method": "POST"},
        },
    ]
    (evidence / "unified_security_report.json").write_text(json.dumps(static), encoding="utf-8")
    _, entries = acc.load_ground_truth(gt)
    signals = acc.load_signals(evidence, code)
    return entries, signals


def _outcomes(report):
    return {v["id"]: (v["esito"], v["come"]) for v in report["voci"]}


def test_path_normalization_and_matching():
    assert acc.normalize_path("/users/v1/<username>/") == "/users/v1/{}"
    assert acc.normalize_path("/api/user/:id?x=1") == "/api/user/{}"
    assert acc.path_matches("/books/v1/libro_di_bob", "/books/v1/{book}")
    assert acc.path_matches("/books/v1/{title}", "/books/v1/{book}")
    assert not acc.path_matches("/books/v1", "/books/v1/{book}")
    assert not acc.path_matches("/books/v2/x", "/books/v1/{book}")


def test_signals_exclude_safe_results_and_route_inventory(setup):
    _, signals = setup
    ids = {s.id for s in signals}
    assert "bola:GET /books/v1/libro_di_bob" in ids
    assert not any("/users/v1/bob" in i for i in ids)  # esito sicuro: non è una segnalazione
    assert "broken_authentication:T03" in ids and "broken_authentication:T01" not in ids
    assert not any(s.origin == "SEMGREP" for s in signals)  # inventario, non segnalazione
    bfla = next(s for s in signals if s.origin == "bfla")
    assert bfla.function == "update_password" and bfla.file == "api_views/users.py"


def test_automatic_matching(setup):
    entries, signals = setup
    report = acc.evaluate(entries, signals)
    out = _outcomes(report)
    assert out["X01"] == ("VP", "percorso")  # BOLA dinamica, percorso concreto
    assert out["X02"] == ("VP", "percorso")  # Spectral API2, alternativa accettata
    assert out["X03"][0] == "CANDIDATO"  # globale: decide la classificazione manuale
    assert out["X04"][0] == "ESCLUSA"  # fuori dalla Top 10: non conta
    assert out["X05"][0] == "FN"


def test_position_matching_when_no_endpoint(setup):
    entries, signals = setup
    without_spectral = [s for s in signals if s.origin != "SPECTRAL"]
    out = _outcomes(acc.evaluate(entries, without_spectral))
    # BFLA (API5) non è né la categoria né l'alternativa di X02: resta solo la prova T03
    # della Broken Authentication (API2, livello applicativo) come candidata
    assert out["X02"][0] == "CANDIDATO"
    bfla = next(s for s in without_spectral if s.origin == "bfla")
    bfla.category = "API1"
    assert _outcomes(acc.evaluate(entries, without_spectral))["X02"] == ("VP", "posizione")


def test_metrics_and_bounds(setup):
    entries, signals = setup
    total = acc.evaluate(entries, signals)["complessivo"]
    assert total["voci"] == 4  # X04 è esclusa
    assert (total["vp"], total["fn"], total["candidati"]) == (2, 1, 1)
    assert total["recall"] == pytest.approx(0.5)
    assert total["recall_massima"] == pytest.approx(0.75)
    # Senza classificazione manuale la precisione resta un limite inferiore
    assert total["precisione"] is None
    assert 0 < total["precisione_minima"] < 1


def test_manual_decisions(setup):
    entries, signals = setup
    rc = next(s.id for s in signals if s.origin == "unrestricted_resource_consumption")
    ssrf = next(s.id for s in signals if s.origin == "ssrf")
    decisions = {
        "voci": {
            "X03": {
                "esito": "FN",
                "motivo": "il limite sui container non è un limite di frequenza",
            },
            "X05": {"fuori_perimetro": "modulo non applicabile al linguaggio"},
        },
        "segnalazioni": {
            rc: {"classe": "vero_non_documentato", "motivo": "nessun limite di memoria"},
            ssrf: {"classe": "falso_positivo", "motivo": "URL fisso"},
        },
    }
    report = acc.evaluate(entries, signals, decisions)
    out = _outcomes(report)
    assert out["X03"] == ("FN", "decisione")
    assert out["X05"] == ("FUORI_PERIMETRO", "decisione")
    total = report["complessivo"]
    assert total["recall"] == pytest.approx(2 / 4)
    assert total["recall_nel_perimetro"] == pytest.approx(2 / 3)


def test_vp_decision_must_cite_a_signal(setup):
    entries, signals = setup
    with pytest.raises(ValueError):
        acc.evaluate(entries, signals, {"voci": {"X03": {"esito": "VP"}}, "segnalazioni": {}})


def test_infrastructure_entries_need_manual_mapping(tmp_path):
    gt = tmp_path / "iac.yaml"
    gt.write_text(
        """
bersaglio: iac
voci:
  - id: S01
    misconfigurazione: no_log_file_validation
    modulo_terraform: modules/aws/cloudtrail
  - id: S02
    misconfigurazione: ebs_volume_unencrypted
    modulo_terraform: modules/aws/ebs
  - id: S03
    misconfigurazione: no_access_logs
    modulo_terraform: modules/aws/cloud
""",
        encoding="utf-8",
    )
    evidence = tmp_path / "ev"
    evidence.mkdir()
    static = [
        {
            "source": "CHECKOV",
            "rule_id": "CKV_AWS_36",
            "raw_data": {
                "check_id": "CKV_AWS_36",
                "file_path": "/modules/aws/cloudtrail/main.tf",
                "resource": "module.cloudtrail.aws_cloudtrail.main",
                "check_name": "Ensure CloudTrail log file validation is enabled",
            },
        }
    ]
    # Controllo assorbito dalla correlazione sulla stessa voce: deve diventare una segnalazione
    static[0]["raw_data"]["merged_checkov-x"] = {
        "check_id": "CKV_AWS_252",
        "file_path": "/modules/aws/cloudtrail/main.tf",
        "resource": "module.cloudtrail.aws_cloudtrail.main",
        "check_name": "Ensure CloudTrail defines an SNS Topic",
    }
    (evidence / "unified_security_report.json").write_text(json.dumps(static), encoding="utf-8")
    _, entries = acc.load_ground_truth(gt)
    signals = acc.load_signals(evidence)
    assert {s.id.split(":")[1] for s in signals} == {"CKV_AWS_36", "CKV_AWS_252"}
    out = _outcomes(acc.evaluate(entries, signals))
    # modules/aws/cloud non è la cartella di modules/aws/cloudtrail: nessun candidato
    assert out == {"S01": ("CANDIDATO", ""), "S02": ("FN", ""), "S03": ("FN", "")}
    decided = acc.evaluate(
        entries,
        signals,
        {"voci": {"S01": {"esito": "VP", "segnalazioni": [signals[0].id]}}, "segnalazioni": {}},
    )
    assert _outcomes(decided)["S01"] == ("VP", "decisione")
    assert decided["complessivo"]["precisione_minima"] == pytest.approx(0.5)


def test_markdown_report(setup):
    entries, signals = setup
    md = acc.to_markdown("finto", acc.evaluate(entries, signals))
    assert "| Totale | 4 | 2 | 1 | 1 |" in md
    assert "X01 BOLA sui libri" in md
