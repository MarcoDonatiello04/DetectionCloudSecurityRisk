import pytest

from src.core.api2_broken_auth.ast_parser import (
    UnsupportedLanguageException,
    run,
)
from src.core.api2_broken_auth.discovery import Config, StackInfo


@pytest.mark.asyncio
async def test_python_import_jwt(tmp_path):
    # Create a test python file that imports jwt
    py_file = tmp_path / "auth_import.py"
    py_file.write_text("import jwt\n", encoding="utf-8")

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    config = Config()
    config.scanner.score_minimo = 1

    results = await run(str(tmp_path), stack, config)

    assert len(results) == 1
    assert results[0].file == "auth_import.py"
    assert results[0].score == 1
    assert any("import jwt" in imp for imp in results[0].imports_auth)


@pytest.mark.asyncio
async def test_python_no_auth(tmp_path):
    # Create a test python file with no security/auth keywords
    py_file = tmp_path / "math_utils.py"
    py_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    # score_minimo is 1, so this file with score 0 should be filtered out
    config = Config()
    config.scanner.score_minimo = 1

    results = await run(str(tmp_path), stack, config)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_route_detection(tmp_path):
    # Create a test python file with routes
    py_file = tmp_path / "routes.py"
    py_code = "@app.post('/login')\ndef login_handler():\n    pass\n"
    py_file.write_text(py_code, encoding="utf-8")

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    config = Config()
    config.scanner.score_minimo = 1

    results = await run(str(tmp_path), stack, config)

    assert len(results) == 1
    assert results[0].file == "routes.py"
    assert results[0].score == 1
    assert any("login" in r for r in results[0].route_auth)


@pytest.mark.asyncio
async def test_env_var_detection(tmp_path):
    # Create a test python file with env vars usage
    py_file = tmp_path / "config.py"
    py_code = "secret = os.environ.get('JWT_SECRET')\n"
    py_file.write_text(py_code, encoding="utf-8")

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    config = Config()
    config.scanner.score_minimo = 1

    results = await run(str(tmp_path), stack, config)

    assert len(results) == 1
    assert results[0].file == "config.py"
    assert results[0].score == 1
    assert any("JWT_SECRET" in env for env in results[0].env_vars_auth)


@pytest.mark.asyncio
async def test_score_filtering_and_limits(tmp_path):
    # Create three files with different scores:
    # 1. file_high.py (score 4)
    file_high = tmp_path / "file_high.py"
    file_high_code = (
        "import jwt\n"
        "@app.post('/login')\n"
        "def login_handler():\n"
        "    sec = os.getenv('JWT_SECRET')\n"
        "    return jwt.encode({'val': 123}, sec)\n"
    )
    file_high.write_text(file_high_code, encoding="utf-8")

    # 2. file_med.py (score 2)
    file_med = tmp_path / "file_med.py"
    file_med_code = "import jwt\nsec = os.getenv('JWT_SECRET')\n"
    file_med.write_text(file_med_code, encoding="utf-8")

    # 3. file_low.py (score 0)
    file_low = tmp_path / "file_low.py"
    file_low.write_text("print('hello')\n", encoding="utf-8")

    stack = StackInfo(
        linguaggio="python",
        framework="FastAPI",
        librerie_auth=["jwt"],
        file_configurazione_rilevanti=[],
    )

    config = Config()

    # Test case 1: score_minimo = 2, max_file_per_fase = 50 -> should return high and med files
    config.scanner.score_minimo = 2
    config.scanner.max_file_per_fase = 50
    results = await run(str(tmp_path), stack, config)
    assert len(results) == 2
    assert results[0].file == "file_high.py"
    assert results[0].score == 4
    assert results[1].file == "file_med.py"
    assert results[1].score == 2

    # Test case 2: score_minimo = 2, max_file_per_fase = 1 -> should return only the high score file
    config.scanner.max_file_per_fase = 1
    results_limited = await run(str(tmp_path), stack, config)
    assert len(results_limited) == 1
    assert results_limited[0].file == "file_high.py"
    assert results_limited[0].score == 4


@pytest.mark.asyncio
async def test_unsupported_language():
    stack = StackInfo(
        linguaggio="cobol", framework="legacy", librerie_auth=[], file_configurazione_rilevanti=[]
    )
    config = Config()

    with pytest.raises(UnsupportedLanguageException) as exc_info:
        await run("/tmp", stack, config)
    assert "non è supportato dal parser tree-sitter" in str(exc_info.value)
