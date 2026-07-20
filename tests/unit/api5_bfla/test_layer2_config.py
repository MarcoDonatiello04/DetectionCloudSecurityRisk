import pathlib
import tempfile

from src.core.api5_bfla.layers.layer2_config import (
    analyze_configs,
    discover_config_files,
)


def test_discover_config_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        settings_file = tmp_path / "settings.py"
        settings_file.write_text("DEBUG = True")

        discovered = discover_config_files(tmpdir)
        assert len(discovered) == 1
        assert discovered[0].name == "settings.py"


def test_analyze_configs_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings = analyze_configs(tmpdir)
        assert findings == []
