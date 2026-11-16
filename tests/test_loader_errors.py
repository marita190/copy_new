"""Tests for edge cases in the plugin loader."""

from pathlib import Path
from plugins.loader import discover_plugins
import plugins.loader

def test_loader_ignores_invalid_plugins(tmp_path, monkeypatch):
    """Загрузчик должен пропускать папки без PLUGIN_TOOLS и не падать."""
    
    fake_plugins_dir = tmp_path / "plugins"
    fake_plugins_dir.mkdir()
    
    bad_plugin = fake_plugins_dir / "bad_plugin"
    bad_plugin.mkdir()
    (bad_plugin / "__init__.py").write_text("# No PLUGIN_TOOLS here")
    
    # Подменяем путь к папке плагинов
    monkeypatch.setattr(plugins.loader.Path, "parent", fake_plugins_dir)
    
    tools = discover_plugins()
    assert tools == []
# source .venv/bin/activate
# pytest tests/test_loader_errors.py -v