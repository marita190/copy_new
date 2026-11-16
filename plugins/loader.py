import importlib
import pkgutil
from pathlib import Path

def discover_plugins() -> list:
    tools = []
    plugins_dir = Path(__file__).parent

    for finder, name, ispkg in pkgutil.iter_modules([str(plugins_dir)]):
        if name.startswith("_") or name == "loader":
            continue
        try:
            module = importlib.import_module(f"plugins.{name}")
            if hasattr(module, "PLUGIN_TOOLS"):
                tools.extend(module.PLUGIN_TOOLS)
                print(f"[plugins] загружен: {name}")
        except Exception as e:
            print(f"[plugins] ошибка загрузки {name}: {e}")

    return tools
