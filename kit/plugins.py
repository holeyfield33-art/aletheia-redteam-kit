from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol


class RunnerPlugin(Protocol):
    def transform_attacks(self, attacks: list[dict], args: Any) -> list[dict] | None: ...

    def transform_result(self, result: dict, attack: dict, args: Any) -> dict | None: ...

    def finalize_summary(self, summary: dict, results: list[dict], args: Any) -> dict | None: ...


def plugin_name(plugin: Any) -> str:
    return str(
        getattr(plugin, "name", None)
        or getattr(plugin, "__name__", None)
        or plugin.__class__.__name__
    )


def load_runner_plugins(specs: list[str] | None) -> list[RunnerPlugin]:
    plugins: list[RunnerPlugin] = []
    for spec in specs or []:
        module_spec, attr_name = _split_plugin_spec(spec)
        module = _load_plugin_module(module_spec)
        plugin = getattr(module, attr_name) if attr_name else getattr(module, "plugin", module)
        if not _supports_runner_hooks(plugin):
            raise TypeError(
                f"Plugin '{spec}' must expose at least one of: transform_attacks, transform_result, finalize_summary"
            )
        plugins.append(plugin)
    return plugins


def _split_plugin_spec(spec: str) -> tuple[str, str | None]:
    raw = str(spec).strip()
    if not raw:
        raise ValueError("Plugin spec cannot be empty")
    if ":" not in raw:
        return raw, None
    module_spec, attr_name = raw.rsplit(":", 1)
    return module_spec, attr_name or None


def _load_plugin_module(spec: str) -> ModuleType:
    candidate = Path(spec)
    if spec.endswith(".py") or candidate.exists():
        path = candidate.resolve()
        module_name = f"aletheia_runner_plugin_{path.stem}_{abs(hash(str(path)))}"
        module_spec = importlib.util.spec_from_file_location(module_name, path)
        if module_spec is None or module_spec.loader is None:
            raise ImportError(f"Unable to load plugin module from path: {path}")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        return module
    return importlib.import_module(spec)


def _supports_runner_hooks(plugin: Any) -> bool:
    return any(
        callable(getattr(plugin, hook_name, None))
        for hook_name in ("transform_attacks", "transform_result", "finalize_summary")
    )