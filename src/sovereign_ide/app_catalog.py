from __future__ import annotations

import json
from pathlib import Path
from typing import Any


APP_STATUSES = {
    "enabled",
    "available",
    "requires_configuration",
    "planned",
    "disabled",
}


class AppCatalogError(ValueError):
    """Raised when the app catalog is missing or malformed."""


def default_catalog_path(workspace_root: str | Path) -> Path:
    return Path(workspace_root).resolve() / "deployments" / "app_catalog.json"


def load_app_catalog(
    workspace_root: str | Path,
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(catalog_path) if catalog_path else default_catalog_path(workspace_root)
    catalog = json.loads(path.read_text(encoding="utf-8"))
    validate_app_catalog(catalog)
    apps = sorted(catalog["apps"], key=lambda item: item["id"])
    return {
        "version": catalog["version"],
        "generated_by": catalog.get("generated_by", "sovereign-ide"),
        "app_count": len(apps),
        "apps": apps,
    }


def filter_app_catalog(
    catalog: dict[str, Any],
    *,
    category: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    apps = list(catalog["apps"])
    if category:
        apps = [app for app in apps if app["category"] == category]
    if status:
        apps = [app for app in apps if app["status"] == status]
    return {
        **catalog,
        "app_count": len(apps),
        "apps": apps,
    }


def validate_app_catalog(catalog: dict[str, Any]) -> None:
    if not isinstance(catalog, dict):
        raise AppCatalogError("app catalog must be an object")
    _require_string(catalog, "version", "catalog")
    apps = catalog.get("apps")
    if not isinstance(apps, list) or not apps:
        raise AppCatalogError("catalog.apps must be a non-empty array")

    seen_ids: set[str] = set()
    for index, app in enumerate(apps):
        name = f"catalog.apps[{index}]"
        if not isinstance(app, dict):
            raise AppCatalogError(f"{name} must be an object")
        app_id = _require_string(app, "id", name)
        if app_id in seen_ids:
            raise AppCatalogError(f"duplicate app id: {app_id}")
        seen_ids.add(app_id)
        _require_string(app, "display_name", name)
        _require_string(app, "category", name)
        status = _require_string(app, "status", name)
        if status not in APP_STATUSES:
            raise AppCatalogError(f"{name}.status is invalid: {status}")
        _require_string(app, "description", name)
        _require_list_of_strings(app, "requirements", name)
        _require_list_of_strings(app, "governance_actions", name)
        _require_list_of_strings(app, "tags", name)

        surfaces = app.get("surfaces")
        if not isinstance(surfaces, list) or not surfaces:
            raise AppCatalogError(f"{name}.surfaces must be a non-empty array")
        for surface_index, surface in enumerate(surfaces):
            surface_name = f"{name}.surfaces[{surface_index}]"
            if not isinstance(surface, dict):
                raise AppCatalogError(f"{surface_name} must be an object")
            _require_string(surface, "type", surface_name)
            _require_string(surface, "ref", surface_name)


def _require_string(mapping: dict[str, Any], key: str, name: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AppCatalogError(f"{name}.{key} must be a non-empty string")
    return value


def _require_list_of_strings(
    mapping: dict[str, Any],
    key: str,
    name: str,
) -> list[str]:
    values = mapping.get(key)
    if not isinstance(values, list):
        raise AppCatalogError(f"{name}.{key} must be an array")
    if not all(isinstance(item, str) and item.strip() for item in values):
        raise AppCatalogError(f"{name}.{key} must contain strings")
    return values
