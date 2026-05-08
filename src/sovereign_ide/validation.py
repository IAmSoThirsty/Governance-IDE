from __future__ import annotations

from pathlib import Path
import json
from typing import Any


WORKSPACE_ROOT_PLACEHOLDER = "${SOVEREIGN_WORKSPACE_ROOT}"
MUTATION_CLASSES = {
    "read",
    "softMutation",
    "hardMutation",
    "governanceMutation",
}


class ValidationError(ValueError):
    """Raised when a runtime artifact fails structural validation."""


def render_workspace_root(value: Any, workspace_root: str | Path) -> Any:
    root = str(Path(workspace_root).resolve())
    if isinstance(value, str):
        return value.replace(WORKSPACE_ROOT_PLACEHOLDER, root)
    if isinstance(value, list):
        return [render_workspace_root(item, root) for item in value]
    if isinstance(value, dict):
        return {
            key: render_workspace_root(item, root)
            for key, item in value.items()
        }
    return value


def load_policy_pack(
    policy_path: str | Path,
    workspace_root: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(policy_path)
    policy = json.loads(path.read_text(encoding="utf-8"))
    if workspace_root is not None:
        policy = render_workspace_root(policy, workspace_root)
    validate_policy_pack(policy)
    return policy


def validate_policy_pack(policy: dict[str, Any]) -> None:
    _require_mapping(policy, "policy")
    _require_string(policy, "version", "policy")

    resolution = _require_mapping(policy.get("resolution"), "resolution")
    if resolution.get("default") != "deny":
        raise ValidationError("policy.resolution.default must be deny")
    precedence = _require_list(
        resolution.get("precedence"),
        "resolution.precedence",
    )
    if not precedence or not all(isinstance(item, str) and item for item in precedence):
        raise ValidationError("resolution.precedence must contain strings")

    workspace = _require_mapping(policy.get("workspace"), "workspace")
    roots = _require_list(workspace.get("allowed_roots"), "workspace.allowed_roots")
    if not roots or not all(isinstance(item, str) and item for item in roots):
        raise ValidationError("workspace.allowed_roots must contain strings")

    risk_scores = _require_mapping(policy.get("risk_scores"), "risk_scores")
    for mutation_class in MUTATION_CLASSES:
        score = risk_scores.get(mutation_class)
        if not isinstance(score, int) or not 0 <= score <= 100:
            raise ValidationError(
                f"risk_scores.{mutation_class} must be an integer 0..100",
            )

    actions = _require_mapping(policy.get("actions"), "actions")
    if not actions:
        raise ValidationError("actions must not be empty")

    for action, rule in actions.items():
        if not isinstance(action, str) or not action:
            raise ValidationError("action names must be non-empty strings")
        rule_map = _require_mapping(rule, f"actions.{action}")
        required_class = rule_map.get("required_mutation_class")
        if required_class not in MUTATION_CLASSES:
            raise ValidationError(
                f"actions.{action}.required_mutation_class is invalid",
            )
        roles = _require_list(
            rule_map.get("allowed_roles"),
            f"actions.{action}.allowed_roles",
        )
        if not roles or not all(isinstance(item, str) and item for item in roles):
            raise ValidationError(
                f"actions.{action}.allowed_roles must contain strings",
            )
        if len(set(roles)) != len(roles):
            raise ValidationError(
                f"actions.{action}.allowed_roles contains duplicates",
            )
        if not isinstance(rule_map.get("quorum_required"), bool):
            raise ValidationError(
                f"actions.{action}.quorum_required must be boolean",
            )
        if "risk_score" in rule_map:
            risk_score = rule_map["risk_score"]
            if not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
                raise ValidationError(
                    f"actions.{action}.risk_score must be an integer 0..100",
                )


def validate_repository_artifacts(workspace_root: str | Path) -> None:
    root = Path(workspace_root).resolve()
    for schema_path in (root / "schemas").glob("*.schema.json"):
        json.loads(schema_path.read_text(encoding="utf-8"))

    for policy_path in (root / "policies").glob("*.json"):
        raw_policy = json.loads(policy_path.read_text(encoding="utf-8"))
        if {"resolution", "workspace", "risk_scores", "actions"}.issubset(
            raw_policy.keys(),
        ):
            load_policy_pack(policy_path, workspace_root=root)


def _require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    return value


def _require_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{name} must be an array")
    return value


def _require_string(mapping: dict[str, Any], key: str, name: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{name}.{key} must be a non-empty string")
    return value


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate Sovereign IDE repository artifacts.",
    )
    parser.add_argument("--workspace-root", default=str(Path.cwd()))
    args = parser.parse_args()
    validate_repository_artifacts(args.workspace_root)
    print("Repository artifacts validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
