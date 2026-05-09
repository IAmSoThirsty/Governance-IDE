from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

CATEGORY_REPO_CODE_BLOCKED = "repo-code blocked"
CATEGORY_ENVIRONMENT_BLOCKED = "environment blocked"
CATEGORY_PRODUCTION_EVIDENCE_BLOCKED = "production-evidence blocked"
CATEGORY_DEPENDENCY_SECURITY_BLOCKED = "dependency-security blocked"
CLASSIFICATION_REHEARSAL_ONLY_PASS = "rehearsal-only pass"
CLASSIFICATION_PRODUCTION_READY_PASS = "production-ready pass"

PLACEHOLDER_PATTERN = re.compile(
    r"REPLACE|PLACEHOLDER|CHANGE_ME|replace-with|dummy|example-value",
    re.IGNORECASE,
)
LOCAL_IMAGE_PATTERN = re.compile(
    r"(^localhost[:/])|(^127\.0\.0\.1[:/])|(:local$)", re.IGNORECASE
)
SENSITIVE_FIELD_PATTERN = re.compile(
    r"token|password|secret|private[_-]?key|signing[_-]?key",
    re.IGNORECASE,
)

REQUIRED_MANIFEST_FIELDS = (
    "release_commit",
    "release_tag",
    "registry_image_ref",
    "image_digest",
    "runtime_mode",
    "signer_type",
    "ed25519_key_source_type",
    "secret_source",
    "artifact_store_backend",
    "trainer_backend",
    "storage_backend",
    "audit_journal_backend",
    "ci_run_id",
    "build_timestamp",
    "sbom_location",
    "dependency_scan_result_location",
    "dependency_scan_status",
)

SAFE_SENSITIVE_LIKE_FIELDS = {
    "secret_source",
}


@dataclass(frozen=True)
class EvidenceIssue:
    category: str
    code: str
    message: str


@dataclass(frozen=True)
class EvidenceValidationResult:
    allowed: bool
    classification: str
    production_claim: bool
    issues: tuple[EvidenceIssue, ...]
    warnings: tuple[str, ...]
    overrides_active: tuple[str, ...]
    overridden_evidence: tuple[str, ...]
    manifest_path: str | None
    manifest_summary: dict[str, Any]

    def to_primitive(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "classification": self.classification,
            "production_claim": self.production_claim,
            "issues": [
                {
                    "category": issue.category,
                    "code": issue.code,
                    "message": issue.message,
                }
                for issue in self.issues
            ],
            "warnings": list(self.warnings),
            "overrides_active": list(self.overrides_active),
            "overridden_evidence": list(self.overridden_evidence),
            "manifest_path": self.manifest_path,
            "manifest_summary": self.manifest_summary,
        }


def _placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_PATTERN.search(value))


def _read_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("manifest must be a JSON object")
    return parsed


def _safe_manifest_summary(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "manifest_type": str(manifest.get("manifest_type") or "").strip(),
        "schema_version": str(manifest.get("schema_version") or "").strip(),
        "release_commit": str(manifest.get("release_commit") or "").strip(),
        "release_tag": str(manifest.get("release_tag") or "").strip(),
        "registry_image_ref": str(manifest.get("registry_image_ref") or "").strip(),
        "image_digest": str(manifest.get("image_digest") or "").strip(),
        "runtime_mode": str(manifest.get("runtime_mode") or "").strip(),
        "signer_type": str(manifest.get("signer_type") or "").strip(),
        "ed25519_key_source_type": str(
            manifest.get("ed25519_key_source_type") or "",
        ).strip(),
        "secret_source": str(manifest.get("secret_source") or "").strip(),
        "artifact_store_backend": str(
            manifest.get("artifact_store_backend") or ""
        ).strip(),
        "trainer_backend": str(manifest.get("trainer_backend") or "").strip(),
        "storage_backend": str(manifest.get("storage_backend") or "").strip(),
        "audit_journal_backend": str(
            manifest.get("audit_journal_backend") or ""
        ).strip(),
        "ci_run_id": str(manifest.get("ci_run_id") or "").strip(),
        "build_timestamp": str(manifest.get("build_timestamp") or "").strip(),
        "sbom_location": str(manifest.get("sbom_location") or "").strip(),
        "dependency_scan_result_location": str(
            manifest.get("dependency_scan_result_location") or "",
        ).strip(),
        "dependency_scan_status": str(
            manifest.get("dependency_scan_status") or ""
        ).strip(),
    }


def _get_env(env: Mapping[str, str], name: str) -> str:
    return str(env.get(name, "")).strip()


def determine_ed25519_key_source_type(env: Mapping[str, str]) -> str:
    pem = _get_env(env, "SOVEREIGN_ED25519_PRIVATE_KEY_PEM")
    key_path = _get_env(env, "SOVEREIGN_ED25519_PRIVATE_KEY_PATH")
    if key_path:
        return "file_path"
    if pem:
        return "inline_pem"
    return "missing"


def derive_artifact_store_backend(artifact_store_uri: str) -> str:
    value = artifact_store_uri.strip().lower()
    if not value:
        return "missing"
    if value.startswith("s3://"):
        return "s3"
    if value.startswith("gs://"):
        return "gcs"
    if value.startswith("az://"):
        return "azure_blob"
    if value.startswith("hf://") or value.startswith("huggingface://"):
        return "huggingface"
    if value.startswith("https://huggingface.co"):
        return "huggingface"
    if value.startswith("https://"):
        return "https"
    if value.startswith("file://") or value.startswith("./") or value.startswith(".\\"):
        return "local"
    if "://" not in value:
        return "local"
    return "custom"


def _classify(
    issues: list[EvidenceIssue], overrides_active: tuple[str, ...]
) -> tuple[bool, str, bool]:
    if issues:
        categories = {issue.category for issue in issues}
        if CATEGORY_REPO_CODE_BLOCKED in categories:
            return False, CATEGORY_REPO_CODE_BLOCKED, False
        if CATEGORY_ENVIRONMENT_BLOCKED in categories:
            return False, CATEGORY_ENVIRONMENT_BLOCKED, False
        if CATEGORY_DEPENDENCY_SECURITY_BLOCKED in categories:
            return False, CATEGORY_DEPENDENCY_SECURITY_BLOCKED, False
        return False, CATEGORY_PRODUCTION_EVIDENCE_BLOCKED, False

    if overrides_active:
        return True, CLASSIFICATION_REHEARSAL_ONLY_PASS, False
    return True, CLASSIFICATION_PRODUCTION_READY_PASS, True


def _append_issue(
    issues: list[EvidenceIssue],
    *,
    category: str,
    code: str,
    message: str,
) -> None:
    issues.append(EvidenceIssue(category=category, code=code, message=message))


def _validate_manifest_fields(
    manifest: Mapping[str, Any], issues: list[EvidenceIssue]
) -> None:
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code=f"manifest_field_missing:{field}",
                message=f"production evidence manifest missing required field: {field}",
            )
            continue

        value = str(manifest.get(field) or "").strip()
        if not value:
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code=f"manifest_field_empty:{field}",
                message=f"production evidence manifest field is empty: {field}",
            )
            continue
        if _placeholder(value):
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code=f"manifest_field_placeholder:{field}",
                message=f"production evidence manifest field looks placeholder-like: {field}",
            )

    dependency_scan_status = (
        str(manifest.get("dependency_scan_status") or "").strip().lower()
    )
    if dependency_scan_status and dependency_scan_status != "pass":
        _append_issue(
            issues,
            category=CATEGORY_DEPENDENCY_SECURITY_BLOCKED,
            code=f"dependency_scan_status:{dependency_scan_status}",
            message="dependency scan status is not pass",
        )

    build_timestamp = str(manifest.get("build_timestamp") or "").strip()
    if build_timestamp:
        try:
            datetime.fromisoformat(build_timestamp.replace("Z", "+00:00"))
        except ValueError:
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code="build_timestamp_invalid",
                message="build_timestamp must be ISO-8601",
            )

    for key in manifest.keys():
        key_text = str(key)
        if key_text in SAFE_SENSITIVE_LIKE_FIELDS:
            continue
        if SENSITIVE_FIELD_PATTERN.search(key_text):
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code=f"manifest_sensitive_field:{key_text}",
                message="manifest must not contain secret/token/private-key fields",
            )


def evaluate_production_evidence(
    *,
    workspace_root: Path,
    env: Mapping[str, str] | None = None,
    manifest_path: Path | None = None,
    allow_local_env_file: bool = False,
    allow_local_image: bool = False,
    allow_missing_manifest: bool = False,
) -> EvidenceValidationResult:
    active_env: Mapping[str, str] = env or os.environ
    issues: list[EvidenceIssue] = []
    warnings: list[str] = []
    strict_production_mode = not (
        allow_local_env_file or allow_local_image or allow_missing_manifest
    )

    overrides_active: list[str] = []
    overridden_evidence: list[str] = []

    if allow_local_env_file:
        overrides_active.append("-AllowLocalEnvFile")
        overridden_evidence.append("developer_env_dependency")
    if allow_local_image:
        overrides_active.append("-AllowLocalImage")
        overridden_evidence.append("durable_registry_image_and_digest")
    if allow_missing_manifest:
        overrides_active.append("-AllowMissingReleaseManifest")
        overridden_evidence.append("production_evidence_manifest")

    repo_env_path = workspace_root / ".env"
    if repo_env_path.exists() and not allow_local_env_file:
        _append_issue(
            issues,
            category=CATEGORY_ENVIRONMENT_BLOCKED,
            code="developer_env_dependency",
            message="production readiness must not depend on developer .env",
        )

    runtime_mode = _get_env(active_env, "SOVEREIGN_RUNTIME_MODE").lower() or "local"
    signer_backend = _get_env(active_env, "SOVEREIGN_SIGNER_BACKEND").lower()
    key_source_type = determine_ed25519_key_source_type(active_env)
    service_token = _get_env(active_env, "SOVEREIGN_SERVICE_TOKEN")
    secret_source = _get_env(active_env, "SOVEREIGN_SECRET_SOURCE")
    image_ref = _get_env(active_env, "SOVEREIGN_IMAGE_REF")
    image_digest = _get_env(active_env, "SOVEREIGN_IMAGE_DIGEST")
    training_artifact_store = _get_env(active_env, "SOVEREIGN_TRAINING_ARTIFACT_STORE")
    artifact_store_backend = derive_artifact_store_backend(training_artifact_store)
    trainer_backend = _get_env(active_env, "SOVEREIGN_TRAINING_BACKEND")
    state_backend = _get_env(active_env, "SOVEREIGN_STATE_BACKEND")
    state_uri = _get_env(active_env, "SOVEREIGN_STATE_URI")
    journal_backend = _get_env(active_env, "SOVEREIGN_JOURNAL_BACKEND").lower()

    if strict_production_mode:
        if runtime_mode != "production":
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="runtime_mode_not_production",
                message="SOVEREIGN_RUNTIME_MODE must be production",
            )

        if signer_backend != "ed25519":
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="signer_backend_not_ed25519",
                message="SOVEREIGN_SIGNER_BACKEND must be ed25519 for production",
            )

        if key_source_type == "missing":
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="ed25519_key_source_missing",
                message=(
                    "production signer requires SOVEREIGN_ED25519_PRIVATE_KEY_PATH "
                    "or SOVEREIGN_ED25519_PRIVATE_KEY_PEM"
                ),
            )
        if key_source_type == "inline_pem":
            pem = _get_env(active_env, "SOVEREIGN_ED25519_PRIVATE_KEY_PEM")
            if _placeholder(pem):
                _append_issue(
                    issues,
                    category=CATEGORY_ENVIRONMENT_BLOCKED,
                    code="ed25519_inline_pem_placeholder",
                    message="SOVEREIGN_ED25519_PRIVATE_KEY_PEM looks placeholder-like",
                )
        if key_source_type == "file_path":
            key_path = Path(_get_env(active_env, "SOVEREIGN_ED25519_PRIVATE_KEY_PATH"))
            if not key_path.exists():
                _append_issue(
                    issues,
                    category=CATEGORY_ENVIRONMENT_BLOCKED,
                    code="ed25519_key_path_missing",
                    message="SOVEREIGN_ED25519_PRIVATE_KEY_PATH does not exist",
                )

        if not service_token:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="service_token_missing",
                message="SOVEREIGN_SERVICE_TOKEN is required",
            )
        elif _placeholder(service_token):
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="service_token_placeholder",
                message="SOVEREIGN_SERVICE_TOKEN looks placeholder-like",
            )

        if not secret_source:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="secret_source_missing",
                message="SOVEREIGN_SECRET_SOURCE is required for production evidence",
            )
        elif _placeholder(secret_source) or re.search(
            r"local|dev|test", secret_source, re.IGNORECASE
        ):
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="secret_source_invalid",
                message="SOVEREIGN_SECRET_SOURCE must identify a real production secret provider",
            )

        if not image_ref:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="image_ref_missing",
                message="SOVEREIGN_IMAGE_REF is required",
            )
        elif not allow_local_image:
            if LOCAL_IMAGE_PATTERN.search(image_ref):
                _append_issue(
                    issues,
                    category=CATEGORY_ENVIRONMENT_BLOCKED,
                    code="image_ref_local",
                    message="SOVEREIGN_IMAGE_REF must reference a durable registry image",
                )
            if "/" not in image_ref or ":" not in image_ref:
                _append_issue(
                    issues,
                    category=CATEGORY_ENVIRONMENT_BLOCKED,
                    code="image_ref_not_fully_qualified",
                    message="SOVEREIGN_IMAGE_REF must include registry/namespace and tag",
                )

        if not image_digest and not allow_local_image:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="image_digest_missing",
                message="SOVEREIGN_IMAGE_DIGEST is required",
            )
        elif image_digest and not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", image_digest):
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="image_digest_invalid",
                message="SOVEREIGN_IMAGE_DIGEST must be immutable sha256 digest",
            )

        if not training_artifact_store:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="artifact_store_missing",
                message="SOVEREIGN_TRAINING_ARTIFACT_STORE is required",
            )
        elif artifact_store_backend == "local":
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="artifact_store_local",
                message="artifact store must be durable in production",
            )

        if not trainer_backend:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="trainer_backend_missing",
                message="SOVEREIGN_TRAINING_BACKEND is required",
            )

        if not state_backend:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="state_backend_missing",
                message="SOVEREIGN_STATE_BACKEND is required",
            )
        elif re.fullmatch(r"local|dev|tmp|temporary", state_backend, re.IGNORECASE):
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="state_backend_not_durable",
                message="SOVEREIGN_STATE_BACKEND must be durable for production",
            )

        if not state_uri:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="state_uri_missing",
                message="SOVEREIGN_STATE_URI is required",
            )
        elif re.fullmatch(r"state|\./.+|\.\\.+", state_uri):
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="state_uri_not_durable",
                message="SOVEREIGN_STATE_URI must identify durable backing storage",
            )

        if journal_backend not in {"sqlite", "file"}:
            _append_issue(
                issues,
                category=CATEGORY_ENVIRONMENT_BLOCKED,
                code="journal_backend_invalid",
                message="SOVEREIGN_JOURNAL_BACKEND must be sqlite or file",
            )

    manifest_path_resolved: Path | None = manifest_path
    if manifest_path_resolved is None:
        env_manifest_path = _get_env(
            active_env, "SOVEREIGN_PRODUCTION_EVIDENCE_MANIFEST"
        )
        if not env_manifest_path:
            env_manifest_path = _get_env(active_env, "SOVEREIGN_RELEASE_MANIFEST")
        if env_manifest_path:
            manifest_path_resolved = Path(env_manifest_path)

    manifest_data: dict[str, Any] = {}
    if manifest_path_resolved is None:
        if not allow_missing_manifest:
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code="manifest_path_missing",
                message="production evidence manifest path is required",
            )
    elif not manifest_path_resolved.exists():
        if not allow_missing_manifest:
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code="manifest_not_found",
                message="production evidence manifest file not found",
            )
    else:
        try:
            manifest_data = _read_manifest(manifest_path_resolved)
        except Exception as exc:  # noqa: BLE001
            _append_issue(
                issues,
                category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                code="manifest_parse_failed",
                message=f"production evidence manifest parse failed: {exc}",
            )
        else:
            _validate_manifest_fields(manifest_data, issues)

            if (
                strict_production_mode
                and image_ref
                and str(manifest_data.get("registry_image_ref") or "").strip()
                != image_ref
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_image_ref_mismatch",
                    message="manifest registry_image_ref does not match SOVEREIGN_IMAGE_REF",
                )
            if (
                strict_production_mode
                and image_digest
                and str(manifest_data.get("image_digest") or "").strip() != image_digest
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_image_digest_mismatch",
                    message="manifest image_digest does not match SOVEREIGN_IMAGE_DIGEST",
                )
            if (
                strict_production_mode
                and runtime_mode
                and str(manifest_data.get("runtime_mode") or "").strip().lower()
                != runtime_mode
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_runtime_mode_mismatch",
                    message="manifest runtime_mode does not match SOVEREIGN_RUNTIME_MODE",
                )
            if (
                strict_production_mode
                and signer_backend
                and str(manifest_data.get("signer_type") or "").strip().lower()
                != signer_backend
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_signer_type_mismatch",
                    message="manifest signer_type does not match SOVEREIGN_SIGNER_BACKEND",
                )
            if (
                strict_production_mode
                and key_source_type
                and str(manifest_data.get("ed25519_key_source_type") or "").strip()
                != key_source_type
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_key_source_mismatch",
                    message="manifest ed25519_key_source_type does not match runtime key source",
                )
            if (
                strict_production_mode
                and secret_source
                and str(manifest_data.get("secret_source") or "").strip()
                != secret_source
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_secret_source_mismatch",
                    message="manifest secret_source does not match SOVEREIGN_SECRET_SOURCE",
                )
            if (
                strict_production_mode
                and trainer_backend
                and str(manifest_data.get("trainer_backend") or "").strip()
                != trainer_backend
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_trainer_backend_mismatch",
                    message="manifest trainer_backend does not match SOVEREIGN_TRAINING_BACKEND",
                )
            if (
                strict_production_mode
                and state_backend
                and str(manifest_data.get("storage_backend") or "").strip()
                != state_backend
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_storage_backend_mismatch",
                    message="manifest storage_backend does not match SOVEREIGN_STATE_BACKEND",
                )
            if (
                strict_production_mode
                and journal_backend
                and str(manifest_data.get("audit_journal_backend") or "")
                .strip()
                .lower()
                != journal_backend
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_audit_backend_mismatch",
                    message="manifest audit_journal_backend does not match SOVEREIGN_JOURNAL_BACKEND",
                )
            if (
                strict_production_mode
                and artifact_store_backend
                and str(manifest_data.get("artifact_store_backend") or "").strip()
                != artifact_store_backend
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_artifact_store_backend_mismatch",
                    message="manifest artifact_store_backend does not match resolved artifact store backend",
                )

            try:
                head_commit = subprocess.check_output(
                    ["git", "-C", str(workspace_root), "rev-parse", "HEAD"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
            except Exception:  # noqa: BLE001
                head_commit = ""
                warnings.append("unable to resolve git commit for manifest comparison")

            manifest_commit = str(manifest_data.get("release_commit") or "").strip()
            if (
                head_commit
                and manifest_commit
                and not head_commit.startswith(manifest_commit)
            ):
                _append_issue(
                    issues,
                    category=CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
                    code="manifest_release_commit_mismatch",
                    message="manifest release_commit does not match current git commit",
                )

            if (
                str(manifest_data.get("dependency_scan_status") or "").strip().lower()
                == "pass"
            ):
                dep_scan_ref = str(
                    manifest_data.get("dependency_scan_result_location") or "",
                ).strip()
                if not dep_scan_ref:
                    _append_issue(
                        issues,
                        category=CATEGORY_DEPENDENCY_SECURITY_BLOCKED,
                        code="dependency_scan_reference_missing",
                        message="dependency scan status is pass but location is missing",
                    )

    allowed, classification, production_claim = _classify(
        issues,
        tuple(overrides_active),
    )

    return EvidenceValidationResult(
        allowed=allowed,
        classification=classification,
        production_claim=production_claim,
        issues=tuple(issues),
        warnings=tuple(warnings),
        overrides_active=tuple(overrides_active),
        overridden_evidence=tuple(overridden_evidence),
        manifest_path=(str(manifest_path_resolved) if manifest_path_resolved else None),
        manifest_summary=_safe_manifest_summary(manifest_data) if manifest_data else {},
    )


def safe_runtime_evidence_status(
    workspace_root: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    active_env: Mapping[str, str] = env or os.environ
    result = evaluate_production_evidence(
        workspace_root=workspace_root,
        env=active_env,
        allow_local_env_file=False,
        allow_local_image=False,
        allow_missing_manifest=False,
    )
    return {
        **result.to_primitive(),
        "runtime_mode": _get_env(active_env, "SOVEREIGN_RUNTIME_MODE") or "local",
        "signer_backend": _get_env(active_env, "SOVEREIGN_SIGNER_BACKEND")
        or "hmac-dev",
        "journal_backend": _get_env(active_env, "SOVEREIGN_JOURNAL_BACKEND")
        or "sqlite",
        "artifact_store_backend": derive_artifact_store_backend(
            _get_env(active_env, "SOVEREIGN_TRAINING_ARTIFACT_STORE"),
        ),
        "ed25519_key_source_type": determine_ed25519_key_source_type(active_env),
    }


def _parse_args() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate sovereign production evidence contract"
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--manifest-path", default="")
    parser.add_argument("--allow-local-env-file", action="store_true")
    parser.add_argument("--allow-local-image", action="store_true")
    parser.add_argument("--allow-missing-manifest", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    workspace_root = Path(args.workspace_root).resolve()
    manifest_path = Path(args.manifest_path).resolve() if args.manifest_path else None

    result = evaluate_production_evidence(
        workspace_root=workspace_root,
        manifest_path=manifest_path,
        allow_local_env_file=bool(args.allow_local_env_file),
        allow_local_image=bool(args.allow_local_image),
        allow_missing_manifest=bool(args.allow_missing_manifest),
    )

    payload = result.to_primitive()
    print(json.dumps(payload, ensure_ascii=False))

    if args.status_only:
        return 0
    return 0 if payload["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
