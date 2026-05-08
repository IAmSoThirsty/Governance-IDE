from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import os


SIGNING_KEY_PLACEHOLDER = "REPLACE_WITH_64_BYTE_HEX_OR_HIGH_ENTROPY_SECRET"
MIN_SIGNING_KEY_LENGTH = 64


@dataclass(frozen=True)
class Settings:
    workspace_root: Path
    runtime_mode: str
    signing_key: str
    signer_backend: str
    signer_key_id: str
    ed25519_private_key_pem: str
    ed25519_private_key_path: Path | None
    policy_path: Path
    state_dir: Path
    journal_path: Path
    journal_backend: str
    sqlite_journal_path: Path
    provenance_path: Path
    supply_chain_path: Path
    model_registry_path: Path


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return

    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def _require_signing_key() -> str:
    signing_key = os.getenv("SOVEREIGN_SIGNING_KEY", "").strip()

    if not signing_key or signing_key == SIGNING_KEY_PLACEHOLDER:
        raise ValueError(
            "SOVEREIGN_SIGNING_KEY must be explicitly configured "
            "with high-entropy key material.",
        )

    if len(signing_key) < MIN_SIGNING_KEY_LENGTH:
        raise ValueError(
            "SOVEREIGN_SIGNING_KEY is too short; "
            f"minimum length is {MIN_SIGNING_KEY_LENGTH} characters.",
        )

    return signing_key


def _runtime_mode() -> str:
    runtime_mode = os.getenv("SOVEREIGN_RUNTIME_MODE", "local").strip().lower()
    aliases = {
        "dev": "local",
        "development": "local",
        "prod": "production",
    }
    normalized = aliases.get(runtime_mode, runtime_mode)
    if normalized not in {"local", "rehearsal", "production"}:
        raise ValueError(
            "SOVEREIGN_RUNTIME_MODE must be one of local, rehearsal, production",
        )
    return normalized


def _resolve_signing_key(*, signer_backend: str) -> str:
    if signer_backend == "hmac-dev":
        return _require_signing_key()
    return os.getenv("SOVEREIGN_SIGNING_KEY", "").strip()


def _resolve_optional_path(root: Path, raw: str) -> Path | None:
    value = raw.strip()
    if not value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate.resolve()


@lru_cache(maxsize=1)
def get_settings(workspace_root: str | Path | None = None) -> Settings:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path.cwd().resolve()
    )
    _load_dotenv(root / ".env")

    policy_path_env = os.getenv(
        "SOVEREIGN_POLICY_PATH",
        "policies/baseline_policy.json",
    )
    runtime_mode = _runtime_mode()
    signer_backend = os.getenv("SOVEREIGN_SIGNER_BACKEND", "hmac-dev").strip()
    if signer_backend not in {"hmac-dev", "ed25519"}:
        raise ValueError("SOVEREIGN_SIGNER_BACKEND must be hmac-dev or ed25519")

    signing_key = _resolve_signing_key(signer_backend=signer_backend)
    policy_path = (root / policy_path_env).resolve()
    state_dir = (root / os.getenv("SOVEREIGN_STATE_DIR", "state")).resolve()
    journal_backend = os.getenv("SOVEREIGN_JOURNAL_BACKEND", "sqlite").strip()
    if journal_backend not in {"sqlite", "file"}:
        raise ValueError("SOVEREIGN_JOURNAL_BACKEND must be sqlite or file")

    return Settings(
        workspace_root=root,
        runtime_mode=runtime_mode,
        signing_key=signing_key,
        signer_backend=signer_backend,
        signer_key_id=os.getenv("SOVEREIGN_SIGNER_KEY_ID", "").strip(),
        ed25519_private_key_pem=os.getenv(
            "SOVEREIGN_ED25519_PRIVATE_KEY_PEM",
            "",
        ).strip(),
        ed25519_private_key_path=_resolve_optional_path(
            root,
            os.getenv("SOVEREIGN_ED25519_PRIVATE_KEY_PATH", ""),
        ),
        policy_path=policy_path,
        state_dir=state_dir,
        journal_path=state_dir / "governance_journal.jsonl",
        journal_backend=journal_backend,
        sqlite_journal_path=state_dir / "governance_events.sqlite3",
        provenance_path=state_dir / "provenance_graph.json",
        supply_chain_path=state_dir / "supply_chain_memory.json",
        model_registry_path=state_dir / "model_registry.json",
    )
