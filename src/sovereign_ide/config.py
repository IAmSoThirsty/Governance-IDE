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
    signing_key: str
    policy_path: Path
    state_dir: Path
    journal_path: Path
    provenance_path: Path
    supply_chain_path: Path


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
    signing_key = _require_signing_key()
    policy_path = (root / policy_path_env).resolve()
    state_dir = (root / os.getenv("SOVEREIGN_STATE_DIR", "state")).resolve()

    return Settings(
        workspace_root=root,
        signing_key=signing_key,
        policy_path=policy_path,
        state_dir=state_dir,
        journal_path=state_dir / "governance_journal.jsonl",
        provenance_path=state_dir / "provenance_graph.json",
        supply_chain_path=state_dir / "supply_chain_memory.json",
    )
