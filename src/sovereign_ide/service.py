from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .app_catalog import filter_app_catalog, load_app_catalog
from .config import get_settings
from .governance import (
    GovernanceRuntime,
    HashChainJournal,
    HMACDecisionSigner,
    JournalIntegrityError,
    PolicyEngine,
)
from .models import (
    CapabilityToken,
    GovernanceContext,
    MutationClass,
    new_id,
    to_primitive,
    utc_now,
)
from .validation import load_policy_pack, validate_repository_artifacts


def build_runtime(workspace_root: str | Path) -> GovernanceRuntime:
    settings = get_settings(Path(workspace_root).resolve())
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    return GovernanceRuntime(
        policy_engine=PolicyEngine.from_path(
            settings.policy_path,
            workspace_root=settings.workspace_root,
        ),
        journal=HashChainJournal(settings.journal_path),
        signer=HMACDecisionSigner(settings.signing_key),
    )


def readiness_report(workspace_root: str | Path) -> dict[str, Any]:
    settings = get_settings(Path(workspace_root).resolve())
    checks: list[dict[str, str]] = []
    status = "ready"

    def add(name: str, check_status: str, detail: str) -> None:
        nonlocal status
        if check_status != "pass":
            status = "not_ready"
        checks.append(
            {
                "name": name,
                "status": check_status,
                "detail": detail,
            },
        )

    try:
        validate_repository_artifacts(settings.workspace_root)
        add("repository_artifacts", "pass", "validated")
    except Exception as exc:  # noqa: BLE001
        add("repository_artifacts", "fail", str(exc))

    try:
        HashChainJournal(settings.journal_path).read_all()
        add("journal_integrity", "pass", "hash chain verified")
    except JournalIntegrityError as exc:
        add("journal_integrity", "fail", str(exc))

    try:
        policy = load_policy_pack(
            settings.policy_path,
            workspace_root=settings.workspace_root,
        )
        add("policy_pack", "pass", str(policy.get("version", "unknown")))
    except Exception as exc:  # noqa: BLE001
        add("policy_pack", "fail", str(exc))

    return {
        "status": status,
        "generated_at": utc_now(),
        "workspace_root": str(settings.workspace_root),
        "checks": checks,
    }


def make_handler(workspace_root: str | Path) -> type[BaseHTTPRequestHandler]:
    root = Path(workspace_root).resolve()

    class SovereignIdeHandler(BaseHTTPRequestHandler):
        server_version = "SovereignIDE/0.1"

        def do_GET(self) -> None:  # noqa: N802
            try:
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(
                        {"status": "ok", "service": "sovereign-ide"},
                    )
                    return
                if not self._authorized():
                    self._send_error(401, "unauthorized")
                    return
                if parsed.path == "/ready":
                    report = readiness_report(root)
                    self._send_json(
                        report,
                        status=200 if report["status"] == "ready" else 503,
                    )
                    return
                if parsed.path == "/v1/policy":
                    settings = get_settings(root)
                    policy = load_policy_pack(
                        settings.policy_path,
                        workspace_root=settings.workspace_root,
                    )
                    self._send_json(policy)
                    return
                if parsed.path == "/v1/apps":
                    query = parse_qs(parsed.query)
                    catalog = load_app_catalog(root)
                    self._send_json(
                        filter_app_catalog(
                            catalog,
                            category=query.get("category", [None])[0],
                            status=query.get("status", [None])[0],
                        ),
                    )
                    return
                if parsed.path == "/v1/audit/replay":
                    query = parse_qs(parsed.query)
                    trace_id = query.get("trace_id", [""])[0]
                    if not trace_id:
                        self._send_error(400, "trace_id is required")
                        return
                    runtime = build_runtime(root)
                    self._send_json(
                        {
                            "trace_id": trace_id,
                            "entries": runtime.replay_trace(trace_id),
                        },
                    )
                    return
                self._send_error(404, "not found")
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, str(exc))

        def do_POST(self) -> None:  # noqa: N802
            try:
                if not self._authorized():
                    self._send_error(401, "unauthorized")
                    return
                parsed = urlparse(self.path)
                if parsed.path == "/v1/policy/evaluate":
                    self._handle_policy_evaluate()
                    return
                self._send_error(404, "not found")
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, str(exc))

        def log_message(self, format: str, *args: object) -> None:
            return

        def _handle_policy_evaluate(self) -> None:
            body = self._read_json()
            runtime = build_runtime(root)
            context_raw = self._require_mapping(body.get("context"), "context")
            context = GovernanceContext(
                trace_id=str(context_raw.get("trace_id") or new_id("trace")),
                actor_id=str(context_raw["actor_id"]),
                actor_roles=tuple(context_raw["actor_roles"]),
                tenant=str(context_raw["tenant"]),
                trust_domain=str(context_raw["trust_domain"]),
                workspace_root=str(context_raw.get("workspace_root") or root),
                classification=str(context_raw["classification"]),
                policy_pack_version=str(
                    context_raw.get("policy_pack_version", "1.0.0"),
                ),
            )
            action = str(body["action"])
            resource = str(body["resource"])
            mutation_class = MutationClass(str(body["mutation_class"]))
            scopes = tuple(str(item) for item in body.get("scopes", [action]))
            token = CapabilityToken(
                token_id=new_id("token"),
                subject=context.actor_id,
                scopes=scopes,
                trust_domain=context.trust_domain,
                issued_at=utc_now(),
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(minutes=15)
                ).isoformat(),
                revoked=False,
            )
            request, evaluation, binding = runtime.evaluate_and_bind(
                context=context,
                action=action,
                resource=resource,
                mutation_class=mutation_class,
                capability_token=token,
            )
            self._send_json(
                {
                    "request": to_primitive(request),
                    "evaluation": to_primitive(evaluation),
                    "binding": to_primitive(binding),
                },
            )

        def _authorized(self) -> bool:
            token = os.getenv("SOVEREIGN_SERVICE_TOKEN", "").strip()
            if not token:
                return True
            expected = f"Bearer {token}"
            return self.headers.get("Authorization", "") == expected

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("request body must be valid JSON") from exc
            return self._require_mapping(payload, "body")

        @staticmethod
        def _require_mapping(value: Any, name: str) -> dict[str, Any]:
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be an object")
            return value

        def _send_json(self, payload: Any, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status: int, message: str) -> None:
            self._send_json({"error": message}, status=status)

    return SovereignIdeHandler


def serve(
    workspace_root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(workspace_root),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
