from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from .config import get_settings
from .evaluation import EvaluationHarness
from .governance import (
    GovernanceRuntime,
    HashChainJournal,
    HMACDecisionSigner,
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


def _csv_values(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _default_policy(workspace_root: str) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "resolution": {
            "default": "deny",
            "precedence": [
                "invariants",
                "immutableDecisionRecord",
                "policyEvaluation",
                "capabilityToken",
                "runtimeConfiguration",
                "operatorOverride",
            ],
        },
        "workspace": {
            "allowed_roots": [workspace_root],
        },
        "risk_scores": {
            "read": 10,
            "softMutation": 35,
            "hardMutation": 70,
            "governanceMutation": 90,
        },
        "actions": {
            "apply_patch": {
                "required_mutation_class": "hardMutation",
                "allowed_roles": ["developer", "reviewer"],
                "quorum_required": True,
            },
            "promote_artifact": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": ["model_steward", "extension_steward"],
                "quorum_required": True,
            },
            "compensate:apply_patch": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": ["incident_responder", "release_authority"],
                "quorum_required": False,
            },
        },
    }


def _build_runtime(workspace_root: Path | None = None) -> GovernanceRuntime:
    settings = get_settings(workspace_root)
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    policy_engine = PolicyEngine.from_path(settings.policy_path)
    journal = HashChainJournal(settings.journal_path)
    signer = HMACDecisionSigner(settings.signing_key)
    return GovernanceRuntime(
        policy_engine=policy_engine,
        journal=journal,
        signer=signer,
    )


def cmd_init(args: argparse.Namespace) -> int:
    settings = get_settings(Path(args.workspace_root).resolve())
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.policy_path.parent.mkdir(parents=True, exist_ok=True)

    if not settings.policy_path.exists():
        settings.policy_path.write_text(
            json.dumps(
                _default_policy(str(settings.workspace_root)),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    if not settings.journal_path.exists():
        settings.journal_path.write_text("", encoding="utf-8")

    if not settings.provenance_path.exists():
        settings.provenance_path.write_text(
            json.dumps({"nodes": {}, "edges": []}, indent=2),
            encoding="utf-8",
        )

    if not settings.supply_chain_path.exists():
        settings.supply_chain_path.write_text(
            json.dumps({"artifacts": {}}, indent=2),
            encoding="utf-8",
        )

    print(f"Initialized sovereign runtime in {settings.workspace_root}")
    return 0


def cmd_simulate_mutation(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    runtime = _build_runtime(workspace_root)

    trace_id = args.trace_id or new_id("trace")
    roles = _csv_values(args.roles)
    scopes = _csv_values(args.scopes)

    context = GovernanceContext(
        trace_id=trace_id,
        actor_id=args.actor,
        actor_roles=roles,
        tenant=args.tenant,
        trust_domain=args.trust_domain,
        workspace_root=str(workspace_root),
        classification=args.classification,
        policy_pack_version="1.0.0",
    )

    token = CapabilityToken(
        token_id=new_id("token"),
        subject=args.actor,
        scopes=scopes,
        trust_domain=args.trust_domain,
        issued_at=utc_now(),
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=30)
        ).isoformat(),
        revoked=False,
    )

    mutation_class = MutationClass(args.mutation_class)
    request, evaluation, eval_binding = runtime.evaluate_and_bind(
        context=context,
        action=args.action,
        resource=args.resource,
        mutation_class=mutation_class,
        capability_token=token,
    )

    mutation_binding = runtime.build_mutation_binding(
        context=context,
        action=args.action,
        resource=args.resource,
        mutation_class=mutation_class,
        capability_token=token,
        evaluation=evaluation,
        binding=eval_binding,
        resolution_policy=(
            "invariants>immutableDecisionRecord>policyEvaluation>"
            "capabilityToken>runtimeConfiguration>operatorOverride"
        ),
        quorum_proof=args.quorum_proof,
    )

    result = runtime.commit_mutation(
        mutation_binding,
        lambda: {
            "request_id": request.request_id,
            "resource": args.resource,
            "status": "applied",
        },
    )

    print(
        json.dumps(
            {
                "applied": result.applied,
                "decision": to_primitive(result.decision),
                "payload": result.payload,
            },
            indent=2,
            ensure_ascii=False,
        ),
    )
    return 0


def cmd_compensate(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    runtime = _build_runtime(workspace_root)

    context = GovernanceContext(
        trace_id=args.trace_id or new_id("trace"),
        actor_id=args.actor,
        actor_roles=_csv_values(args.roles),
        tenant=args.tenant,
        trust_domain=args.trust_domain,
        workspace_root=str(workspace_root),
        classification=args.classification,
        policy_pack_version="1.0.0",
    )

    transaction, decision, payload = runtime.compensate(
        target_decision_id=args.target_decision_id,
        context=context,
        reason=args.reason,
        compensate_fn=lambda: {
            "status": "compensation_applied",
            "target_decision_id": args.target_decision_id,
        },
    )

    print(
        json.dumps(
            {
                "transaction": to_primitive(transaction),
                "decision": to_primitive(decision),
                "payload": payload,
            },
            indent=2,
            ensure_ascii=False,
        ),
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    runtime = _build_runtime(Path(args.workspace_root).resolve())
    replay = runtime.replay_trace(args.trace_id)
    print(json.dumps(replay, indent=2, ensure_ascii=False))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    events = json.loads(Path(args.session_file).read_text(encoding="utf-8"))
    harness = EvaluationHarness()
    capability, assurance = harness.evaluate(events)

    print(
        json.dumps(
            {
                "capability": to_primitive(capability),
                "assurance": to_primitive(assurance),
            },
            indent=2,
            ensure_ascii=False,
        ),
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sovereign IDE governed runtime CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--workspace-root", default=str(Path.cwd()))
    init_parser.set_defaults(func=cmd_init)

    simulate = subparsers.add_parser("simulate-mutation")
    simulate.add_argument("--workspace-root", default=str(Path.cwd()))
    simulate.add_argument("--trace-id", default=None)
    simulate.add_argument("--actor", required=True)
    simulate.add_argument("--roles", required=True)
    simulate.add_argument("--tenant", required=True)
    simulate.add_argument("--trust-domain", required=True)
    simulate.add_argument("--classification", default="confidential")
    simulate.add_argument("--action", required=True)
    simulate.add_argument("--resource", required=True)
    simulate.add_argument(
        "--mutation-class",
        required=True,
        choices=[item.value for item in MutationClass],
    )
    simulate.add_argument("--scopes", required=True)
    simulate.add_argument("--quorum-proof", default=None)
    simulate.set_defaults(func=cmd_simulate_mutation)

    compensate = subparsers.add_parser("compensate")
    compensate.add_argument("--workspace-root", default=str(Path.cwd()))
    compensate.add_argument("--trace-id", default=None)
    compensate.add_argument("--actor", required=True)
    compensate.add_argument("--roles", required=True)
    compensate.add_argument("--tenant", required=True)
    compensate.add_argument("--trust-domain", required=True)
    compensate.add_argument("--classification", default="confidential")
    compensate.add_argument("--target-decision-id", required=True)
    compensate.add_argument("--reason", required=True)
    compensate.set_defaults(func=cmd_compensate)

    replay = subparsers.add_parser("replay")
    replay.add_argument("--workspace-root", default=str(Path.cwd()))
    replay.add_argument("--trace-id", required=True)
    replay.set_defaults(func=cmd_replay)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--session-file", required=True)
    evaluate.set_defaults(func=cmd_evaluate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
