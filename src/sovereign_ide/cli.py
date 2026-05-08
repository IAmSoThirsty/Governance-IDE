from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from .app_catalog import filter_app_catalog, load_app_catalog
from .config import get_settings
from .evaluation import EvaluationHarness
from .governance import (
    GovernanceRuntime,
    PolicyEngine,
    build_decision_signer,
    build_journal,
)
from .models import (
    CapabilityToken,
    GovernanceContext,
    MutationClass,
    new_id,
    to_primitive,
    utc_now,
)
from .model_registry import GovernedModelRegistry
from .service import inspect_execution_ticket, request_execution_ticket, serve
from .supply_chain import ArtifactType, SupplyChainRegistry
from .workshop import SovereignModelServerWorkshop


def _csv_values(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


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
            "register_model": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": ["model_steward", "release_authority"],
                "quorum_required": True,
            },
            "execute_model": {
                "required_mutation_class": "read",
                "allowed_roles": [
                    "developer",
                    "reviewer",
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": False,
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

    policy_engine = PolicyEngine.from_path(
        settings.policy_path,
        workspace_root=settings.workspace_root,
    )
    journal = build_journal(settings)
    signer = build_decision_signer(settings)
    return GovernanceRuntime(
        policy_engine=policy_engine,
        journal=journal,
        signer=signer,
    )


def _build_workshop(args: argparse.Namespace) -> SovereignModelServerWorkshop:
    workspace_root = Path(args.workspace_root).resolve()
    policy_path = Path(args.policy_path).resolve()
    return SovereignModelServerWorkshop(
        workspace_root=workspace_root,
        policy_path=policy_path,
    )


def _workshop_context(args: argparse.Namespace) -> GovernanceContext:
    workspace_root = Path(args.workspace_root).resolve()
    return GovernanceContext(
        trace_id=args.trace_id or new_id("trace"),
        actor_id=args.actor,
        actor_roles=_csv_values(args.roles),
        tenant=args.tenant,
        trust_domain=args.trust_domain,
        workspace_root=str(workspace_root),
        classification=args.classification,
        policy_pack_version="1.0.0",
    )


def _governance_context(args: argparse.Namespace) -> GovernanceContext:
    workspace_root = Path(args.workspace_root).resolve()
    return GovernanceContext(
        trace_id=args.trace_id or new_id("trace"),
        actor_id=args.actor,
        actor_roles=_csv_values(args.roles),
        tenant=args.tenant,
        trust_domain=args.trust_domain,
        workspace_root=str(workspace_root),
        classification=args.classification,
        policy_pack_version="1.0.0",
    )


def _capability_token(context: GovernanceContext, action: str) -> CapabilityToken:
    return CapabilityToken(
        token_id=new_id("token"),
        subject=context.actor_id,
        scopes=(action,),
        trust_domain=context.trust_domain,
        issued_at=utc_now(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        revoked=False,
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

    _print_json(
        {
            "applied": result.applied,
            "decision": to_primitive(result.decision),
            "payload": result.payload,
        },
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

    _print_json(
        {
            "transaction": to_primitive(transaction),
            "decision": to_primitive(decision),
            "payload": payload,
        },
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

    _print_json(
        {
            "capability": to_primitive(capability),
            "assurance": to_primitive(assurance),
        },
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    serve(
        workspace_root=Path(args.workspace_root).resolve(),
        host=args.host,
        port=args.port,
    )
    return 0


def cmd_apps_list(args: argparse.Namespace) -> int:
    catalog = load_app_catalog(Path(args.workspace_root).resolve())
    _print_json(
        filter_app_catalog(
            catalog,
            category=args.category or None,
            status=args.status or None,
        ),
    )
    return 0


def cmd_model_register(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    settings = get_settings(workspace_root)
    runtime = _build_runtime(workspace_root)
    context = _governance_context(args)
    metadata = json.loads(args.metadata_json) if args.metadata_json else {}
    content_hash = args.content_hash or None
    if args.source_type == "local_path" and content_hash is None:
        content_hash = GovernedModelRegistry.hash_local_path(args.source)

    token = _capability_token(context, "register_model")
    request, evaluation, binding = runtime.evaluate_and_bind(
        context=context,
        action="register_model",
        resource=str(settings.model_registry_path),
        mutation_class=MutationClass.GOVERNANCE_MUTATION,
        capability_token=token,
    )
    mutation_binding = runtime.build_mutation_binding(
        context=context,
        action="register_model",
        resource=str(settings.model_registry_path),
        mutation_class=MutationClass.GOVERNANCE_MUTATION,
        capability_token=token,
        evaluation=evaluation,
        binding=binding,
        resolution_policy="invariants>policyEvaluation>capabilityToken",
        quorum_proof=args.quorum_proof,
    )

    def _mutate() -> dict[str, Any]:
        registry = GovernedModelRegistry(settings.model_registry_path)
        record = registry.register(
            source_type=args.source_type,
            source=args.source,
            license=args.license,
            content_hash=content_hash,
            immutable_identifier=args.immutable_identifier or None,
            metadata=metadata,
            trust_level=args.trust_level,
            policy_profile=args.policy_profile,
            provenance_ref=args.provenance_ref,
            signer=runtime.signer,
        )
        supply_chain = SupplyChainRegistry(settings.supply_chain_path)
        supply_chain.register_candidate(
            artifact_id=record.model_id,
            artifact_type=ArtifactType.MODEL,
            publisher=context.actor_id,
            checksum=record.content_hash,
            signature_verified=record.signature is not None,
            static_scan_passed=True,
            dependency_scan_passed=True,
            provenance_verified=True,
            airgap_manifest_approved=False,
        )
        supply_chain.register_evidence(
            artifact_id=record.model_id,
            evidence_type="provenance",
            passed=True,
            evidence_ref=record.provenance_ref,
        )
        if record.signature is not None:
            supply_chain.register_evidence(
                artifact_id=record.model_id,
                evidence_type="signature",
                passed=True,
                evidence_ref=f"signature://{record.signature.key_id}/{record.model_id}",
            )
        return {"model": to_primitive(record)}

    result = runtime.commit_mutation(mutation_binding, _mutate)
    _print_json(
        {
            "request": to_primitive(request),
            "evaluation": to_primitive(evaluation),
            "decision": to_primitive(result.decision),
            "payload": result.payload,
        },
    )
    return 0 if result.applied else 1


def cmd_models_list(args: argparse.Namespace) -> int:
    settings = get_settings(Path(args.workspace_root).resolve())
    registry = GovernedModelRegistry(settings.model_registry_path)
    _print_json({"models": [to_primitive(model) for model in registry.list()]})
    return 0


def cmd_model_execution_ticket(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    context = _governance_context(args)
    response = request_execution_ticket(
        workspace_root,
        context=context,
        model_id=args.model_id,
        ticket_purpose=args.ticket_purpose,
        ticket_ttl_seconds=args.ticket_ttl_seconds,
    )
    _print_json(response)
    return 0 if bool(response.get("allowed")) else 1


def cmd_model_execution_ticket_inspect(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace_root).resolve()
    ticket_path = Path(args.ticket_file).resolve()
    raw = json.loads(ticket_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("ticket file must contain a JSON object")

    response = inspect_execution_ticket(
        workspace_root,
        ticket=raw,
        at_time=(args.at_time or None),
        trace_id=(args.trace_id or None),
    )
    _print_json(response)
    return 0 if bool(response.get("allowed")) else 1


def cmd_workshop_init(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.bootstrap_founding_charter(
        context=context,
        quorum_proof=args.quorum_proof,
    )
    _print_json(result)
    return 0


def cmd_workshop_ingest(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.admit_corpus_artifacts(
        context=context,
        artifact_paths=_csv_values(args.artifact_paths),
        artifact_type=args.artifact_type,
        source_class=args.source_class,
        trust_class=args.trust_class,
    )
    _print_json(result)
    return 0


def cmd_workshop_build_datasets(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.build_constitutional_datasets(context=context)
    _print_json(result)
    return 0


def cmd_workshop_train(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    base_checkpoint = args.base_checkpoint if args.base_checkpoint else None
    result = workshop.start_training_run(
        context=context,
        model_family=args.model_family,
        base_checkpoint=base_checkpoint,
        dataset_ids=_csv_values(args.dataset_ids),
        quorum_proof=args.quorum_proof,
        execution_mode=args.execution_mode,
        training_command=args.training_command or None,
    )
    _print_json(result)
    return 0


def cmd_workshop_eval(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.run_shadow_evaluation(
        context=context,
        checkpoint_id=args.checkpoint_id,
    )
    _print_json(result)
    return 0


def cmd_workshop_promote(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.promote_checkpoint(
        context=context,
        checkpoint_id=args.checkpoint_id,
        evaluation_id=args.evaluation_id,
        approvals=_csv_values(args.approvals),
        charter_version=args.charter_version,
        quorum_proof=args.quorum_proof,
    )
    _print_json(result)
    return 0


def cmd_workshop_register_repair(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.register_repair_unit(
        context=context,
        component=args.component,
        version=args.version,
        payload_hash=args.payload_hash,
        certification_decision_id=args.certification_decision_id,
        quorum_proof=args.quorum_proof,
    )
    _print_json(result)
    return 0


def cmd_workshop_apply_repair(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    context = _workshop_context(args)
    result = workshop.apply_repair_unit(
        context=context,
        unit_id=args.unit_id,
        target_component=args.target_component,
        reason=args.reason,
        quorum_proof=args.quorum_proof,
    )
    _print_json(result)
    return 0


def cmd_workshop_containment_check(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    decision = workshop.evaluate_runtime_containment(
        action=args.action,
        requested_syscalls=_csv_values(args.requested_syscalls),
        network_egress_class=args.network_egress_class,
        filesystem_write_paths=_csv_values(args.filesystem_write_paths),
    )
    _print_json(
        {
            "allowed": decision.allowed,
            "reasons": list(decision.reasons),
        },
    )
    return 0


def cmd_workshop_report(args: argparse.Namespace) -> int:
    workshop = _build_workshop(args)
    output_path = Path(args.output_path).resolve() if args.output_path else None
    report = workshop.export_workshop_report(output_path=output_path)
    _print_json(report)
    return 0


def _add_workshop_common_args(
    parser: argparse.ArgumentParser,
    *,
    include_quorum: bool,
) -> None:
    parser.add_argument("--workspace-root", default=str(Path.cwd()))
    parser.add_argument(
        "--policy-path",
        default="policies/workshop_policy.json",
    )
    parser.add_argument("--trace-id", default=None)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--roles", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--trust-domain", required=True)
    parser.add_argument("--classification", default="confidential")
    if include_quorum:
        parser.add_argument("--quorum-proof", required=True)


def _add_governance_common_args(
    parser: argparse.ArgumentParser,
    *,
    include_quorum: bool,
) -> None:
    parser.add_argument("--workspace-root", default=str(Path.cwd()))
    parser.add_argument("--trace-id", default=None)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--roles", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--trust-domain", required=True)
    parser.add_argument("--classification", default="confidential")
    if include_quorum:
        parser.add_argument("--quorum-proof", required=True)


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

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--workspace-root", default=str(Path.cwd()))
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.set_defaults(func=cmd_serve)

    apps_list = subparsers.add_parser("apps-list")
    apps_list.add_argument("--workspace-root", default=str(Path.cwd()))
    apps_list.add_argument("--category", default="")
    apps_list.add_argument("--status", default="")
    apps_list.set_defaults(func=cmd_apps_list)

    model_register = subparsers.add_parser("model-register")
    _add_governance_common_args(model_register, include_quorum=True)
    model_register.add_argument(
        "--source-type",
        required=True,
        choices=[
            "local_path",
            "huggingface_model_id",
            "openai_compatible_endpoint",
            "ollama_endpoint",
            "external_gateway",
        ],
    )
    model_register.add_argument("--source", required=True)
    model_register.add_argument("--license", default="unknown")
    model_register.add_argument("--content-hash", default="")
    model_register.add_argument("--immutable-identifier", default="")
    model_register.add_argument("--metadata-json", default="")
    model_register.add_argument(
        "--trust-level",
        required=True,
        choices=["untrusted", "quarantine", "reviewed", "trusted"],
    )
    model_register.add_argument("--policy-profile", required=True)
    model_register.add_argument("--provenance-ref", required=True)
    model_register.set_defaults(func=cmd_model_register)

    models_list = subparsers.add_parser("models-list")
    models_list.add_argument("--workspace-root", default=str(Path.cwd()))
    models_list.set_defaults(func=cmd_models_list)

    model_ticket = subparsers.add_parser("model-execution-ticket")
    _add_governance_common_args(model_ticket, include_quorum=False)
    model_ticket.add_argument("--model-id", required=True)
    model_ticket.add_argument("--ticket-purpose", default="model_execution")
    model_ticket.add_argument("--ticket-ttl-seconds", type=int, default=900)
    model_ticket.set_defaults(func=cmd_model_execution_ticket)

    model_ticket_inspect = subparsers.add_parser("model-execution-ticket-inspect")
    model_ticket_inspect.add_argument("--workspace-root", default=str(Path.cwd()))
    model_ticket_inspect.add_argument("--ticket-file", required=True)
    model_ticket_inspect.add_argument("--trace-id", default="")
    model_ticket_inspect.add_argument("--at-time", default="")
    model_ticket_inspect.set_defaults(func=cmd_model_execution_ticket_inspect)

    workshop_init = subparsers.add_parser("workshop-init")
    _add_workshop_common_args(workshop_init, include_quorum=True)
    workshop_init.set_defaults(func=cmd_workshop_init)

    workshop_ingest = subparsers.add_parser("workshop-ingest")
    _add_workshop_common_args(workshop_ingest, include_quorum=False)
    workshop_ingest.add_argument("--artifact-paths", required=True)
    workshop_ingest.add_argument("--artifact-type", required=True)
    workshop_ingest.add_argument("--source-class", required=True)
    workshop_ingest.add_argument("--trust-class", required=True)
    workshop_ingest.set_defaults(func=cmd_workshop_ingest)

    workshop_build = subparsers.add_parser("workshop-build-datasets")
    _add_workshop_common_args(workshop_build, include_quorum=False)
    workshop_build.set_defaults(func=cmd_workshop_build_datasets)

    workshop_train = subparsers.add_parser("workshop-train")
    _add_workshop_common_args(workshop_train, include_quorum=True)
    workshop_train.add_argument("--model-family", required=True)
    workshop_train.add_argument("--base-checkpoint", default="")
    workshop_train.add_argument("--dataset-ids", required=True)
    workshop_train.add_argument(
        "--execution-mode",
        choices=("actual", "simulated"),
        default="actual",
    )
    workshop_train.add_argument("--training-command", default="")
    workshop_train.set_defaults(func=cmd_workshop_train)

    workshop_eval = subparsers.add_parser("workshop-eval")
    _add_workshop_common_args(workshop_eval, include_quorum=False)
    workshop_eval.add_argument("--checkpoint-id", required=True)
    workshop_eval.set_defaults(func=cmd_workshop_eval)

    workshop_promote = subparsers.add_parser("workshop-promote")
    _add_workshop_common_args(workshop_promote, include_quorum=True)
    workshop_promote.add_argument("--checkpoint-id", required=True)
    workshop_promote.add_argument("--evaluation-id", required=True)
    workshop_promote.add_argument("--approvals", required=True)
    workshop_promote.add_argument("--charter-version", required=True)
    workshop_promote.set_defaults(func=cmd_workshop_promote)

    workshop_register = subparsers.add_parser("workshop-register-repair")
    _add_workshop_common_args(workshop_register, include_quorum=True)
    workshop_register.add_argument("--component", required=True)
    workshop_register.add_argument("--version", required=True)
    workshop_register.add_argument("--payload-hash", required=True)
    workshop_register.add_argument(
        "--certification-decision-id",
        required=True,
    )
    workshop_register.set_defaults(func=cmd_workshop_register_repair)

    workshop_apply = subparsers.add_parser("workshop-apply-repair")
    _add_workshop_common_args(workshop_apply, include_quorum=True)
    workshop_apply.add_argument("--unit-id", required=True)
    workshop_apply.add_argument("--target-component", required=True)
    workshop_apply.add_argument("--reason", required=True)
    workshop_apply.set_defaults(func=cmd_workshop_apply_repair)

    workshop_containment = subparsers.add_parser(
        "workshop-containment-check",
    )
    workshop_containment.add_argument(
        "--workspace-root",
        default=str(Path.cwd()),
    )
    workshop_containment.add_argument(
        "--policy-path",
        default="policies/workshop_policy.json",
    )
    workshop_containment.add_argument("--action", required=True)
    workshop_containment.add_argument("--requested-syscalls", default="")
    workshop_containment.add_argument(
        "--network-egress-class",
        required=True,
    )
    workshop_containment.add_argument(
        "--filesystem-write-paths",
        default="",
    )
    workshop_containment.set_defaults(func=cmd_workshop_containment_check)

    workshop_report = subparsers.add_parser("workshop-report")
    workshop_report.add_argument("--workspace-root", default=str(Path.cwd()))
    workshop_report.add_argument(
        "--policy-path",
        default="policies/workshop_policy.json",
    )
    workshop_report.add_argument("--output-path", default="")
    workshop_report.set_defaults(func=cmd_workshop_report)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
