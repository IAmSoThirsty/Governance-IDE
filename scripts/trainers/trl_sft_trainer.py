# /// script
# dependencies = [
#   "accelerate>=0.30.0",
#   "datasets>=2.19.0",
#   "peft>=0.11.0",
#   "torch",
#   "transformers>=4.41.0",
#   "trl>=0.12.0",
# ]
# ///
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

from datasets import Dataset
from peft import LoraConfig
from trl import SFTConfig, SFTTrainer


def _require_non_empty(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _validate_governed_training_request(request: dict) -> dict:
    governance = request.get("governance_metadata")
    if not isinstance(governance, dict):
        raise ValueError("governance_metadata is required")

    if _require_non_empty(governance.get("mode"), "governance_metadata.mode") != "actual_training":
        raise ValueError("trainer accepts only governed actual_training mode")

    required_fields = (
        "base_model_id",
        "policy_profile",
        "trust_level",
        "training_config_hash",
        "artifact_store_uri",
        "trainer_backend",
        "output_registration_path",
    )
    for field_name in required_fields:
        _require_non_empty(
            governance.get(field_name),
            f"governance_metadata.{field_name}",
        )

    dataset_references = governance.get("dataset_references")
    if not isinstance(dataset_references, list) or not dataset_references:
        raise ValueError("governance_metadata.dataset_references is required")

    for index, reference in enumerate(dataset_references):
        if not isinstance(reference, dict):
            raise ValueError(
                f"governance_metadata.dataset_references[{index}] must be an object",
            )
        for required in (
            "dataset_id",
            "dataset_ref",
            "dataset_provenance",
            "dataset_source_type",
            "dataset_license",
        ):
            _require_non_empty(
                reference.get(required),
                f"dataset_references[{index}].{required}",
            )
        if not str(reference.get("dataset_hash", "")).strip() and not str(
            reference.get("dataset_immutable_ref", ""),
        ).strip():
            raise ValueError(
                "dataset_references entries require dataset_hash "
                "or dataset_immutable_ref",
            )

    if not bool(governance.get("audit_journal_enabled", False)):
        raise ValueError("governance_metadata.audit_journal_enabled must be true")

    top_level_store = _require_non_empty(
        request.get("artifact_store_uri"),
        "artifact_store_uri",
    )
    governance_store = _require_non_empty(
        governance.get("artifact_store_uri"),
        "governance_metadata.artifact_store_uri",
    )
    if top_level_store != governance_store:
        raise ValueError(
            "artifact_store_uri must match governance_metadata.artifact_store_uri",
        )

    return governance


def _load_records(dataset_paths: list[str]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for dataset_path in dataset_paths:
        payload = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
        for item in payload.get("records", []):
            prompt = str(item.get("input", "")).strip()
            response = str(item.get("output", "")).strip()
            if prompt and response:
                records.append(
                    {
                        "text": (
                            "### Instruction\n"
                            f"{prompt}\n\n"
                            "### Response\n"
                            f"{response}"
                        ),
                    },
                )
    if not records:
        raise ValueError("no SFT records found in requested datasets")
    return records


def _sha256_tree(path: Path) -> str:
    hasher = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        hasher.update(str(item.relative_to(path)).replace("\\", "/").encode())
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Real TRL SFT trainer for Sovereign IDE workshop datasets.",
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=float, default=float(os.getenv("SOVEREIGN_TRAIN_EPOCHS", "1")))
    parser.add_argument("--max-steps", type=int, default=int(os.getenv("SOVEREIGN_TRAIN_MAX_STEPS", "-1")))
    parser.add_argument("--learning-rate", type=float, default=float(os.getenv("SOVEREIGN_TRAIN_LR", "0.0002")))
    parser.add_argument("--max-length", type=int, default=int(os.getenv("SOVEREIGN_TRAIN_MAX_LENGTH", "1024")))
    parser.add_argument("--lora-r", type=int, default=int(os.getenv("SOVEREIGN_LORA_R", "16")))
    parser.add_argument("--lora-alpha", type=int, default=int(os.getenv("SOVEREIGN_LORA_ALPHA", "32")))
    parser.add_argument("--hub-model-id", default=os.getenv("SOVEREIGN_HUB_MODEL_ID", ""))
    args = parser.parse_args()

    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    governance = _validate_governed_training_request(request)
    output_dir = Path(request["output_dir"]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_store_uri = str(request.get("artifact_store_uri") or "").strip()

    records = _load_records(list(request["dataset_paths"]))
    dataset = Dataset.from_list(records)
    split = dataset.train_test_split(test_size=0.1, seed=42) if len(dataset) > 10 else {"train": dataset, "test": None}

    push_to_hub = bool(args.hub_model_id)
    trainer = SFTTrainer(
        model=request["model_family"],
        train_dataset=split["train"],
        eval_dataset=split["test"],
        peft_config=LoraConfig(
            r=args.lora_r,
            lora_alpha=args.lora_alpha,
            target_modules="all-linear",
        ),
        args=SFTConfig(
            output_dir=str(output_dir),
            num_train_epochs=args.epochs,
            max_steps=args.max_steps,
            learning_rate=args.learning_rate,
            max_length=args.max_length,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            gradient_checkpointing=True,
            save_strategy="epoch",
            eval_strategy="epoch" if split["test"] is not None else "no",
            push_to_hub=push_to_hub,
            hub_model_id=args.hub_model_id or None,
            report_to=[],
        ),
    )

    trainer.train()
    trainer.save_model(str(output_dir))
    if push_to_hub:
        trainer.push_to_hub()

    if artifact_store_uri and not push_to_hub:
        raise RuntimeError(
            "durable artifact store requires --hub-model-id/"
            "SOVEREIGN_HUB_MODEL_ID or a custom trainer uploader",
        )
    artifact_uri = (
        f"https://huggingface.co/{args.hub_model_id}"
        if push_to_hub
        else output_dir.as_uri()
    )
    if artifact_store_uri and artifact_uri.rstrip("/") != artifact_store_uri.rstrip("/"):
        raise RuntimeError(
            "pushed artifact URI does not match requested artifact store",
        )
    result = {
        "status": "completed",
        "checkpoint_id": f"checkpoint_{uuid4().hex}",
        "artifact_uri": artifact_uri,
        "artifact_store_uri": artifact_store_uri or None,
        "checkpoint_hash": _sha256_tree(output_dir),
        "governance": {
            "mode": governance["mode"],
            "base_model_id": governance["base_model_id"],
            "policy_profile": governance["policy_profile"],
            "trust_level": governance["trust_level"],
            "training_config_hash": governance["training_config_hash"],
            "dataset_refs": [
                str(reference.get("dataset_ref", "")).strip()
                for reference in governance["dataset_references"]
            ],
        },
    }
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
