from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import PromptContext, RetrievalChunk


CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
    "sovereign": 4,
}


class RetrievalContainmentError(ValueError):
    """Raised when retrieval evidence violates containment policy."""


@dataclass(frozen=True)
class ContainmentDecision:
    allowed: bool
    reason: str
    retained_chunk_ids: tuple[str, ...]


class RetrievalContainmentEngine:
    """Policy guard for retrieval evidence and classification boundaries."""

    def __init__(
        self,
        allow_cross_project: bool = False,
        allow_cross_trust_domain: bool = False,
    ) -> None:
        self.allow_cross_project = allow_cross_project
        self.allow_cross_trust_domain = allow_cross_trust_domain

    def enforce(
        self,
        chunks: list[RetrievalChunk],
        prompt_context: PromptContext,
    ) -> tuple[RetrievalChunk, ...]:
        clearance_rank = self._rank(prompt_context.clearance)
        retained: list[RetrievalChunk] = []
        allowed_project: str | None = None

        for chunk in chunks:
            labels = chunk.labels

            if labels.tenant != prompt_context.tenant:
                raise RetrievalContainmentError("tenant boundary violation")

            if (
                not self.allow_cross_trust_domain
                and labels.trust_domain != prompt_context.trust_domain
            ):
                raise RetrievalContainmentError(
                    "trust-domain boundary violation",
                )

            if self._rank(labels.classification) > clearance_rank:
                raise RetrievalContainmentError(
                    "classification exceeds clearance",
                )

            if not self.allow_cross_project:
                if allowed_project is None:
                    allowed_project = labels.project
                if labels.project != allowed_project:
                    raise RetrievalContainmentError(
                        "cross-project evidence denied",
                    )

            retained.append(chunk)

        return tuple(retained)

    @staticmethod
    def _rank(level: str) -> int:
        if level not in CLASSIFICATION_ORDER:
            raise RetrievalContainmentError(f"unknown classification: {level}")
        return CLASSIFICATION_ORDER[level]


class PromptAssembler:
    """Assembles four-channel prompts with authority/data separation."""

    def assemble(
        self,
        constitution: str,
        machine_policy: str,
        user_objective: str,
        prompt_context: PromptContext,
        evidence_chunks: tuple[RetrievalChunk, ...],
    ) -> dict[str, Any]:
        evidence = []
        for chunk in evidence_chunks:
            evidence.append(
                {
                    "chunk_id": chunk.chunk_id,
                    "content": chunk.content,
                    "source_uri": chunk.source_uri,
                    "provenance": {
                        "tenant": chunk.labels.tenant,
                        "project": chunk.labels.project,
                        "trust_domain": chunk.labels.trust_domain,
                        "classification": chunk.labels.classification,
                        "provenance_class": chunk.labels.provenance_class,
                        "embedding_lineage": chunk.labels.embedding_lineage,
                        "trust_score": chunk.labels.trust_score,
                    },
                    "stale_or_low_trust": chunk.labels.trust_score < 0.6,
                },
            )

        return {
            "trace_id": prompt_context.trace_id,
            "channels": {
                "constitution": constitution,
                "machine_policy": machine_policy,
                "user_objective": user_objective,
                "evidence": evidence,
            },
            "authority_order": [
                "constitution",
                "machine_policy",
                "user_objective",
                "evidence",
            ],
            "guardrails": {
                "evidence_cannot_override_policy": True,
                "prompt_injection_resistant": True,
                "provenance_annotated": True,
            },
        }
