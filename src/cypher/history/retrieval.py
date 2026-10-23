"""Hard-filtered keyword/vector retrieval with reciprocal-rank fusion."""
from __future__ import annotations

import math
import re
from typing import Protocol
from uuid import UUID

from cypher.history.models import CaseRecord, ReviewStatus, RetrievedCase


class EmbeddingProvider(Protocol):
    model_id: str
    def embed(self, text: str) -> tuple[float, ...]: ...


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_./:-]+", text.lower()) if len(t) > 1}


def _cosine(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0


def hybrid_retrieve(*, cases: tuple[CaseRecord, ...], project_id: UUID, vuln_class: str,
                    mutation_dimension: str, method: str, resource_type: str, query_text: str,
                    query_embedding: tuple[float, ...] | None = None, limit: int = 5, rrf_k: int = 60) -> tuple[RetrievedCase, ...]:
    """Only reviewed cases in the caller's project and matching all hard filters are considered."""
    filtered = [c for c in cases if c.project_id == project_id and c.review_status == ReviewStatus.REVIEWED
                and c.vuln_class == vuln_class and c.mutation_dimension == mutation_dimension
                and c.method.upper() == method.upper() and c.resource_type == resource_type]
    qtokens = _tokens(query_text)
    keyword_rows: list[tuple[CaseRecord, float]] = []
    for case in filtered:
        text = f"{case.pattern_summary} {case.fix_pattern} {case.policy_rule_type}"
        tokens = _tokens(text)
        score = len(qtokens & tokens) / max(1, len(qtokens))
        if score > 0:
            keyword_rows.append((case, score))
    keyword_rows.sort(key=lambda pair: (-pair[1], str(pair[0].case_id)))
    keyword_rank = {case.case_id: (rank, score) for rank, (case, score) in enumerate(keyword_rows, 1)}

    vector_rows: list[tuple[CaseRecord, float]] = []
    if query_embedding is not None:
        vector_rows = [(case, _cosine(query_embedding, case.embedding)) for case in filtered if case.embedding is not None
                       and case.embedding_model is not None]
        vector_rows.sort(key=lambda pair: (-pair[1], str(pair[0].case_id)))
    vector_rank = {case.case_id: (rank, score) for rank, (case, score) in enumerate(vector_rows, 1)}

    scores: list[RetrievedCase] = []
    for case in filtered:
        kw = keyword_rank.get(case.case_id)
        vec = vector_rank.get(case.case_id)
        fused = (1.0 / (rrf_k + kw[0]) if kw else 0.0) + (1.0 / (rrf_k + vec[0]) if vec else 0.0)
        if fused <= 0:
            continue
        scores.append(RetrievedCase(case, kw[0] if kw else None, kw[1] if kw else None,
                                    vec[0] if vec else None, vec[1] if vec else None, fused))
    scores.sort(key=lambda row: (-row.fused_score, str(row.case.case_id)))
    return tuple(scores[:max(1, min(limit, 5))])
