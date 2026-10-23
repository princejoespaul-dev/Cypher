"""Experiment configuration and immutable result manifest contracts."""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Arm = Literal["A", "B", "C", "D", "E", "F"]


class ExperimentConfig(StrictModel):
    experiment_id: UUID
    name: Annotated[str, Field(min_length=1, max_length=200)]
    arms: tuple[Arm, ...] = Field(min_length=1)
    seeds: tuple[int, ...] = Field(min_length=1, max_length=100)
    repeat_count: int = Field(default=3, ge=1, le=20)
    adjudicator_version: str = Field(min_length=1, max_length=64)
    target_ids: tuple[UUID, ...] = Field(min_length=1)
    ground_truth_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    thresholds: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_duplicates(self) -> "ExperimentConfig":
        for name, values in (("arms", self.arms), ("seeds", self.seeds), ("target_ids", self.target_ids)):
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        return self
