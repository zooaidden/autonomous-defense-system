"""Pydantic schemas for the OPS chat endpoint.

Only the request side gets a strict schema. The response is intentionally
returned as a plain ``dict`` so the orchestrator can evolve its envelope
fields (``mcpTrace``, ``executionResult``, ``auditTrail``) without
forcing a wire-protocol bump every time.

This mirrors the convention used by ``POST /workflow/run`` in
``main.py`` (request is typed, response is dict).
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class OpsChatRequest(BaseModel):
    """Single-shot natural-language OPS request."""

    instruction: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="Natural-language OPS request from the operator.",
    )


__all__ = ["OpsChatRequest"]
