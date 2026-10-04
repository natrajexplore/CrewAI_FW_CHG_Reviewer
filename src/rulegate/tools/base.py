"""Shared base for tools bound to one ReviewContext.

Tools take the facts from the deterministic pipeline, so agents cannot feed in
fabricated rule or request data. No tool has a write path to any firewall.
"""

from __future__ import annotations

from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class NoArgs(BaseModel):
    """This tool takes no arguments; it works on the change request under review."""


class ContextTool(BaseTool):
    ctx: Any = Field(exclude=True, description="rulegate.pipeline.ReviewContext")
    args_schema: type[BaseModel] = NoArgs
