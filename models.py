"""
Pydantic Models — Incident Response Commander
==============================================
Type-safe Action, Observation, and State models extending
the OpenEnv specification base classes.

Author: Team Envonox
"""

from typing import Any, Dict, List, Optional

from pydantic import Field

try:
    from openenv.core.env_server.types import Action, Observation, State
except ImportError:
    # Fallback for standalone usage without openenv installed
    from pydantic import BaseModel, ConfigDict

    class Action(BaseModel):
        model_config = ConfigDict(extra="forbid", validate_assignment=True, arbitrary_types_allowed=True)
        metadata: Dict[str, Any] = Field(default_factory=dict)

    class Observation(BaseModel):
        model_config = ConfigDict(extra="forbid", validate_assignment=True, arbitrary_types_allowed=True)
        done: bool = Field(default=False)
        reward: float | int | bool | None = Field(default=None)
        metadata: Dict[str, Any] = Field(default_factory=dict)

    class State(BaseModel):
        model_config = ConfigDict(extra="allow", validate_assignment=True, arbitrary_types_allowed=True)
        episode_id: Optional[str] = Field(default=None)
        step_count: int = Field(default=0, ge=0)


# ── Action ──────────────────────────────────────────────────────────────
class IRAction(Action):
    """What the agent sends each step."""
    response: str = Field(..., description="Agent's text response to the incident alert")


# ── Observation ─────────────────────────────────────────────────────────
class IRObservation(Observation):
    """What the agent sees after each reset() or step() call."""
    task_id: str = ""
    task_name: str = ""
    alert_summary: str = ""
    log_excerpt: str = ""
    network_indicators: Optional[str] = None
    affected_systems: Optional[str] = None
    timeline: Optional[str] = None
    instruction: str = ""
    step: int = 0
    max_steps: int = 3
    context: Optional[str] = None
    attack_taxonomy: Optional[List[str]] = None


# ── State ───────────────────────────────────────────────────────────────
class IRState(State):
    """Environment state tracking."""
    task_id: Optional[str] = None
    max_steps: int = 3
    is_done: bool = False
    last_reward: float = 0.0
    all_rewards: List[float] = Field(default_factory=list)
