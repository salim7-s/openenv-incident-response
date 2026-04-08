"""
Environment — Incident Response Commander
===========================================
Core environment class extending the OpenEnv Environment base.
Implements reset(), step(), and state following the OpenEnv spec.

Author: Team Envonox
"""

import random
import uuid
from typing import Any, Optional

from models import IRAction, IRObservation, IRState
from data import (
    ATTACK_VECTORS, SEVERITY_LEVELS,
    EASY_INCIDENTS, MEDIUM_INCIDENTS, HARD_INCIDENTS,
)
from grader import grade_severity, grade_attack_vector, grade_remediation

try:
    from openenv.core.env_server.interfaces import Environment
except ImportError:
    from abc import ABC, abstractmethod

    class Environment(ABC):
        """Fallback base for standalone usage."""
        def __init__(self, transform=None, rubric=None):
            self.transform = transform
            self.rubric = rubric

        @abstractmethod
        def reset(self, seed=None, episode_id=None, **kwargs): ...

        @abstractmethod
        def step(self, action, timeout_s=None, **kwargs): ...

        @property
        @abstractmethod
        def state(self): ...

        def close(self):
            pass


class IncidentResponseEnv(Environment):
    """
    OpenEnv-compliant cybersecurity incident response environment.

    Tasks:
        classify-severity      (easy)   — Classify alert as CRITICAL/HIGH/MEDIUM/LOW
        identify-attack-vector  (medium) — Identify attack from 12-label taxonomy
        write-remediation       (hard)   — Write structured remediation playbook
    """

    TASKS = {
        "classify-severity":      {"difficulty": "easy",   "max_steps": 3},
        "identify-attack-vector": {"difficulty": "medium", "max_steps": 3},
        "write-remediation":      {"difficulty": "hard",   "max_steps": 3},
    }

    def __init__(self):
        super().__init__()
        self._state = IRState()
        self.current_incident = None
        self._done = False
        self._last_error = None

    # ── reset ───────────────────────────────────────────────────────────
    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> IRObservation:
        """Start a new episode for the given task."""
        task_name = kwargs.get("task_name", "classify-severity")

        if task_name not in self.TASKS:
            raise ValueError(f"Unknown task '{task_name}'. Valid: {list(self.TASKS.keys())}")

        if seed is not None:
            random.seed(seed)

        eid = episode_id or str(uuid.uuid4())
        max_steps = self.TASKS[task_name]["max_steps"]

        self._state = IRState(
            episode_id=eid,
            step_count=0,
            task_id=task_name,
            max_steps=max_steps,
            is_done=False,
            last_reward=0.0,
            all_rewards=[],
        )
        self.current_incident = None
        self._done = False

        if task_name == "classify-severity":
            self.current_incident = random.choice(EASY_INCIDENTS)
            instruction = (
                "You are a SOC analyst. Read the security alert carefully and classify its severity. "
                "Respond with exactly one word: CRITICAL, HIGH, MEDIUM, or LOW."
            )
            return IRObservation(
                task_id=task_name,
                task_name="Classify Incident Severity",
                alert_summary=self.current_incident["alert_summary"],
                log_excerpt=self.current_incident["log_excerpt"],
                network_indicators=self.current_incident.get("network_indicators"),
                affected_systems=self.current_incident.get("affected_systems"),
                timeline=self.current_incident.get("timeline"),
                instruction=instruction,
                step=0,
                max_steps=max_steps,
                context="You are a Tier-2 SOC analyst triaging incoming security alerts at a Fortune 500 company.",
                done=False,
                reward=0.0,
            )

        elif task_name == "identify-attack-vector":
            self.current_incident = random.choice(MEDIUM_INCIDENTS)
            vectors_str = ", ".join(ATTACK_VECTORS)
            instruction = (
                f"You are a threat intelligence analyst. Analyze this security incident and identify the attack vector. "
                f"Respond with exactly one of these labels: {vectors_str}"
            )
            return IRObservation(
                task_id=task_name,
                task_name="Identify Attack Vector",
                alert_summary=self.current_incident["alert_summary"],
                log_excerpt=self.current_incident["log_excerpt"],
                network_indicators=self.current_incident.get("network_indicators"),
                affected_systems=self.current_incident.get("affected_systems"),
                instruction=instruction,
                step=0,
                max_steps=max_steps,
                context="You are analyzing incidents to map them to the MITRE ATT&CK framework for threat intelligence.",
                attack_taxonomy=ATTACK_VECTORS,
                done=False,
                reward=0.0,
            )

        else:  # write-remediation
            self.current_incident = random.choice(HARD_INCIDENTS)
            instruction = (
                "You are an Incident Response Commander. Write a structured remediation playbook for this incident. "
                "Your playbook MUST include three clearly labeled sections:\n"
                "1. CONTAINMENT — Immediate actions to stop the spread\n"
                "2. ERADICATION — Steps to remove the threat completely\n"
                "3. RECOVERY — Steps to restore normal operations safely\n"
                "Be specific. Reference actual systems, IPs, and indicators from the alert."
            )
            return IRObservation(
                task_id=task_name,
                task_name="Write Remediation Playbook",
                alert_summary=self.current_incident["alert_summary"],
                log_excerpt=self.current_incident["log_excerpt"],
                network_indicators=self.current_incident.get("network_indicators"),
                affected_systems=self.current_incident.get("affected_systems"),
                timeline=self.current_incident.get("timeline"),
                instruction=instruction,
                step=0,
                max_steps=max_steps,
                context=f"Incident risk assessment: {self.current_incident['risk']}",
                done=False,
                reward=0.0,
            )

    # ── step ────────────────────────────────────────────────────────────
    def step(
        self,
        action: IRAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IRObservation:
        """Process an agent action and return graded result."""
        if self._done:
            return IRObservation(
                task_id=self._state.task_id or "",
                task_name=self._state.task_id or "",
                alert_summary="",
                log_excerpt="",
                instruction="Episode already finished.",
                step=self._state.step_count,
                max_steps=self._state.max_steps,
                done=True,
                reward=0.0,
                metadata={"feedback": "Episode already finished."},
            )

        self._state.step_count += 1
        response = action.response.strip()
        task_id = self._state.task_id

        # Route to the appropriate grader
        if task_id == "classify-severity":
            result = grade_severity(response, self.current_incident, self._state.step_count, self._state.max_steps)
        elif task_id == "identify-attack-vector":
            result = grade_attack_vector(response, self.current_incident, self._state.step_count, self._state.max_steps)
        elif task_id == "write-remediation":
            result = grade_remediation(response, self.current_incident, self._state.step_count, self._state.max_steps)
        else:
            result = {"score": 0.0, "feedback": "Unknown task.", "done": True, "partial": False}

        score = result["score"]
        self._state.last_reward = score
        self._state.all_rewards.append(score)
        self._done = result["done"] or self._state.step_count >= self._state.max_steps
        self._state.is_done = self._done

        return IRObservation(
            task_id=task_id or "",
            task_name=task_id or "",
            alert_summary=self.current_incident.get("alert_summary", "") if self.current_incident else "",
            log_excerpt=self.current_incident.get("log_excerpt", "") if self.current_incident else "",
            instruction="Episode complete." if self._done else "Continue.",
            step=self._state.step_count,
            max_steps=self._state.max_steps,
            done=self._done,
            reward=score,
            metadata={
                "feedback": result["feedback"],
                "partial": result.get("partial", False),
                "step": self._state.step_count,
                "task": task_id,
            },
        )

    # ── state ───────────────────────────────────────────────────────────
    @property
    def state(self) -> IRState:
        """Return the current environment state."""
        return self._state
