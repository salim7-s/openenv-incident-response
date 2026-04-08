"""
FastAPI application for Incident Response Commander.
Uses OpenEnv's create_app factory when available,
falls back to a standalone FastAPI app for HuggingFace Spaces.

Author: Team Envonox
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pathlib import Path
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from models import IRAction, IRObservation
from environment import IncidentResponseEnv
from agent import BaselineAgent
from data import ATTACK_VECTORS

# ---------------------------------------------------------------------------
# App Creation
# ---------------------------------------------------------------------------

DESCRIPTION = """
## 🛡️ Incident Response Commander — OpenEnv HTTP API

An OpenEnv-compliant cybersecurity incident response environment
where AI agents act as SOC analysts, triaging incidents with
deterministic grading and partial-credit reward signals.

### Workflow
1. Call `/reset` to start a new episode and get initial observation
2. Call `/step` repeatedly with actions to interact with the environment
3. Episode ends when observation returns `done: true`
4. Call `/state` anytime to inspect current environment state
5. Call `/grader` to evaluate task scores anytime

### Documentation
- **Swagger UI**: Available at `/docs`
- **ReDoc**: Available at `/redoc`
"""

app = FastAPI(
    title="Incident Response Commander — OpenEnv API",
    version="1.0.0",
    description=DESCRIPTION,
)

# Static files directory
STATIC_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Global environment instance
_env = IncidentResponseEnv()


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task_name: Optional[str] = "classify-severity"
    seed: Optional[int] = None
    episode_id: Optional[str] = None

class StepRequest(BaseModel):
    action: Optional[Dict[str, Any]] = None
    response: Optional[str] = None  # Shorthand

class StepResponse(BaseModel):
    observation: Dict[str, Any]
    reward: Optional[float] = None
    done: bool = False
    info: Dict[str, Any] = {}

class StateResponse(BaseModel):
    state: Dict[str, Any]

class GraderResponse(BaseModel):
    task_scores: Dict[str, float]

class BaselineResponse(BaseModel):
    task_scores: Dict[str, float]
    observations: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Core Endpoints
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def serve_frontend():
    """Serve the interactive dashboard."""
    html_path = STATIC_DIR / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path))
    return HTMLResponse("<h1>Incident Response Commander</h1><p>Server running.</p>")


@app.api_route("/reset", methods=["GET", "POST"])
def reset(body: Optional[ResetRequest] = None):
    """Reset the environment and start a new episode."""
    body = body or ResetRequest()
    obs = _env.reset(
        seed=body.seed,
        episode_id=body.episode_id,
        task_name=body.task_name or "classify-severity",
    )
    obs_dict = obs.model_dump(exclude={"reward", "done", "metadata"})
    return {"observation": obs_dict, "reward": obs.reward, "done": obs.done, "info": {}}


@app.post("/step")
def step(body: StepRequest):
    """Submit an agent action and receive graded result."""
    # Handle both {"action": {"response": "..."}} and {"response": "..."}
    if body.action and "response" in body.action:
        response_text = body.action["response"]
    elif body.response:
        response_text = body.response
    elif body.action:
        response_text = str(body.action)
    else:
        response_text = ""

    action = IRAction(response=response_text)
    obs = _env.step(action)
    obs_dict = obs.model_dump(exclude={"reward", "done", "metadata"})

    return {
        "observation": obs_dict,
        "reward": obs.reward,
        "done": obs.done,
        "info": obs.metadata,
    }


@app.get("/state")
def get_state():
    """Return the current environment state."""
    return {"state": _env.state.model_dump()}


@app.get("/health")
def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/schema")
def schema():
    """Return JSON schemas for action and observation types."""
    return {
        "action": IRAction.model_json_schema(),
        "observation": IRObservation.model_json_schema(),
    }


# ---------------------------------------------------------------------------
# Task & Grading Endpoints (inspired by reference project)
# ---------------------------------------------------------------------------

@app.get("/tasks")
def list_tasks():
    """List all available tasks with metadata."""
    return [
        {
            "id": "classify-severity",
            "name": "Classify Incident Severity",
            "difficulty": "easy",
            "description": "Classify a security incident alert as CRITICAL, HIGH, MEDIUM, or LOW",
            "max_steps": 3,
            "score_range": [0.01, 0.99],
        },
        {
            "id": "identify-attack-vector",
            "name": "Identify Attack Vector",
            "difficulty": "medium",
            "description": "Identify the specific attack vector from a MITRE ATT&CK-inspired taxonomy",
            "max_steps": 3,
            "score_range": [0.01, 0.99],
            "taxonomy": ATTACK_VECTORS,
        },
        {
            "id": "write-remediation",
            "name": "Write Remediation Playbook",
            "difficulty": "hard",
            "description": "Write a structured incident remediation playbook",
            "max_steps": 3,
            "score_range": [0.01, 0.99],
        },
    ]


@app.get("/grader")
def get_grader_scores():
    """
    Evaluate current episode and return task scores.
    Runs the baseline agent on each task and returns scores.
    """
    agent = BaselineAgent()
    env = IncidentResponseEnv()
    scores = {}

    for task_id in ["classify-severity", "identify-attack-vector", "write-remediation"]:
        task_rewards = []
        for _ in range(5):  # Run 5 episodes per task for averaging
            obs = env.reset(task_name=task_id)
            obs_dict = obs.model_dump()
            response = agent.select_action(task_id, obs_dict)
            result = env.step(IRAction(response=response))
            task_rewards.append(float(result.reward or 0.0))
        scores[task_id] = round(sum(task_rewards) / len(task_rewards), 2)

    return {"task_scores": scores}


@app.get("/baseline")
def run_baseline():
    """
    Run the rule-based baseline agent on all tasks.
    Returns scores and observation traces for reference.
    """
    agent = BaselineAgent()
    env = IncidentResponseEnv()
    all_observations = []
    scores = {}

    for task_id in ["classify-severity", "identify-attack-vector", "write-remediation"]:
        task_rewards = []
        for _ in range(5):
            obs = env.reset(task_name=task_id)
            obs_dict = obs.model_dump()
            all_observations.append({"task": task_id, "reset": obs_dict})

            response = agent.select_action(task_id, obs_dict)
            result = env.step(IRAction(response=response))

            reward = float(result.reward or 0.0)
            task_rewards.append(reward)
            all_observations.append({
                "task": task_id,
                "action": response[:200],
                "reward": reward,
                "done": result.done,
                "feedback": result.metadata.get("feedback", ""),
            })

        scores[task_id] = round(sum(task_rewards) / len(task_rewards), 2)

    return {"task_scores": scores, "observations": all_observations}


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
