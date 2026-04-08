"""
Inference Script — Incident Response Commander
================================================
Runs an LLM agent against all 3 tasks and emits structured logs.

MANDATORY ENVIRONMENT VARIABLES:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

STDOUT FORMAT (mandatory):
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.00> rewards=<r1,r2,...>

Author: Team Envonox
"""

import os
import sys
import json
from typing import List, Optional

from openai import OpenAI

# ── Import environment directly (no HTTP needed) ──────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from environment import IncidentResponseEnv
from models import IRAction

# ── Environment variables (match sample exactly) ─────────────────────────
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "meta-llama/Llama-3.1-8B-Instruct")
HF_TOKEN     = os.getenv("HF_TOKEN") or os.getenv("API_KEY", "")

BENCHMARK = "incident-response-commander"
MAX_STEPS = 3

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

# ── Structured logging helpers (match sample exactly) ────────────────────

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ── LLM action selection ────────────────────────────────────────────────

ATTACK_VECTORS = [
    "PHISHING_CREDENTIAL_HARVEST", "RANSOMWARE_ENCRYPTION", "SQL_INJECTION",
    "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "DATA_EXFILTRATION",
    "SUPPLY_CHAIN_COMPROMISE", "DNS_TUNNELING", "BRUTE_FORCE_AUTH",
    "INSIDER_THREAT", "ZERO_DAY_EXPLOIT", "COMMAND_AND_CONTROL",
]

SYSTEM_PROMPTS = {
    "classify-severity": (
        "You are an expert SOC analyst performing incident triage. "
        "Assess the severity. Respond with exactly one word: CRITICAL, HIGH, MEDIUM, or LOW. "
        "No explanation."
    ),
    "identify-attack-vector": (
        "You are a threat intelligence analyst. Identify the attack vector. "
        f"Respond with exactly one of: {', '.join(ATTACK_VECTORS)}. "
        "No explanation."
    ),
    "write-remediation": (
        "You are an Incident Response Commander. Write a structured remediation playbook with:\n"
        "1. CONTAINMENT — Immediate actions to stop the spread\n"
        "2. ERADICATION — Steps to remove the threat completely\n"
        "3. RECOVERY — Steps to safely restore operations\n"
        "Be specific. Reference IPs, hostnames, and indicators from the alert."
    ),
}


def get_action_from_llm(task_id: str, obs: dict) -> tuple:
    """Ask the LLM for an action. Returns (response_text, error_or_None)."""
    system = SYSTEM_PROMPTS[task_id]

    parts = []
    if obs.get("context"):
        parts.append(f"Context: {obs['context']}")
    parts.append(f"Instruction: {obs.get('instruction', '')}")
    parts.append("--- SECURITY ALERT ---")
    parts.append(f"Summary: {obs.get('alert_summary', '')}")
    if obs.get("log_excerpt"):
        parts.append(f"Log Excerpt:\n{obs['log_excerpt']}")
    if obs.get("network_indicators"):
        parts.append(f"Network Indicators: {obs['network_indicators']}")
    if obs.get("affected_systems"):
        parts.append(f"Affected Systems: {obs['affected_systems']}")
    if obs.get("timeline"):
        parts.append(f"Timeline: {obs['timeline']}")
    if obs.get("attack_taxonomy"):
        parts.append(f"Valid Labels: {', '.join(obs['attack_taxonomy'])}")
    parts.append("--- END ALERT ---")

    user_msg = "\n".join(parts)

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user_msg},
            ],
            max_tokens=1024,
            temperature=0.0,
        )
        text = completion.choices[0].message.content.strip()
        # Strip markdown code blocks if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:].strip()
            text = text.strip()
        return text, None
    except Exception as e:
        return "", str(e)


def action_to_str(action: str) -> str:
    """Format action as compact string for [STEP] logging."""
    clean = action.replace("\n", " ").replace("\r", "").strip()
    if len(clean) > 120:
        clean = clean[:117] + "..."
    return clean or "null"


# ── Run inference ────────────────────────────────────────────────────────

def run_inference():
    """Run the LLM agent on all 3 tasks with structured logging."""
    task_ids = ["classify-severity", "identify-attack-vector", "write-remediation"]
    env = IncidentResponseEnv()

    for task_id in task_ids:
        rewards: List[float] = []
        steps_taken = 0
        score = 0.0
        success = False

        try:
            obs = env.reset(task_name=task_id)
            obs_dict = obs.model_dump()

            log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

            for step_num in range(1, MAX_STEPS + 1):
                action_text, err = get_action_from_llm(task_id, obs_dict)
                steps_taken = step_num

                result = env.step(IRAction(response=action_text))
                reward = float(result.reward) if result.reward is not None else 0.0
                done = bool(result.done)

                rewards.append(reward)

                log_step(
                    step=step_num,
                    action=action_to_str(action_text),
                    reward=reward,
                    done=done,
                    error=err,
                )

                if done:
                    break

                # Update obs for next iteration
                obs_dict = result.model_dump()

            score = rewards[-1] if rewards else 0.0
            success = score > 0.0

        except Exception as e:
            rewards = rewards or [0.0]
            score = 0.0
            success = False
            log_step(
                step=steps_taken + 1,
                action="null",
                reward=0.0,
                done=True,
                error=str(e),
            )

        log_end(
            success=success,
            steps=steps_taken,
            score=score,
            rewards=rewards,
        )

    sys.exit(0)


if __name__ == "__main__":
    run_inference()
