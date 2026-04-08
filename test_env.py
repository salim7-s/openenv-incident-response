"""
Verification Script — Incident Response Commander
===================================================
Validates environment, grading, and baseline agent.
Run: python test_env.py

Author: Team Envonox
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from environment import IncidentResponseEnv
from models import IRAction
from agent import BaselineAgent

def test():
    print("Testing Incident Response Commander...")

    env = IncidentResponseEnv()
    agent = BaselineAgent()

    # Test all 3 tasks with baseline agent
    scores = {}
    for task_id in ["classify-severity", "identify-attack-vector", "write-remediation"]:
        task_rewards = []
        for _ in range(5):
            obs = env.reset(task_name=task_id)
            obs_dict = obs.model_dump()
            response = agent.select_action(task_id, obs_dict)
            result = env.step(IRAction(response=response))
            reward = float(result.reward or 0.0)
            task_rewards.append(reward)

            # Verify reward range
            assert 0.0 <= reward <= 1.0, f"Reward {reward} out of range for {task_id}"
            assert result.done is True, f"Episode should be done after first step for {task_id}"

        avg = sum(task_rewards) / len(task_rewards)
        scores[task_id] = round(avg, 2)
        print(f"  {task_id}: avg_score={avg:.2f}")

    # Verify all scores > 0
    for task_id, score in scores.items():
        assert score > 0, f"Score for {task_id} should be > 0, got {score}"

    print(f"\nAll Scores: {scores}")
    print("Verification successful!")

if __name__ == "__main__":
    test()
