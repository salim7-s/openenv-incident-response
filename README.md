# 🛡️ Incident Response Commander

**An OpenEnv environment for cybersecurity incident response triage and remediation.**

[![OpenEnv](https://img.shields.io/badge/OpenEnv-Compatible-blue)](https://github.com/meta-pytorch/OpenEnv)
[![Python](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Overview

The **Incident Response Commander** is an OpenEnv-compliant environment that trains AI agents to handle real-world cybersecurity incidents. The agent acts as a SOC (Security Operations Center) analyst, performing:

| Task | Difficulty | Description |
|------|-----------|-------------|
| **classify-severity** | 🟢 Easy | Classify alert severity as CRITICAL, HIGH, MEDIUM, or LOW |
| **identify-attack-vector** | 🟡 Medium | Identify attack vector from a 12-label MITRE ATT&CK taxonomy |
| **write-remediation** | 🔴 Hard | Write a structured remediation playbook with containment, eradication, and recovery |

### Features

- **45+ realistic incidents** with syslog/SIEM data, network indicators, and grading metadata
- **Deterministic grading** with partial credit (ordinal distance, kill-chain phase matching, multi-dimensional playbook scoring)
- **3 difficulty levels** for progressive agent training
- **OpenEnv-compliant** — extends `Environment`, `Action`, `Observation`, `State` base classes
- **Production-ready** — Dockerfile, inference script, interactive HTML UI

---

## Quick Start

### 1. Run locally

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn server.app:app --host 0.0.0.0 --port 7860

# Open http://localhost:7860 in your browser
```

### 2. Use the API

```python
import requests

# Reset environment
r = requests.post("http://localhost:7860/reset", json={"task_name": "classify-severity"})
obs = r.json()

# Submit response
r = requests.post("http://localhost:7860/step", json={"action": {"response": "CRITICAL"}})
result = r.json()
print(f"Reward: {result['reward']}, Done: {result['done']}")
```

### 3. Run with OpenEnv client

```python
from client import IncidentResponseClient
from models import IRAction

with IncidentResponseClient(base_url="http://localhost:7860").sync() as env:
    result = env.reset(task_name="classify-severity")
    result = env.step(IRAction(response="CRITICAL"))
    print(result.reward)
```

### 4. Deploy to HuggingFace Spaces

```bash
# Build Docker image
docker build -t incident-response-commander .

# Push to HuggingFace Spaces
# (Upload entire env/ directory as a Docker Space)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reset` | Start a new episode (`{"task_name": "classify-severity"}`) |
| `POST` | `/step` | Submit action (`{"action": {"response": "CRITICAL"}}`) |
| `GET` | `/state` | Get current episode state |
| `GET` | `/tasks` | List all available tasks |
| `GET` | `/health` | Health check |
| `GET` | `/schema` | JSON schemas for action/observation |
| `GET` | `/docs` | Swagger API documentation |
| `GET` | `/` | Interactive UI |

---

## Project Structure

```
env/
├── models.py            # IRAction, IRObservation, IRState (OpenEnv types)
├── environment.py       # IncidentResponseEnv (OpenEnv Environment)
├── grader.py            # Deterministic grading logic
├── data.py              # 45+ incidents organized by difficulty
├── client.py            # IncidentResponseClient (OpenEnv EnvClient)
├── inference.py         # LLM agent with structured logging
├── openenv.yaml         # OpenEnv manifest
├── pyproject.toml       # Python packaging
├── Dockerfile           # Container for HuggingFace Spaces
├── requirements.txt     # Dependencies
├── server/
│   ├── app.py           # FastAPI server (uses create_app)
│   ├── index.html       # Interactive web UI
│   └── __init__.py
└── tests/
    └── test_env.py      # 14 automated tests
```

---

## Scoring

### Severity Classification (Easy)
- **Exact match**: 1.0
- **1 level off** (e.g., HIGH vs CRITICAL): 0.5
- **2 levels off**: 0.25
- **3 levels off**: 0.0
- **Invalid format** (retries left): 0.1

### Attack Vector Identification (Medium)
- **Exact match**: 1.0
- **Same kill-chain phase**: 0.4
- **Related keyword match**: 0.3
- **Valid taxonomy label**: 0.1

### Remediation Playbook (Hard)
Multi-dimensional scoring:
- **Structure** (30%): Has CONTAINMENT, ERADICATION, RECOVERY sections
- **Action coverage** (40%): Mentions key remediation actions
- **Safety** (20%): No dangerous recommendations
- **Specificity** (10%): References specific indicators from alert

---

## Running Tests

```bash
cd project/env
python tests/test_env.py
```

---

## Author

**Team Envonox** — Scaler × Meta PyTorch National Hackathon

## License

MIT
