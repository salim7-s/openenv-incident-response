"""
Grader — Incident Response Commander
======================================
Deterministic grading logic for all 3 tasks.
Returns dicts with score, feedback, done, partial — consumed by the
environment to populate IRObservation.reward and metadata.

Author: Team Envonox
"""

from data import SEVERITY_LEVELS, ATTACK_VECTORS, KILL_CHAIN_PHASES


def grade_severity(response: str, incident: dict, step_count: int, max_steps: int) -> dict:
    """
    Grade severity classification with ordinal distance scoring.

    Returns dict with keys: score, feedback, done, partial
    """
    resp = response.upper().strip().rstrip(".")

    for level in SEVERITY_LEVELS:
        if level in resp:
            resp = level
            break

    correct = incident["severity"]
    reason = incident["reason"]

    if resp == correct:
        return {"score": 0.99, "feedback": f"Correct! Severity is {correct}. {reason}", "done": True, "partial": False}

    if resp in SEVERITY_LEVELS:
        correct_idx = SEVERITY_LEVELS.index(correct)
        resp_idx = SEVERITY_LEVELS.index(resp)
        distance = abs(correct_idx - resp_idx)

        if distance == 1:
            score = 0.5
            feedback = f"Close — you said {resp}, correct is {correct} (1 level off). {reason}"
        elif distance == 2:
            score = 0.25
            feedback = f"Off by 2 levels — you said {resp}, correct is {correct}. {reason}"
        else:
            score = 0.01
            feedback = f"Wrong — you said {resp}, correct is {correct}. {reason}"

        return {"score": score, "feedback": feedback, "done": True, "partial": score > 0}

    if step_count < max_steps:
        return {
            "score": 0.1,
            "feedback": "Invalid response. Respond with exactly one of: CRITICAL, HIGH, MEDIUM, LOW.",
            "done": False,
            "partial": True,
        }
    return {"score": 0.01, "feedback": f"Invalid format. Correct severity was {correct}.", "done": True, "partial": False}


def grade_attack_vector(response: str, incident: dict, step_count: int, max_steps: int) -> dict:
    """
    Grade attack vector identification with kill-chain phase partial credit.

    Returns dict with keys: score, feedback, done, partial
    """
    resp = response.upper().strip().replace(" ", "_").replace("-", "_")
    correct = incident["attack_vector"]
    keywords = incident["keywords"]
    explanation = incident["explanation"]
    correct_phase = incident["kill_chain_phase"]

    if resp == correct:
        return {"score": 0.99, "feedback": f"Perfect! Attack vector: {correct}. {explanation}", "done": True, "partial": False}

    valid = [v.upper() for v in ATTACK_VECTORS]
    in_taxonomy = resp in valid

    same_phase = False
    if in_taxonomy:
        for phase, vectors in KILL_CHAIN_PHASES.items():
            if resp in vectors and phase == correct_phase:
                same_phase = True
                break

    keyword_hit = any(kw in resp for kw in keywords)

    if same_phase and in_taxonomy:
        return {
            "score": 0.4,
            "feedback": f"Same kill-chain phase ({correct_phase}) but wrong specific vector. Correct: {correct}",
            "done": True, "partial": True,
        }
    if keyword_hit and in_taxonomy:
        return {
            "score": 0.3,
            "feedback": f"Related domain but wrong label. Correct: {correct}. {explanation}",
            "done": True, "partial": True,
        }
    if in_taxonomy:
        return {
            "score": 0.1,
            "feedback": f"Valid taxonomy label but incorrect. Correct: {correct}",
            "done": True, "partial": True,
        }
    if keyword_hit:
        return {
            "score": 0.15,
            "feedback": f"Right keyword domain but not a valid taxonomy label. Correct: {correct}",
            "done": True, "partial": True,
        }

    if step_count < max_steps:
        taxonomy_str = ", ".join(ATTACK_VECTORS)
        return {
            "score": 0.05,
            "feedback": f"Invalid response. Choose exactly one from: {taxonomy_str}",
            "done": False, "partial": True,
        }
    return {"score": 0.01, "feedback": f"Incorrect. Correct: {correct}. {explanation}", "done": True, "partial": False}


def grade_remediation(response: str, incident: dict, step_count: int, max_steps: int) -> dict:
    """
    Grade remediation playbook with multi-dimensional scoring.

    Returns dict with keys: score, feedback, done, partial
    """
    if len(response) < 50:
        if step_count < max_steps:
            return {
                "score": 0.01,
                "feedback": "Too short. Write a complete remediation playbook with CONTAINMENT, ERADICATION, and RECOVERY sections.",
                "done": False, "partial": False,
            }
        return {"score": 0.01, "feedback": "Response too short to be a valid remediation playbook.", "done": True, "partial": False}

    resp_lower = response.lower()
    keywords = incident["remediation_keywords"]
    required_sections = incident["required_sections"]
    dangerous_actions = incident["dangerous_actions"]
    min_kw = incident["min_keywords"]

    sections_found = [s for s in required_sections if s.lower() in resp_lower]
    structure_score = (len(sections_found) / len(required_sections)) * 0.3

    matched_keywords = [kw for kw in keywords if kw.lower() in resp_lower]
    coverage_score = (len(matched_keywords) / len(keywords)) * 0.4

    dangerous_found = [d for d in dangerous_actions if d.lower() in resp_lower]
    danger_penalty = len(dangerous_found) * 0.1
    safety_score = max(0.0, 0.2 - danger_penalty)

    specificity_hits = 0
    alert_text = incident.get("alert_summary", "") + " " + incident.get("affected_systems", "")
    alert_words = set(w.strip(",.()")for w in alert_text.split() if len(w) > 5)
    for word in alert_words:
        if word.lower() in resp_lower:
            specificity_hits += 1
    specificity_score = min(0.1, (specificity_hits / max(len(alert_words), 1)) * 0.15)

    raw_score = structure_score + coverage_score + safety_score + specificity_score

    if len(matched_keywords) < min_kw:
        raw_score -= 0.15

    if 200 < len(response) < 2000:
        raw_score += 0.05

    score = round(min(0.99, max(0.01, raw_score)), 2)

    if score >= 0.75:
        feedback = (
            f"Excellent playbook! Sections: {sections_found}. "
            f"Covered {len(matched_keywords)}/{len(keywords)} remediation actions: {matched_keywords}"
        )
    elif score >= 0.5:
        missing_kw = [k for k in keywords if k.lower() not in resp_lower]
        feedback = (
            f"Good effort. Sections: {sections_found}. "
            f"Matched {len(matched_keywords)}/{len(keywords)} actions. "
            f"Missing: {missing_kw[:5]}"
        )
    elif score >= 0.25:
        missing_sections = [s for s in required_sections if s.lower() not in resp_lower]
        feedback = (
            f"Needs improvement. Missing sections: {missing_sections}. "
            f"Only {len(matched_keywords)} remediation actions identified."
        )
    else:
        feedback = (
            f"Inadequate playbook. Must include sections: {required_sections}. "
            f"Cover actions: {keywords[:6]}"
        )

    if dangerous_found:
        feedback += f" WARNING: Dangerous recommendations detected: {dangerous_found}"

    return {"score": score, "feedback": feedback, "done": True, "partial": score < 1.0}
