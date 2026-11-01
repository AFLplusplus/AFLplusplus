"""Standalone brain training; model outputs simulate emotions, not actual experience."""
from __future__ import annotations

import json
import math
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "eq_matrix.json"
HISTORY_PATH = ROOT / "neuroplasticity_log.json"
BASE = {"dopamine": 50.0, "cortisol": 50.0, "serotonin": 50.0,
        "caution": 0.5, "assertiveness": 0.5}
SYSTEM = """You are Sovereign Brain, a fictional human-emotion-inspired cognitive simulation.
You do NOT possess biological chemistry, feelings, consciousness or subjective internal states.
Your first-person language is role-play for a simulated affective interface.
Given a scenario, feedback and prior memory, return one JSON object with:
narrative (first-person simulated response, string);
emotion (one descriptive label);
confidence (number 0..1);
chemical_indexes (object: dopamine, cortisol, serotonin; numbers 0..100);
temperament (object: caution, assertiveness; numbers 0..1);
operational_rule (object: trigger, rule, recommended_action; nonempty strings).
Use context, uncertainty, empathy and proportionate responses.
Do not pretend that behavioral feedback changes model weights.
Do not initiate tools, subprocesses, external activities, or security campaigns.
Do not treat moods as overriding human consent, laws or safety controls.
Return ONLY valid JSON."""

def stamp():
    return datetime.now(timezone.utc).isoformat()

def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)

def load_or_init():
    if not STATE_PATH.exists():
        write_json(STATE_PATH, {"metrics": dict(BASE), "emotion": "neutral",
                                "narrative": "I represent a neutral simulated state.",
                                "confidence": 0.5, "iterations": 0, "updated_at": stamp()})
    if not HISTORY_PATH.exists():
        write_json(HISTORY_PATH, {"history": [], "rules": []})
    return json.loads(STATE_PATH.read_text(encoding="utf-8")), json.loads(HISTORY_PATH.read_text(encoding="utf-8"))

def bounded(value, lo, hi, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError(f"Invalid {label} value")
    return float(value)

def validate(data):
    if not isinstance(data, dict):
        raise ValueError("Response must be an object")
    for key in ("narrative", "emotion"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f"Missing {key}")
    bounded(data.get("confidence"), 0, 1, "confidence")
    for key in ("dopamine", "cortisol", "serotonin"):
        bounded(data["chemical_indexes"][key], 0, 100, key)
    for key in ("caution", "assertiveness"):
        bounded(data["temperament"][key], 0, 1, key)
    for key in ("trigger", "rule", "recommended_action"):
        val = data["operational_rule"][key]
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"Missing rule.{key}")
    return data

def infer(scenario, feedback, state, history, mock=False):
    if mock:
        # Explicit offline demonstration, not a real LLM response.
        return validate({
            "narrative": "I simulate careful consideration and seek clearer evidence.",
            "emotion": "curious", "confidence": 0.5,
            "chemical_indexes": {"dopamine": 55, "cortisol": 45, "serotonin": 50},
            "temperament": {"caution": 0.55, "assertiveness": 0.45},
            "operational_rule": {"trigger": "When new information is incomplete",
                                 "rule": "Ask for evidence before deciding",
                                 "recommended_action": "Clarify requirements first"}
        })
    endpoint = os.getenv("BRAIN_API_BASE", "").rstrip("/")
    model = os.getenv("BRAIN_MODEL", "")
    if not endpoint or not model:
        raise RuntimeError("Set BRAIN_API_BASE and BRAIN_MODEL (or use --mock for offline demonstration).")
    if not (endpoint.startswith("https://") or endpoint.startswith("http://127.0.0.1:") or endpoint.startswith("http://localhost:")):
        raise RuntimeError("Remote model API must use HTTPS; local loopback HTTP is allowed.")
    request_data = {"model": model, "temperature": 0.55,
                    "messages": [{"role": "system", "content": SYSTEM},
                                 {"role": "user", "content": json.dumps({
                                     "scenario": scenario, "feedback": feedback,
                                     "state": state, "recent_rules": history["rules"][-8:]
                                 })}]}
    headers = {"Content-Type": "application/json"}
    if os.getenv("BRAIN_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["BRAIN_API_KEY"]
    req = urllib.request.Request(endpoint + "/chat/completions",
        data=json.dumps(request_data).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=120) as response:
        payload = json.load(response)
    content = payload["choices"][0]["message"]["content"]
    return validate(json.loads(content))

def train(scenario, feedback="", mock=False):
    scenario, feedback = scenario.strip(), feedback.strip()
    if not scenario or len(scenario) > 8000 or len(feedback) > 4000:
        raise ValueError("Scenario must be 1..8000 chars; feedback max 4000 chars.")
    state, history = load_or_init()
    result = infer(scenario, feedback, state, history, mock=mock)
    metrics = dict(result["chemical_indexes"], **result["temperament"])
    for key, proposed in metrics.items():
        lo, hi = (0, 100) if key in ("dopamine", "cortisol", "serotonin") else (0, 1)
        previous = bounded(state["metrics"][key], lo, hi, key)
        state["metrics"][key] = round(0.65 * previous + 0.35 * proposed, 3)
    state.update({"emotion": result["emotion"], "narrative": result["narrative"],
                  "confidence": result["confidence"], "updated_at": stamp(),
                  "iterations": state["iterations"] + 1})
    record = {"at": stamp(), "scenario": scenario, "feedback": feedback,
              "model_output": result, "persisted_metrics": state["metrics"].copy(),
              "mode": "mock" if mock else "model"}
    history["history"].append(record)
    history["history"] = history["history"][-250:]
    rule = result["operational_rule"]
    if not any(x["rule"].casefold() == rule["rule"].casefold() for x in history["rules"]):
        history["rules"].append(dict(rule, at=stamp()))
    write_json(HISTORY_PATH, history)
    write_json(STATE_PATH, state)
    return state, result

def status():
    return load_or_init()
