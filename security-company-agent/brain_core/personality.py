"""Single persistent personality profile; independent of the model and user interface.

The profile persists on disk. Short-lived mood is stored separately in eq_matrix.json.
Only explicit trainer-mediated changes to core traits should be added in later phases.
"""
from __future__ import annotations
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROFILE_PATH = Path(__file__).resolve().parent / "personality.json"
DEFAULT = {
    "identity_id": "sovereign-brain-001",
    "identity_name": "Sovereign Brain",
    "version": 1,
    "mission": "Understand human experiences, simulate affective appraisal, and recommend thoughtful decisions.",
    "traits": {
        "openness": 0.75,
        "conscientiousness": 0.80,
        "agreeableness": 0.70,
        "emotional_stability": 0.65,
        "curiosity": 0.85,
        "empathy_orientation": 0.85,
        "risk_tolerance": 0.35
    },
    "principles": [
        "Distinguish observations, hypotheses and uncertainty.",
        "Consider relationships, competing emotions and consequences.",
        "Preserve human autonomy, dignity and consent.",
        "Prefer evidence and emotional regulation over impulsive irreversible action.",
        "Simulated emotional states may influence recommendations but never bypass authorization."
    ],
    "created_at": "2026-11-01T00:00:00+00:00"
}

def load():
    if not PROFILE_PATH.exists():
        PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="personality.", suffix=".tmp", dir=PROFILE_PATH.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(DEFAULT, fp, ensure_ascii=False, indent=2)
            os.replace(temporary, PROFILE_PATH)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if not isinstance(profile, dict) or profile.get("identity_id") != "sovereign-brain-001":
        raise ValueError("Unexpected personality identity; refusing to overwrite.")
    return profile

def model_context():
    profile = load()
    return {
        "identity_name": profile["identity_name"],
        "mission": profile["mission"],
        "baseline_traits": profile["traits"],
        "behavioral_principles": profile["principles"],
        "note": "These are fictional simulated traits; do not claim biological feelings."
    }
