"""Single persistent personality profile; independent of the model and user interface.

The profile persists on disk. Short-lived mood is stored separately in eq_matrix.json.
Only explicit trainer-mediated changes to core traits should be added in later phases.
"""
from __future__ import annotations
import json
import os
import tempfile
import math
import copy
import threading
from datetime import datetime, timezone
from pathlib import Path

PROFILE_PATH = Path(__file__).resolve().parent / "personality.json"
_LOCK = threading.RLock()

class PersonalityError(ValueError):
    """Invalid or missing established identity; recovery requires human review."""
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

def validate(profile):
    if not isinstance(profile, dict) or profile.get('identity_id') != DEFAULT['identity_id']:
        raise PersonalityError('Unexpected personality identity; refusing to overwrite.')
    if type(profile.get('version')) is not int or profile['version'] != 1:
        raise PersonalityError('Unsupported personality version; explicit migration is required.')
    for key in ('identity_name', 'mission', 'created_at'):
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            raise PersonalityError('Personality metadata is incomplete; the existing file was preserved.')
    traits = profile.get('traits')
    if not isinstance(traits, dict) or not set(DEFAULT['traits']).issubset(traits):
        raise PersonalityError('Personality traits are incomplete; the existing file was preserved.')
    for value in traits.values():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise PersonalityError('Personality trait values must be finite numbers from 0 to 1.')
    if not isinstance(profile.get('principles'), list) or not profile['principles'] or any(
            not isinstance(item, str) or not item.strip() for item in profile['principles']):
        raise PersonalityError('Personality principles are invalid; the existing file was preserved.')
    return profile

def _load(profile_path=None):
    profile_path = Path(profile_path) if profile_path is not None else PROFILE_PATH
    anchor = profile_path.with_suffix('.identity')
    if anchor.exists() and not profile_path.exists():
        raise PersonalityError('The established personality file is missing. Restore it from backup; no reset was performed.')
    if not profile_path.exists():
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="personality.", suffix=".tmp", dir=profile_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                profile = copy.deepcopy(DEFAULT)
                profile['created_at'] = datetime.now(timezone.utc).isoformat()
                json.dump(profile, fp, ensure_ascii=False, indent=2, allow_nan=False)
                fp.flush()
                os.fsync(fp.fileno())
            try:
                os.link(temporary, profile_path)  # publish a complete file without replacing a concurrent creator
            except FileExistsError:
                pass
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    try:
        profile = validate(json.loads(profile_path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PersonalityError('The personality cannot be read. Existing data was preserved; no reset was performed.') from None
    if anchor.exists():
        try:
            established_id = anchor.read_text(encoding='utf-8').strip()
        except (OSError, UnicodeError):
            raise PersonalityError('The personality identity marker is unreadable; no reset was performed.') from None
        if established_id != profile['identity_id']:
            raise PersonalityError('Personality identity does not match its persistent identity marker.')
    else:
        try:
            with anchor.open('x', encoding='utf-8') as output:
                output.write(profile['identity_id'] + '\n')
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            pass
    return profile

def load(*, profile_path=None, initialize=False):
    """Inspect identity by default; create the established profile only by explicit opt-in."""
    if not initialize:
        return inspect(profile_path=profile_path)
    with _LOCK:
        return _load(profile_path)

def inspect(*, profile_path=None):
    """Read the established profile without creating files or identity markers."""
    profile_path = Path(profile_path) if profile_path is not None else PROFILE_PATH
    with _LOCK:
        if not profile_path.exists():
            return None
        try:
            profile = validate(json.loads(profile_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise PersonalityError('The personality cannot be read. Existing data was preserved; no reset was performed.') from None
        anchor = profile_path.with_suffix('.identity')
        if anchor.exists():
            try:
                established_id = anchor.read_text(encoding='utf-8').strip()
            except (OSError, UnicodeError):
                raise PersonalityError('The personality identity marker is unreadable; no reset was performed.') from None
            if established_id != profile['identity_id']:
                raise PersonalityError('Personality identity does not match its persistent identity marker.')
        return profile

def model_context(profile=None, *, initialize=False, profile_path=None):
    profile = validate(profile) if profile is not None else (
        load(profile_path=profile_path) if initialize else inspect(profile_path=profile_path) or copy.deepcopy(DEFAULT))
    return {
        "identity_id": profile['identity_id'],
        "identity_name": profile["identity_name"],
        "mission": profile["mission"],
        "baseline_traits": profile["traits"],
        "behavioral_principles": profile["principles"],
        "note": "These are fictional simulated traits; do not claim biological feelings."
    }
