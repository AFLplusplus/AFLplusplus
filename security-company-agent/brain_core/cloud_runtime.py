"""Process-local pending cloud consent. Not persisted; reruns retain state only in memory."""
from __future__ import annotations
from .cloud_consent import CloudApprovalManager

MANAGER = CloudApprovalManager()
