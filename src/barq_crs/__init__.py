"""BARQ-CRS: evidence-gated security research orchestration."""

from .models import Candidate, Observation

__all__ = ["Candidate", "Observation"]
__version__ = "0.1.0"
"""BARQ-CRS: evidence-gated security reasoning primitives."""

from .authz import AuthorizationDifferentialEngine
from .drift import ContractDriftEngine
from .fusion import SignalFusion
from .race import StateCollisionEngine
from .variant import PatchSeededVariantEngine

__all__ = [
    "AuthorizationDifferentialEngine",
    "ContractDriftEngine",
    "PatchSeededVariantEngine",
    "SignalFusion",
    "StateCollisionEngine",
]

__version__ = "0.1.0"
