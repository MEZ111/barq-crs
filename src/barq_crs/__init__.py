"""BARQ-CRS: evidence-gated cyber reasoning for authorized research."""

from .api_graph import OpenApiDependencyGraph
from .authz import AuthorizationDifferentialEngine
from .campaign import CampaignRunner
from .collector import EvidenceCollector
from .drift import ContractDriftEngine
from .fusion import SignalFusion
from .mobile import AndroidArtifactAnalyzer
from .models import Candidate, Observation
from .race import StateCollisionEngine
from .schema_fuzz import OpenApiTestPlanner
from .variant import PatchSeededVariantEngine

__all__ = [
    "AndroidArtifactAnalyzer",
    "AuthorizationDifferentialEngine",
    "CampaignRunner",
    "Candidate",
    "ContractDriftEngine",
    "EvidenceCollector",
    "Observation",
    "OpenApiDependencyGraph",
    "OpenApiTestPlanner",
    "PatchSeededVariantEngine",
    "SignalFusion",
    "StateCollisionEngine",
]

__version__ = "0.3.0"
