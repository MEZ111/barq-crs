"""BARQ-CRS: evidence-gated cyber verification for authorized research."""

from .api_graph import OpenApiDependencyGraph
from .authz import AuthorizationDifferentialEngine
from .bounty import BountyRunner, EndpointPrioritizer
from .campaign import CampaignRunner
from .collector import EvidenceCollector
from .drift import ContractDriftEngine
from .fusion import SignalFusion
from .mobile import AndroidArtifactAnalyzer
from .models import Candidate, Observation
from .race import StateCollisionEngine
from .schema_fuzz import OpenApiTestPlanner
from .smart_verify import DiscoveryTemplateSynthesizer, SmartBountyRunner
from .variant import PatchSeededVariantEngine
from .verifier import (
    ActiveAuthorizationVerifier,
    OpenApiReadTemplatePlanner,
    VerificationRunner,
)

__all__ = [
    "ActiveAuthorizationVerifier",
    "AndroidArtifactAnalyzer",
    "AuthorizationDifferentialEngine",
    "BountyRunner",
    "CampaignRunner",
    "Candidate",
    "ContractDriftEngine",
    "DiscoveryTemplateSynthesizer",
    "EndpointPrioritizer",
    "EvidenceCollector",
    "Observation",
    "OpenApiDependencyGraph",
    "OpenApiReadTemplatePlanner",
    "OpenApiTestPlanner",
    "PatchSeededVariantEngine",
    "SignalFusion",
    "SmartBountyRunner",
    "StateCollisionEngine",
    "VerificationRunner",
]

__version__ = "0.6.0"
