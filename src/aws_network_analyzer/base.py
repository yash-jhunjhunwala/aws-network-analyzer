#!/usr/bin/env python3
"""
Base Module for Multi-Cloud Network Analyzer

Provides shared base classes, protocols, and interfaces used across
all cloud providers (AWS, Azure, GCP).

This module defines the common contract that all cloud-specific analyzers
must implement, enabling consistent behavior and code reuse.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Any, Protocol, TypeVar, Generic, Callable
from datetime import datetime
from enum import Enum, auto
import threading


# =============================================================================
# Constants
# =============================================================================

VERSION = "1.0.0"

# Parallelism limits
MAX_PARALLEL_REGIONS = 10
MAX_PARALLEL_ACCOUNTS = 20
MAX_RETRIES = 3
BASE_DELAY = 1.0
MAX_DELAY = 60.0

# Network ports for scanner reachability
SCAN_PORTS = [22, 443, 445, 5985, 5986]  # SSH, HTTPS, SMB, WinRM
EPHEMERAL_RANGE = (1024, 65535)

# Default timeouts
DEFAULT_TIMEOUT = 600  # 10 minutes

# Exit codes
class ExitCode(Enum):
    """Standard exit codes for the analyzer."""
    SUCCESS = 0
    PARTIAL = 1       # Partial coverage - some instances unreachable
    ERROR = 2         # Error during execution
    TIMEOUT = 3       # Timeout exceeded
    INTERRUPTED = 130 # Ctrl+C (128 + SIGINT)


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class AnalysisMode(Enum):
    """Analysis modes."""
    ACCOUNT = "account"  # Single account/subscription/project
    ORG = "org"          # Organization-wide


class RecommendationStatus(Enum):
    """Status of deployment recommendation."""
    SUCCESS = "SUCCESS"       # 100% coverage from single location
    PARTIAL = "PARTIAL"       # Partial coverage, multi-deploy needed
    NO_INSTANCES = "NO_INSTANCES"  # No instances found
    NO_VMS = "NO_VMS"         # Azure variant
    ERROR = "ERROR"           # Analysis failed


class ConnectivityType(Enum):
    """Types of network connectivity."""
    SAME_VPC = "same_vpc"
    SAME_VNET = "same_vnet"
    PEERING = "peering"
    TRANSIT_GATEWAY = "transit_gateway"
    VIRTUAL_WAN = "virtual_wan"
    SHARED_VPC = "shared_vpc"
    ISOLATED = "isolated"
    NONE = "none"


# =============================================================================
# Base Data Models
# =============================================================================

@dataclass
class NetworkInfo:
    """Base class for network/VPC/VNet information."""
    network_id: str
    name: str
    region: str
    cidr_blocks: List[str] = field(default_factory=list)
    is_default: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubnetInfo:
    """Base class for subnet information."""
    subnet_id: str
    name: str
    cidr: str
    network_id: str  # VPC/VNet ID
    region: str
    availability_zone: Optional[str] = None
    is_public: bool = False
    has_internet_access: bool = False
    route_table_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InstanceInfo:
    """Base class for compute instance (EC2/VM/Instance) information."""
    instance_id: str
    name: str
    network_id: str  # VPC/VNet ID
    subnet_id: str
    region: str
    private_ips: List[str] = field(default_factory=list)
    public_ip: Optional[str] = None
    state: str = "running"
    security_groups: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def primary_private_ip(self) -> str:
        """Get the primary private IP address."""
        return self.private_ips[0] if self.private_ips else ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PeeringInfo:
    """Base class for network peering information."""
    peering_id: str
    local_network_id: str
    remote_network_id: str
    local_region: str
    remote_region: str
    state: str
    is_active: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeploymentLocation:
    """Recommended deployment location for scanner."""
    region: str
    network_id: str
    network_name: str
    network_cidr: str
    subnet_id: Optional[str] = None
    subnet_cidr: Optional[str] = None
    is_public: bool = False
    has_internet_access: bool = False
    internet_access_method: str = "none"  # igw, nat, private_access
    instances_reachable: int = 0
    
    # Cloud-specific fields stored as extras
    extras: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Flatten extras into result
        extras = result.pop('extras', {})
        result.update(extras)
        return result


@dataclass
class CoverageInfo:
    """Coverage statistics for a deployment location."""
    total_instances: int
    reachable_instances: int
    percentage: float
    reachable_same_region: int = 0
    reachable_cross_region: int = 0
    unreachable_instances: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectivitySummary:
    """Summary of network connectivity."""
    peered_networks: int = 0
    transit_gateway_networks: int = 0
    isolated_networks: int = 0
    total_peering_connections: int = 0
    total_transit_gateways: int = 0
    
    # Cloud-specific
    cross_account_peered: int = 0
    cross_account_tgw: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FullCoverageDeployment:
    """A single deployment in the full coverage plan."""
    deployment_order: int
    region: str
    network_id: str
    network_name: str
    network_cidr: Optional[str]
    subnet_id: Optional[str]
    subnet_cidr: Optional[str]
    is_public: bool
    has_internet_access: bool
    internet_access_method: str
    covers_instances: int
    cumulative_covered: int = 0
    cumulative_percentage: float = 0.0
    covered_instance_ids: List[str] = field(default_factory=list)
    covered_instances_detail: List[Dict[str, Any]] = field(default_factory=list)
    
    # Cloud-specific extras
    extras: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        extras = result.pop('extras', {})
        result.update(extras)
        return result


@dataclass
class FullCoveragePlan:
    """Complete multi-deployment coverage plan."""
    total_deployments_needed: int
    total_instances_covered: int
    coverage_percentage: float
    unreachable_count: int
    deployments: List[FullCoverageDeployment] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_deployments_needed": self.total_deployments_needed,
            "total_instances_covered": self.total_instances_covered,
            "coverage_percentage": self.coverage_percentage,
            "unreachable_count": self.unreachable_count,
            "deployments": [d.to_dict() for d in self.deployments]
        }


@dataclass
class AnalysisSummary:
    """Summary of analysis results."""
    total_regions_scanned: int
    total_networks: int  # VPCs/VNets
    total_instances: int
    total_subnets: int = 0
    total_peerings: int = 0
    total_transit_gateways: int = 0  # AWS TGW / Azure vWAN
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    """Deployment recommendation."""
    status: RecommendationStatus
    message: str
    deployment_location: Optional[DeploymentLocation]
    coverage: CoverageInfo
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "message": self.message,
            "deployment_location": self.deployment_location.to_dict() if self.deployment_location else None,
            "coverage": self.coverage.to_dict()
        }


# =============================================================================
# Base Analyzer Protocol/Interface
# =============================================================================

T = TypeVar('T')


class BaseNetworkAnalyzer(ABC, Generic[T]):
    """
    Abstract base class for cloud network analyzers.
    
    This defines the common interface that all cloud-specific analyzers
    must implement.
    
    Type parameter T represents the cloud-specific credential type.
    """
    
    def __init__(
        self,
        credentials: T,
        regions: Optional[List[str]] = None,
        max_parallel: int = MAX_PARALLEL_REGIONS,
        quiet: bool = False
    ):
        """
        Initialize the analyzer.
        
        Args:
            credentials: Cloud-specific credentials object
            regions: List of regions to analyze (None = all available)
            max_parallel: Maximum parallel region scans
            quiet: Suppress progress output
        """
        self.credentials = credentials
        self.regions = regions or []
        self.max_parallel = max_parallel
        self.quiet = quiet
        
        # Thread-safe data stores
        self._lock = threading.Lock()
        self.networks: Dict[str, NetworkInfo] = {}
        self.instances: Dict[str, InstanceInfo] = {}
        self.subnets: Dict[str, SubnetInfo] = {}
        self.peerings: List[PeeringInfo] = []
        
        # Reachability matrix: network_id -> network_id -> is_reachable
        self.reachability_matrix: Dict[str, Dict[str, bool]] = {}
        
        # Raw discovery data per region
        self.discovery_data: Dict[str, Any] = {}
    
    @property
    @abstractmethod
    def cloud_provider(self) -> CloudProvider:
        """Return the cloud provider enum."""
        pass
    
    @abstractmethod
    def get_available_regions(self) -> List[str]:
        """Get list of available regions for this cloud."""
        pass
    
    @abstractmethod
    def discover_all(self, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Discover all network resources.
        
        Returns:
            Dictionary with discovery summary
        """
        pass
    
    @abstractmethod
    def _discover_region(self, region: str) -> None:
        """Discover resources in a single region."""
        pass
    
    @abstractmethod
    def _analyze_connectivity(self) -> None:
        """Analyze network-to-network connectivity."""
        pass
    
    @abstractmethod
    def _find_best_location(self) -> Optional[DeploymentLocation]:
        """Find the best single deployment location."""
        pass
    
    @abstractmethod
    def _find_full_coverage_deployments(self) -> List[FullCoverageDeployment]:
        """Find minimum deployments needed for full coverage."""
        pass
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report.
        
        This is the main output method that produces the full report.
        """
        # Find best single location
        best_location = self._find_best_location()
        
        # Calculate coverage
        total_instances = len(self.instances)
        reachable_instances = 0
        unreachable = []
        
        if best_location:
            best_network = best_location.network_id
            for inst_id, inst in self.instances.items():
                if self._is_instance_reachable_from(inst, best_network):
                    reachable_instances += 1
                else:
                    unreachable.append(self._instance_to_unreachable_dict(inst))
        
        coverage_pct = (reachable_instances / total_instances * 100) if total_instances > 0 else 0
        
        # Determine status
        if total_instances == 0:
            status = RecommendationStatus.NO_INSTANCES
            message = "No instances found in the analyzed regions"
        elif coverage_pct == 100 and best_location:
            status = RecommendationStatus.SUCCESS
            message = f"Deploy scanner in {best_location.region} - {best_location.network_name} for 100% coverage"
        else:
            status = RecommendationStatus.PARTIAL
            message = f"Primary location covers {coverage_pct:.1f}% of instances. Multi-region deployment recommended."
        
        # Calculate full coverage plan
        full_coverage_deployments = self._find_full_coverage_deployments()
        full_coverage_total = sum(d.covers_instances for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_instances * 100) if total_instances > 0 else 0
        
        # Build all instances list for HTML reports
        all_instances = self._build_all_instances_list(best_location)
        
        # Build coverage info
        coverage = CoverageInfo(
            total_instances=total_instances,
            reachable_instances=reachable_instances,
            percentage=coverage_pct,
            unreachable_instances=unreachable
        )
        
        # Build recommendation
        recommendation = Recommendation(
            status=status,
            message=message,
            deployment_location=best_location,
            coverage=coverage
        )
        
        # Build full coverage plan
        full_coverage_plan = FullCoveragePlan(
            total_deployments_needed=len(full_coverage_deployments),
            total_instances_covered=full_coverage_total,
            coverage_percentage=full_coverage_pct,
            unreachable_count=total_instances - full_coverage_total,
            deployments=full_coverage_deployments
        )
        
        # Build connectivity summary
        connectivity = self._build_connectivity_summary()
        
        # Build summary
        summary = AnalysisSummary(
            total_regions_scanned=len(self.regions) if self.regions else 0,
            total_networks=len(self.networks),
            total_instances=total_instances,
            total_subnets=len(self.subnets),
            total_peerings=len(self.peerings)
        )
        
        # Assemble final report
        report = {
            "cloud": self.cloud_provider.value,
            "all_instances": all_instances,
            "recommendation": recommendation.to_dict(),
            "full_coverage_plan": full_coverage_plan.to_dict(),
            "summary": summary.to_dict(),
            "connectivity_summary": connectivity.to_dict(),
            "generated_at": datetime.now().isoformat()
        }
        
        # Add cloud-specific fields
        report.update(self._get_cloud_specific_report_fields())
        
        return report
    
    def _is_instance_reachable_from(self, instance: InstanceInfo, network_id: str) -> bool:
        """Check if an instance is reachable from a given network."""
        return (
            instance.network_id == network_id or
            self.reachability_matrix.get(network_id, {}).get(instance.network_id, False)
        )
    
    def _instance_to_unreachable_dict(self, instance: InstanceInfo) -> Dict[str, Any]:
        """Convert an instance to the unreachable instance dict format."""
        return {
            "instance_id": instance.instance_id,
            "name": instance.name,
            "network_id": instance.network_id,
            "region": instance.region,
            "private_ip": instance.primary_private_ip,
            "public_ip": instance.public_ip or ""
        }
    
    def _build_all_instances_list(self, best_location: Optional[DeploymentLocation]) -> List[Dict[str, Any]]:
        """Build complete list of all instances with reachability info for HTML reports."""
        all_instances = []
        best_network = best_location.network_id if best_location else None
        
        for inst_id, inst in self.instances.items():
            is_reachable = self._is_instance_reachable_from(inst, best_network) if best_network else False
            
            inst_dict = inst.to_dict()
            inst_dict["reachable"] = is_reachable
            all_instances.append(inst_dict)
        
        return all_instances
    
    def _build_connectivity_summary(self) -> ConnectivitySummary:
        """Build connectivity summary from peerings data."""
        peered_networks = set()
        for peering in self.peerings:
            if peering.is_active:
                peered_networks.add(peering.local_network_id)
                peered_networks.add(peering.remote_network_id)
        
        isolated = len(self.networks) - len(peered_networks)
        
        return ConnectivitySummary(
            peered_networks=len(peered_networks),
            isolated_networks=isolated,
            total_peering_connections=len(self.peerings)
        )
    
    @abstractmethod
    def _get_cloud_specific_report_fields(self) -> Dict[str, Any]:
        """Return cloud-specific fields to add to the report."""
        pass
    
    def get_discovery_data(self) -> Dict[str, Any]:
        """Return raw discovery data."""
        return self.discovery_data
    
    def validate_discovery_data(self) -> Dict[str, Any]:
        """
        Validate discovered data for consistency and report any issues.
        
        Returns:
            Dictionary containing validation results and any issues found.
        """
        issues = []
        warnings = []
        
        # Validate instances have required fields
        for inst_id, inst in self.instances.items():
            if not inst.instance_id:
                issues.append(f"Instance missing ID: {inst}")
            if not inst.network_id:
                issues.append(f"Instance {inst_id} missing network_id")
            if not inst.region:
                warnings.append(f"Instance {inst_id} missing region")
        
        # Validate subnets
        for subnet_id, subnet in self.subnets.items():
            if not subnet.subnet_id:
                issues.append(f"Subnet missing ID: {subnet}")
            if not subnet.network_id:
                issues.append(f"Subnet {subnet_id} missing network_id")
        
        # Validate networks
        for net_id, net in self.networks.items():
            if not net.network_id:
                issues.append(f"Network missing ID: {net}")
        
        # Cross-reference validation
        for inst_id, inst in self.instances.items():
            if inst.network_id and inst.network_id not in self.networks:
                # Network might be stored by VPC ID directly in self.vpcs for AWS
                warnings.append(f"Instance {inst_id} references unknown network {inst.network_id}")
            if inst.subnet_id and inst.subnet_id not in self.subnets:
                warnings.append(f"Instance {inst_id} references unknown subnet {inst.subnet_id}")
        
        # Count validation
        expected_instances = len(self.instances)
        actual_instances_in_networks = 0
        for region_data in self.discovery_data.values():
            if isinstance(region_data, dict):
                for vpc in region_data.get('vpcs', {}).values():
                    if isinstance(vpc, dict):
                        actual_instances_in_networks += len(vpc.get('instances', {}))
        
        if expected_instances != actual_instances_in_networks:
            warnings.append(
                f"Instance count mismatch: self.instances has {expected_instances}, "
                f"but discovery_data has {actual_instances_in_networks}"
            )
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "stats": {
                "total_networks": len(self.networks),
                "total_subnets": len(self.subnets),
                "total_instances": len(self.instances),
                "total_peerings": len(self.peerings)
            }
        }
