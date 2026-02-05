"""
Multi-Cloud Network Reachability Analyzer

A production-grade tool for analyzing network infrastructure across AWS, Azure, 
and GCP to find optimal deployment locations for scanner VMs with maximum reachability.

Features:
- Multi-cloud support (AWS, Azure, GCP)
- Multi-region parallel scanning
- VPC/VNet peering and Transit Gateway analysis
- Multiple export formats (JSON, CSV, HTML)
- Retry logic with exponential backoff
- Progress indicators and logging
- Caching and resumable scans
- AWS Organization / Azure Management Group / GCP Organization support

Example (AWS):
    >>> from aws_network_analyzer import AWSNetworkAnalyzer
    >>> import boto3
    >>> session = boto3.Session()
    >>> analyzer = AWSNetworkAnalyzer(session, ["us-east-1", "us-west-2"])
    >>> analyzer.discover_all()
    >>> report = analyzer.generate_report()
    >>> print(report["recommendation"]["status"])

Example (Azure):
    >>> from aws_network_analyzer.azure_analyzer import AzureNetworkAnalyzer
    >>> from azure.identity import DefaultAzureCredential
    >>> analyzer = AzureNetworkAnalyzer("subscription-id", DefaultAzureCredential())
    >>> analyzer.discover_all()
    >>> report = analyzer.generate_report()

Example (GCP):
    >>> from aws_network_analyzer.gcp_analyzer import GCPNetworkAnalyzer
    >>> analyzer = GCPNetworkAnalyzer("project-id")
    >>> analyzer.discover_all()
    >>> report = analyzer.generate_report()
"""

# Import version from base module for single source of truth
from aws_network_analyzer.base import VERSION

__version__ = VERSION
__author__ = "Yash Jhunjhunwala"
__email__ = "yash.jhunjhunwala@gmail.com"

# Core modules
from aws_network_analyzer.analyzer import AWSNetworkAnalyzer

# Base classes and utilities
from aws_network_analyzer.base import (
    CloudProvider,
    ExitCode,
    RecommendationStatus,
    SubnetInfo,
    InstanceInfo,
    NetworkInfo,
    PeeringInfo,
    DeploymentLocation,
    CoverageInfo,
    FullCoverageDeployment,
    FullCoveragePlan,
    Recommendation,
    AnalysisSummary,
    ConnectivitySummary,
)
from aws_network_analyzer.utils import (
    retry_with_backoff,
    ProgressIndicator,
    ETAProgressTracker,
    setup_logging,
    logger,
    check_cidr_overlap,
    cidr_contains_ip,
    parallel_execute,
)
from aws_network_analyzer.exporters import (
    JSONExporter,
    CSVExporter,
    SummaryExporter,
    get_exporter,
    export_report,
)

# Optional cloud imports - gracefully handle missing dependencies
try:
    from aws_network_analyzer.azure_analyzer import AzureNetworkAnalyzer, AzureOrgAnalyzer
except ImportError:
    AzureNetworkAnalyzer = None
    AzureOrgAnalyzer = None

try:
    from aws_network_analyzer.gcp_analyzer import GCPNetworkAnalyzer, GCPOrgAnalyzer
except ImportError:
    GCPNetworkAnalyzer = None
    GCPOrgAnalyzer = None

# Import caching and HTML report modules
try:
    from aws_network_analyzer.cache import ScanCache, ScanStateManager, ProgressTracker
    from aws_network_analyzer.html_report import generate_html_report
except ImportError:
    ScanCache = None
    ScanStateManager = None
    ProgressTracker = None
    generate_html_report = None

__all__ = [
    # Version
    "__version__",
    
    # Core analyzers
    "AWSNetworkAnalyzer",
    "AzureNetworkAnalyzer",
    "AzureOrgAnalyzer",
    "GCPNetworkAnalyzer",
    "GCPOrgAnalyzer",
    
    # Base classes and enums
    "CloudProvider",
    "ExitCode",
    "RecommendationStatus",
    
    # Data models
    "SubnetInfo",
    "InstanceInfo",
    "NetworkInfo",
    "PeeringInfo",
    "DeploymentLocation",
    "CoverageInfo",
    "FullCoverageDeployment",
    "FullCoveragePlan",
    "Recommendation",
    "AnalysisSummary",
    "ConnectivitySummary",
    
    # Utilities
    "retry_with_backoff",
    "ProgressIndicator",
    "ETAProgressTracker",
    "setup_logging",
    "logger",
    "check_cidr_overlap",
    "cidr_contains_ip",
    "parallel_execute",
    
    # Exporters
    "JSONExporter",
    "CSVExporter",
    "SummaryExporter",
    "get_exporter",
    "export_report",
    
    # Cache and HTML
    "ScanCache",
    "ScanStateManager",
    "ProgressTracker",
    "generate_html_report",
]
