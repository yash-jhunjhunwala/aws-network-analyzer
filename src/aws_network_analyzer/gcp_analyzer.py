#!/usr/bin/env python3
"""
GCP Network Reachability Analyzer

Finds the optimal VPC and subnet to deploy a VM that can reach
all other VMs across VPCs, regions, and projects.

Requires: pip install google-cloud-compute google-cloud-resource-manager google-auth

Refactored to use shared base classes and utilities.
"""

import sys
import time
import random
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import shared modules
from .base import VERSION, CloudProvider, MAX_PARALLEL_REGIONS, MAX_PARALLEL_ACCOUNTS
from .utils import ProgressIndicator, logger

try:
    from google.cloud import compute_v1
    from google.cloud import resourcemanager_v3
    from google.auth import default as google_auth_default
    from google.oauth2 import service_account
    GCP_SDK_AVAILABLE = True
except ImportError:
    GCP_SDK_AVAILABLE = False

MAX_RETRIES = 5
BASE_DELAY = 1.0
MAX_DELAY = 60.0


def gcp_retry(func, *args, max_retries=MAX_RETRIES, **kwargs):
    """
    Execute GCP API call with retry logic for transient errors.
    
    Uses exponential backoff with jitter to handle GCP API rate limits.
    """
    from google.api_core import exceptions as gcp_exceptions
    
    last_exception = None
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except gcp_exceptions.ResourceExhausted as e:
            # Quota exceeded - retry with backoff
            last_exception = e
            delay = min(BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), MAX_DELAY)
            logger.debug(f"GCP API quota exceeded, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
            continue
        except gcp_exceptions.ServiceUnavailable as e:
            # Service unavailable - retry with backoff
            last_exception = e
            delay = min(BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), MAX_DELAY)
            logger.debug(f"GCP service unavailable, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
            continue
        except gcp_exceptions.DeadlineExceeded as e:
            # Timeout - retry with backoff
            last_exception = e
            delay = min(BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), MAX_DELAY)
            logger.debug(f"GCP deadline exceeded, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
            continue
        except Exception as e:
            # Unknown error - don't retry
            raise
    
    # Exhausted retries
    if last_exception:
        raise last_exception
    return None


def check_gcp_sdk():
    """Check if GCP SDK is installed."""
    if not GCP_SDK_AVAILABLE:
        raise ImportError(
            "GCP SDK not installed. Install with:\n"
            "pip install google-cloud-compute google-cloud-resource-manager google-auth"
        )


# Use shared ProgressIndicator with GCP alias for backwards compatibility
GCPProgressIndicator = ProgressIndicator


@dataclass
class GCPVMInfo:
    """Information about a GCP VM instance."""
    instance_id: str
    name: str
    project: str
    zone: str
    region: str
    vpc_name: str
    subnet_name: str
    private_ips: List[str]
    public_ip: Optional[str]
    network_tags: List[str]
    state: str


@dataclass
class GCPSubnetInfo:
    """Information about a GCP subnet."""
    subnet_id: str
    name: str
    region: str
    ip_cidr_range: str
    vpc_name: str
    project: str
    private_ip_google_access: bool
    secondary_ip_ranges: List[Dict]


@dataclass
class GCPVPCInfo:
    """Information about a GCP VPC."""
    vpc_id: str
    name: str
    project: str
    auto_create_subnetworks: bool
    routing_mode: str
    subnets: Dict[str, Any] = field(default_factory=dict)
    instances: Dict[str, Any] = field(default_factory=dict)
    peerings: List[str] = field(default_factory=list)


class GCPNetworkAnalyzer:
    """
    Analyzes GCP network infrastructure to find optimal deployment locations.
    
    Discovers VPCs, VMs, peering connections, and Shared VPCs across regions
    to calculate reachability and recommend deployment locations.
    
    Attributes:
        cloud_provider: CloudProvider enum indicating this is GCP
        version: Current analyzer version from base module
    """
    
    cloud_provider = CloudProvider.GCP
    version = VERSION
    
    def __init__(self, project_id: str, credentials=None, regions: List[str] = None,
                 max_parallel: int = MAX_PARALLEL_REGIONS, quiet: bool = False):
        """
        Initialize the GCP analyzer.
        
        Args:
            project_id: GCP project ID
            credentials: GCP credentials (if None, uses default)
            regions: List of GCP regions to analyze (if None, discovers all)
            max_parallel: Maximum parallel region scans
            quiet: Suppress progress output
        """
        check_gcp_sdk()
        
        self.project_id = project_id
        self.project_name = project_id  # GCP uses project_id as the name
        self.credentials = credentials
        self.regions = regions or []
        self.max_parallel = max_parallel
        self.quiet = quiet
        
        logger.debug(f"Initialized GCPNetworkAnalyzer v{VERSION} for project {project_id}")
        
        # Initialize clients
        if credentials:
            self.instances_client = compute_v1.InstancesClient(credentials=credentials)
            self.networks_client = compute_v1.NetworksClient(credentials=credentials)
            self.subnetworks_client = compute_v1.SubnetworksClient(credentials=credentials)
            self.regions_client = compute_v1.RegionsClient(credentials=credentials)
            self.zones_client = compute_v1.ZonesClient(credentials=credentials)
        else:
            self.instances_client = compute_v1.InstancesClient()
            self.networks_client = compute_v1.NetworksClient()
            self.subnetworks_client = compute_v1.SubnetworksClient()
            self.regions_client = compute_v1.RegionsClient()
            self.zones_client = compute_v1.ZonesClient()
        
        # Thread-safe data stores
        self._lock = threading.Lock()
        self.vpcs: Dict[str, GCPVPCInfo] = {}
        self.instances: Dict[str, GCPVMInfo] = {}
        self.subnets: Dict[str, GCPSubnetInfo] = {}
        self.peerings: List[Dict] = []
        
        # Results
        self.reachability_matrix: Dict[str, Dict[str, bool]] = {}
        self.discovery_data: Dict[str, Any] = {}
    
    def get_regions(self) -> List[str]:
        """Get list of available GCP regions."""
        if self.regions:
            return self.regions
        
        regions = []
        request = compute_v1.ListRegionsRequest(project=self.project_id)
        for region in self.regions_client.list(request=request):
            if region.status == "UP":
                regions.append(region.name)
        return regions
    
    def get_zones(self) -> List[str]:
        """Get list of available GCP zones."""
        zones = []
        request = compute_v1.ListZonesRequest(project=self.project_id)
        for zone in self.zones_client.list(request=request):
            if zone.status == "UP":
                # Filter by regions if specified
                region = zone.name.rsplit('-', 1)[0]
                if not self.regions or region in self.regions:
                    zones.append(zone.name)
        return zones
    
    def discover_all(self, progress_callback=None, quiet: bool = False) -> Dict[str, Any]:
        """
        Discover all network resources across configured regions.
        
        Returns:
            Dictionary with discovery summary
        """
        # Discover VPCs first (global resource)
        self._discover_vpcs()
        
        # Get regions and zones
        if not self.regions:
            self.regions = self.get_regions()
        
        zones = self.get_zones()
        
        print(f"Scanning {len(zones)} GCP zones across {len(self.regions)} regions...")
        progress = GCPProgressIndicator(len(zones), "Scanning zones", quiet or self.quiet)
        
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            futures = {
                executor.submit(self._discover_zone, zone): zone 
                for zone in zones
            }
            
            for future in as_completed(futures):
                zone = futures[future]
                try:
                    future.result()
                    progress.update(zone, "done")
                    if progress_callback:
                        progress_callback(f"Completed {zone}")
                except Exception as e:
                    logger.error(f"Error discovering zone {zone}: {e}")
                    progress.update(zone, f"error: {e}")
        
        progress.finish()
        
        # Discover subnets
        self._discover_subnets()
        
        # Analyze connectivity
        self._analyze_connectivity()
        
        # Validate discovered data
        self._validate_and_log_data()
        
        return {
            "total_vpcs": len(self.vpcs),
            "total_instances": len(self.instances),
            "total_subnets": len(self.subnets),
            "total_peerings": len(self.peerings),
            "regions_scanned": len(self.regions)
        }
    
    def _validate_and_log_data(self) -> None:
        """Validate discovered data and log any issues."""
        # Count instances from VPCs
        instances_from_vpcs = 0
        for vpc in self.vpcs.values():
            instances_from_vpcs += len(vpc.instances)
        
        instances_from_self = len(self.instances)
        vpcs_from_self = len(self.vpcs)
        
        logger.debug(f"GCP Validation: self.instances={instances_from_self}, vpcs.instances={instances_from_vpcs}")
        
        if instances_from_self != instances_from_vpcs:
            logger.warning(
                f"GCP data inconsistency: self.instances has {instances_from_self} entries, "
                f"but VPCs have {instances_from_vpcs} instances"
            )
        
        # Verify all instances have valid VPC references
        orphan_instances = 0
        for inst_id, inst in self.instances.items():
            if inst.vpc_name not in self.vpcs:
                orphan_instances += 1
                logger.debug(f"Instance {inst_id} references unknown VPC {inst.vpc_name}")
        
        if orphan_instances > 0:
            logger.warning(f"GCP: {orphan_instances} instances reference unknown VPCs")
        
        logger.info(f"GCP discovery complete: {vpcs_from_self} VPCs, {instances_from_self} instances, "
                   f"{len(self.subnets)} subnets, {len(self.peerings)} peerings")
    
    def _discover_vpcs(self) -> None:
        """Discover all VPCs in the project."""
        try:
            request = compute_v1.ListNetworksRequest(project=self.project_id)
            for network in self.networks_client.list(request=request):
                vpc_info = GCPVPCInfo(
                    vpc_id=str(network.id),
                    name=network.name,
                    project=self.project_id,
                    auto_create_subnetworks=network.auto_create_subnetworks or False,
                    routing_mode=network.routing_config.routing_mode if network.routing_config else "REGIONAL",
                    subnets={},
                    instances={},
                    peerings=[p.name for p in (network.peerings or [])]
                )
                
                # Get peering details
                for peering in (network.peerings or []):
                    peering_info = {
                        "name": peering.name,
                        "network": peering.network,
                        "state": peering.state,
                        "export_custom_routes": peering.export_custom_routes,
                        "import_custom_routes": peering.import_custom_routes
                    }
                    with self._lock:
                        if not any(p['name'] == peering_info['name'] for p in self.peerings):
                            self.peerings.append(peering_info)
                
                with self._lock:
                    self.vpcs[network.name] = vpc_info
        
        except Exception as e:
            print(f"Error discovering VPCs: {e}", file=sys.stderr)
    
    def _discover_zone(self, zone: str) -> None:
        """Discover all instances in a zone."""
        region = zone.rsplit('-', 1)[0]
        
        try:
            request = compute_v1.ListInstancesRequest(
                project=self.project_id,
                zone=zone
            )
            
            for instance in self.instances_client.list(request=request):
                # Get network info
                private_ips = []
                public_ip = None
                vpc_name = None
                subnet_name = None
                
                for nic in (instance.network_interfaces or []):
                    if nic.network_i_p:
                        private_ips.append(nic.network_i_p)
                    
                    # Extract VPC name from network URL
                    if nic.network:
                        vpc_name = nic.network.split('/')[-1]
                    
                    # Extract subnet name from subnetwork URL
                    if nic.subnetwork:
                        subnet_name = nic.subnetwork.split('/')[-1]
                    
                    # Get public IP from access configs
                    for access_config in (nic.access_configs or []):
                        if access_config.nat_i_p:
                            public_ip = access_config.nat_i_p
                            break
                
                if not vpc_name:
                    continue
                
                instance_info = GCPVMInfo(
                    instance_id=str(instance.id),
                    name=instance.name,
                    project=self.project_id,
                    zone=zone,
                    region=region,
                    vpc_name=vpc_name,
                    subnet_name=subnet_name or "",
                    private_ips=private_ips,
                    public_ip=public_ip,
                    network_tags=list(instance.tags.items) if instance.tags else [],
                    state=instance.status
                )
                
                with self._lock:
                    self.instances[instance.name] = instance_info
                    if vpc_name in self.vpcs:
                        self.vpcs[vpc_name].instances[instance.name] = asdict(instance_info)
        
        except Exception as e:
            print(f"Error discovering zone {zone}: {e}", file=sys.stderr)
    
    def _discover_subnets(self) -> None:
        """Discover all subnets across regions."""
        for region in self.regions:
            try:
                request = compute_v1.ListSubnetworksRequest(
                    project=self.project_id,
                    region=region
                )
                
                for subnet in self.subnetworks_client.list(request=request):
                    vpc_name = subnet.network.split('/')[-1] if subnet.network else None
                    
                    subnet_info = GCPSubnetInfo(
                        subnet_id=str(subnet.id),
                        name=subnet.name,
                        region=region,
                        ip_cidr_range=subnet.ip_cidr_range or "",
                        vpc_name=vpc_name or "",
                        project=self.project_id,
                        private_ip_google_access=subnet.private_ip_google_access or False,
                        secondary_ip_ranges=[
                            {"name": r.range_name, "cidr": r.ip_cidr_range}
                            for r in (subnet.secondary_ip_ranges or [])
                        ]
                    )
                    
                    with self._lock:
                        self.subnets[f"{region}/{subnet.name}"] = subnet_info
                        if vpc_name and vpc_name in self.vpcs:
                            self.vpcs[vpc_name].subnets[f"{region}/{subnet.name}"] = asdict(subnet_info)
            
            except Exception as e:
                print(f"Error discovering subnets in {region}: {e}", file=sys.stderr)
    
    def _analyze_connectivity(self) -> None:
        """Analyze VPC-to-VPC connectivity via peerings."""
        # In GCP, VPCs are global, so all instances in the same VPC can reach each other
        # Peered VPCs can also communicate
        
        for vpc_name in self.vpcs:
            self.reachability_matrix[vpc_name] = {}
            
            for other_vpc_name in self.vpcs:
                if vpc_name == other_vpc_name:
                    self.reachability_matrix[vpc_name][other_vpc_name] = True
                    continue
                
                # Check if VPCs are peered
                is_peered = any(
                    p['network'].split('/')[-1] == other_vpc_name and p['state'] == 'ACTIVE'
                    for p in self.peerings
                    if p.get('name', '').startswith(vpc_name) or vpc_name in str(p.get('network', ''))
                )
                
                self.reachability_matrix[vpc_name][other_vpc_name] = is_peered
    
    def _find_best_location(self) -> Optional[Dict]:
        """Find the VPC/subnet with maximum reachability."""
        if not self.vpcs:
            return None
        
        best_vpc = None
        best_coverage = 0
        best_subnet = None
        best_region = None
        
        for vpc_name, vpc in self.vpcs.items():
            # Count reachable instances from this VPC
            reachable = 0
            for inst in self.instances.values():
                if inst.vpc_name == vpc_name or self.reachability_matrix.get(vpc_name, {}).get(inst.vpc_name, False):
                    reachable += 1
            
            if reachable > best_coverage:
                best_coverage = reachable
                best_vpc = vpc
                
                # Find best subnet (prefer one with private Google access)
                for subnet_key, subnet_data in vpc.subnets.items():
                    subnet = self.subnets.get(subnet_key)
                    if subnet and subnet.private_ip_google_access:
                        best_subnet = subnet
                        best_region = subnet.region
                        break
                
                if not best_subnet and vpc.subnets:
                    first_subnet_key = list(vpc.subnets.keys())[0]
                    best_subnet = self.subnets.get(first_subnet_key)
                    if best_subnet:
                        best_region = best_subnet.region
        
        if not best_vpc:
            return None
        
        return {
            "project": self.project_id,
            "region": best_region,
            "vpc_name": best_vpc.name,
            "vpc_id": best_vpc.vpc_id,
            "subnet_name": best_subnet.name if best_subnet else None,
            "subnet_cidr": best_subnet.ip_cidr_range if best_subnet else None,
            "private_google_access": best_subnet.private_ip_google_access if best_subnet else False,
            "instances_reachable": best_coverage
        }
    
    def _find_full_coverage_deployments(self) -> List[Dict]:
        """
        Find the MINIMUM set of deployment locations needed to cover ALL instances.
        Uses a greedy set cover algorithm.
        
        Returns:
            List of deployment locations, each covering a subset of instances.
            Together they cover all reachable instances.
        """
        if not self.instances:
            return []
        
        # Build a mapping of each VPC to the set of instances it can reach
        candidates = {}  # vpc_name -> {"vpc": vpc, "subnet": subnet, "instances": set()}
        
        for vpc_name, vpc in self.vpcs.items():
            # Find all instances reachable from this VPC
            reachable_inst_ids = set()
            
            for inst_id, inst in self.instances.items():
                # Instance is reachable if it's in the same VPC or in a peered VPC
                if inst.vpc_name == vpc_name or self.reachability_matrix.get(vpc_name, {}).get(inst.vpc_name, False):
                    reachable_inst_ids.add(inst_id)
            
            if reachable_inst_ids:
                # Find best subnet
                best_subnet = None
                best_region = None
                for subnet_key in vpc.subnets:
                    subnet = self.subnets.get(subnet_key)
                    if subnet:
                        if subnet.private_ip_google_access:
                            best_subnet = subnet
                            best_region = subnet.region
                            break
                        if not best_subnet:
                            best_subnet = subnet
                            best_region = subnet.region
                
                candidates[vpc_name] = {
                    "vpc": vpc,
                    "subnet": best_subnet,
                    "region": best_region,
                    "instances": reachable_inst_ids
                }
        
        if not candidates:
            return []
        
        # Greedy set cover algorithm
        all_instances = set(self.instances.keys())
        uncovered = all_instances.copy()
        selected_deployments = []
        
        while uncovered:
            # Find the candidate that covers the most uncovered instances
            best_candidate = None
            best_coverage = set()
            best_key = None
            
            for key, data in candidates.items():
                newly_covered = data["instances"] & uncovered
                if len(newly_covered) > len(best_coverage):
                    best_coverage = newly_covered
                    best_candidate = data
                    best_key = key
            
            if not best_candidate or not best_coverage:
                break
            
            vpc = best_candidate["vpc"]
            subnet = best_candidate["subnet"]
            region = best_candidate["region"]
            
            # Get VPC peerings
            vpc_peerings = [p for p in self.peerings if p.get('network', '').endswith(f'/{vpc.name}')]
            
            # Determine internet access method
            internet_access_method = "none"
            if subnet and subnet.private_ip_google_access:
                internet_access_method = "private_google_access"
            
            deploy = {
                "deployment_order": len(selected_deployments) + 1,
                # Project info
                "project_id": self.project_id,
                "project_name": self.project_name,
                # Region info
                "region": region,
                "zone": region + "-a" if region else None,  # Default zone
                "zones_available": [f"{region}-a", f"{region}-b", f"{region}-c"] if region else [],
                # VPC info
                "vpc_id": vpc.vpc_id,
                "vpc_name": vpc.name,
                "vpc_cidr": None,  # GCP VPCs don't have single CIDR - subnets have CIDRs
                "auto_create_subnetworks": vpc.auto_create_subnetworks,
                "routing_mode": vpc.routing_mode,
                # Subnet info
                "subnet_id": subnet.subnet_id if subnet else None,
                "subnet_name": subnet.name if subnet else None,
                "subnet_cidr": subnet.ip_cidr_range if subnet else None,
                "secondary_ip_ranges": subnet.secondary_ip_ranges if subnet else [],
                # Internet connectivity
                "is_public": False,  # GCP uses external IPs, not public subnets
                "private_ip_google_access": subnet.private_ip_google_access if subnet else False,
                "has_internet": subnet.private_ip_google_access if subnet else False,
                "internet_access_method": internet_access_method,
                # Note: GCP uses Cloud NAT at router level, not subnet level
                # Connectivity info
                "peering_connections": [p.get('peering') for p in vpc_peerings],
                # Coverage info
                "covers_instances": len(best_coverage),
                "covers_vms": len(best_coverage),
                "newly_covered_ids": list(best_coverage)[:20]
            }
            
            # Add details of newly covered instances
            deploy["covered_instances_detail"] = []
            deploy["covered_vms_detail"] = []
            for inst_id in list(best_coverage)[:10]:
                inst = self.instances.get(inst_id)
                if inst:
                    detail = {
                        "instance_id": inst_id,
                        "vm_id": inst_id,
                        "name": inst.name,
                        "internal_ip": inst.private_ips[0] if inst.private_ips else "",
                        "private_ip": inst.private_ips[0] if inst.private_ips else "",
                        "external_ip": inst.public_ip or "",
                        "zone": inst.zone,
                        "vpc_name": inst.vpc_name,
                        "subnet_name": inst.subnet_name,
                        "network_tags": inst.network_tags,  # Used for firewall rules
                        "state": inst.state
                    }
                    deploy["covered_instances_detail"].append(detail)
                    deploy["covered_vms_detail"].append(detail)
            
            # Update running totals
            uncovered -= best_coverage
            selected_deployments.append(deploy)
            
            # Remove this candidate from future consideration
            del candidates[best_key]
        
        # Add cumulative coverage info
        cumulative = 0
        for deploy in selected_deployments:
            cumulative += deploy["covers_instances"]
            deploy["cumulative_covered"] = cumulative
            deploy["cumulative_percentage"] = (cumulative / len(all_instances) * 100) if all_instances else 0
        
        return selected_deployments
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        best_location = self._find_best_location()
        
        total_instances = len(self.instances)
        reachable_instances = 0
        unreachable = []
        
        if best_location:
            best_vpc = best_location['vpc_name']
            for inst_name, inst in self.instances.items():
                if inst.vpc_name == best_vpc or self.reachability_matrix.get(best_vpc, {}).get(inst.vpc_name, False):
                    reachable_instances += 1
                else:
                    unreachable.append({
                        "instance_id": inst.instance_id,
                        "name": inst.name,
                        "vpc_name": inst.vpc_name,
                        "zone": inst.zone,
                        "internal_ip": inst.private_ips[0] if inst.private_ips else "",
                        "external_ip": inst.public_ip or ""
                    })
        
        coverage_pct = (reachable_instances / total_instances * 100) if total_instances > 0 else 0
        
        if coverage_pct == 100:
            status = "SUCCESS"
            message = f"Deploy scanner in {best_location['region']} - {best_location['vpc_name']} for 100% coverage"
        elif coverage_pct > 0:
            status = "PARTIAL"
            message = f"Primary location covers {coverage_pct:.1f}% of instances. Multi-region deployment recommended."
        else:
            status = "NO_INSTANCES"
            message = "No instances found in the analyzed regions"
        
        # Connectivity summary
        peered_vpcs = set()
        for p in self.peerings:
            if p['state'] == 'ACTIVE':
                peered_vpcs.add(p['network'].split('/')[-1])
        
        isolated_vpcs = len(self.vpcs) - len(peered_vpcs)
        
        # Calculate full coverage plan
        full_coverage_deployments = self._find_full_coverage_deployments()
        full_coverage_total = sum(d.get("covers_instances", 0) for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_instances * 100) if total_instances > 0 else 0
        remaining_unreachable = total_instances - full_coverage_total
        
        # Build complete list of all instances with their IPs for HTML report
        all_instances_list = []
        
        if best_location:
            best_vpc = best_location['vpc_name']
            for inst_name, inst in self.instances.items():
                is_reachable = (inst.vpc_name == best_vpc or 
                               self.reachability_matrix.get(best_vpc, {}).get(inst.vpc_name, False))
                
                all_instances_list.append({
                    "instance_id": inst.instance_id,
                    "name": inst.name,
                    "vpc_name": inst.vpc_name,
                    "subnet_name": inst.subnet_name,
                    "region": inst.zone.rsplit('-', 1)[0] if inst.zone else "",
                    "zone": inst.zone,
                    "private_ip": inst.private_ips[0] if inst.private_ips else "",
                    "private_ips": inst.private_ips,
                    "public_ip": inst.public_ip or "",
                    "external_ip": inst.public_ip or "",
                    "network_tags": inst.network_tags,
                    "state": inst.state,
                    "reachable": is_reachable
                })
        else:
            for inst_name, inst in self.instances.items():
                all_instances_list.append({
                    "instance_id": inst.instance_id,
                    "name": inst.name,
                    "vpc_name": inst.vpc_name,
                    "subnet_name": inst.subnet_name,
                    "region": inst.zone.rsplit('-', 1)[0] if inst.zone else "",
                    "zone": inst.zone,
                    "private_ip": inst.private_ips[0] if inst.private_ips else "",
                    "private_ips": inst.private_ips,
                    "public_ip": inst.public_ip or "",
                    "external_ip": inst.public_ip or "",
                    "network_tags": inst.network_tags,
                    "state": inst.state,
                    "reachable": False
                })
        
        # Normalize deployment_location to use standard field names
        normalized_location = None
        if best_location:
            normalized_location = {
                "region": best_location.get('region', ''),
                "network_id": best_location.get('vpc_name', ''),
                "network_name": best_location.get('vpc_name', ''),
                "network_cidr": best_location.get('subnet_cidr', ''),
                "subnet_id": best_location.get('subnet_name', ''),
                "subnet_name": best_location.get('subnet_name', ''),
                "subnet_cidr": best_location.get('subnet_cidr', ''),
                "has_internet": best_location.get('has_external_ip', False),
                "instances_reachable": best_location.get('instances_reachable', 0),
                # GCP-specific fields preserved for backward compatibility
                "vpc_name": best_location.get('vpc_name', ''),
                "zone": best_location.get('zone', ''),
                "has_external_ip": best_location.get('has_external_ip', False)
            }
        
        report = {
            "cloud": "gcp",
            "project_id": self.project_id,
            "all_instances": all_instances_list,  # Complete list of all instances with IPs
            "recommendation": {
                "status": status,
                "message": message,
                "deployment_location": normalized_location,
                "coverage": {
                    "percentage": coverage_pct,
                    "total_instances": total_instances,
                    "reachable_instances": reachable_instances
                },
                "unreachable_instances": unreachable
            },
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": full_coverage_total,
                "coverage_percentage": full_coverage_pct,
                "unreachable_count": remaining_unreachable,
                "deployments": full_coverage_deployments
            },
            "summary": {
                "total_regions_scanned": len(self.regions),
                "total_networks": len(self.vpcs),
                "total_vpcs": len(self.vpcs),  # Backward compatibility
                "total_instances": total_instances,
                "total_subnets": len(self.subnets),
                "total_peerings": len(self.peerings)
            },
            "connectivity_summary": {
                "peered_networks": len(peered_vpcs),
                "isolated_networks": isolated_vpcs,
                "total_peering_connections": len(self.peerings),
                # Backward compatibility
                "peered_vpcs": len(peered_vpcs),
                "isolated_vpcs": isolated_vpcs
            },
            "generated_at": datetime.now().isoformat()
        }
        
        return report


class GCPOrgAnalyzer:
    """
    Analyzes GCP network infrastructure across multiple projects.
    """
    
    def __init__(self, credentials=None, regions: List[str] = None,
                 max_parallel: int = MAX_PARALLEL_REGIONS,
                 max_parallel_projects: int = MAX_PARALLEL_ACCOUNTS,
                 quiet: bool = False):
        check_gcp_sdk()
        
        self.credentials = credentials
        self.regions = regions
        self.max_parallel = max_parallel
        self.max_parallel_projects = max_parallel_projects
        self.quiet = quiet
        
        # Initialize resource manager client
        if credentials:
            self.projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        else:
            self.projects_client = resourcemanager_v3.ProjectsClient()
        
        self.projects: List[Dict] = []
        self.project_results: Dict[str, Any] = {}
    
    def get_projects(self) -> List[Dict]:
        """Get all accessible projects."""
        projects = []
        try:
            request = resourcemanager_v3.SearchProjectsRequest()
            for project in self.projects_client.search_projects(request=request):
                if project.state.name == "ACTIVE":
                    projects.append({
                        "project_id": project.project_id,
                        "display_name": project.display_name,
                        "state": project.state.name
                    })
        except Exception as e:
            print(f"Error listing projects: {e}", file=sys.stderr)
        return projects
    
    def discover_organization(self, quiet: bool = False, max_projects: int = None) -> Dict[str, Any]:
        """Discover all projects and analyze network infrastructure with parallel execution."""
        self.projects = self.get_projects()
        
        if max_projects:
            self.projects = self.projects[:max_projects]
        
        print(f"Found {len(self.projects)} GCP projects")
        
        # Thread-safe counters
        lock = threading.Lock()
        total_vpcs = 0
        total_instances = 0
        successful = 0
        
        def analyze_project(project: Dict) -> tuple:
            """Analyze a single project - runs in thread pool."""
            project_id = project['project_id']
            project_name = project['display_name']
            try:
                print(f"  Analyzing project: {project_name} ({project_id})")
                analyzer = GCPNetworkAnalyzer(
                    project_id=project_id,
                    credentials=self.credentials,
                    regions=self.regions,
                    max_parallel=self.max_parallel,
                    quiet=True
                )
                
                summary = analyzer.discover_all(quiet=True)
                report = analyzer.generate_report()
                
                return project_id, {
                    "name": project_name,
                    "status": "success",
                    "vpcs": summary['total_vpcs'],
                    "instances": summary['total_instances'],
                    "report": report
                }
                
            except Exception as e:
                return project_id, {
                    "name": project_name,
                    "status": "error",
                    "error": str(e)
                }
        
        # Use ThreadPoolExecutor for parallel project scanning
        num_workers = min(self.max_parallel_projects, len(self.projects))
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(analyze_project, proj): proj for proj in self.projects}
            
            for future in as_completed(futures):
                project_id, result = future.result()
                
                with lock:
                    self.project_results[project_id] = result
                    if result['status'] == 'success':
                        total_vpcs += result['vpcs']
                        total_instances += result['instances']
                        successful += 1
        
        return {
            "total_projects": len(self.projects),
            "successful_projects": successful,
            "total_vpcs": total_vpcs,
            "total_instances": total_instances
        }
    
    def generate_org_report(self) -> Dict[str, Any]:
        """Generate organization-wide report."""
        # Find best overall location
        best_location = None
        best_coverage = 0
        
        # Aggregate all instances from all projects for HTML report
        all_instances = []
        total_peerings = 0
        
        for project_id, result in self.project_results.items():
            if result['status'] == 'success':
                report = result['report']
                coverage = report['recommendation']['coverage']['reachable_instances']
                if coverage > best_coverage:
                    best_coverage = coverage
                    best_location = report['recommendation']['deployment_location']
                    if best_location:
                        best_location['project_id'] = project_id
                        best_location['project_name'] = result['name']
                
                # Aggregate instances with project info for HTML report
                for instance in report.get('all_instances', []):
                    instance_copy = instance.copy()
                    instance_copy['project_id'] = project_id
                    instance_copy['project_name'] = result['name']
                    all_instances.append(instance_copy)
                
                # Count peerings
                total_peerings += report.get('connectivity_summary', {}).get('total_peering_connections', 0)
        
        total_instances = sum(
            r['instances'] for r in self.project_results.values() 
            if r['status'] == 'success'
        )
        
        total_vpcs = sum(r['vpcs'] for r in self.project_results.values() if r['status'] == 'success')
        
        coverage_pct = (best_coverage / total_instances * 100) if total_instances > 0 else 0
        
        # Build full coverage plan with deployments (like AWS org mode)
        full_coverage_deployments = []
        deployment_order = 0
        cumulative_covered = 0
        
        # Sort projects by instance count descending for greedy coverage
        sorted_projects = sorted(
            [(project_id, result) for project_id, result in self.project_results.items() 
             if result['status'] == 'success' and result['instances'] > 0],
            key=lambda x: x[1]['instances'],
            reverse=True
        )
        
        for project_id, result in sorted_projects:
            instances = result.get('instances', 0)
            if instances == 0:
                continue
            
            deployment_order += 1
            cumulative_covered += instances
            
            report = result['report']
            rec = report.get('recommendation', {})
            deploy_loc = rec.get('deployment_location', {}) or {}
            
            # Get covered instances details
            covered_instances_detail = []
            for inst in report.get('all_instances', []):
                private_ip = inst.get("private_ip", "")
                if not private_ip and inst.get("private_ips"):
                    private_ip = inst["private_ips"][0]
                covered_instances_detail.append({
                    "instance_id": inst.get("instance_id", "N/A"),
                    "name": inst.get("name", "N/A"),
                    "private_ip": private_ip or "N/A",
                    "region": inst.get("zone", inst.get("region", "N/A")),
                    "project_id": project_id,
                    "project_name": result['name']
                })
            
            full_coverage_deployments.append({
                "deployment_order": deployment_order,
                "project_id": project_id,
                "project_name": result['name'],
                "region": deploy_loc.get("region", "N/A"),
                "zone": deploy_loc.get("zone", "N/A"),
                "vpc_id": deploy_loc.get("vpc_name", deploy_loc.get("network_id", "N/A")),
                "vpc_name": deploy_loc.get("vpc_name", deploy_loc.get("network_name", "N/A")),
                "vpc_cidr": deploy_loc.get("subnet_cidr", deploy_loc.get("network_cidr", "N/A")),
                "subnet_id": deploy_loc.get("subnet_name", deploy_loc.get("subnet_id", "N/A")),
                "subnet_name": deploy_loc.get("subnet_name", "N/A"),
                "subnet_cidr": deploy_loc.get("subnet_cidr", "N/A"),
                "is_public": deploy_loc.get("has_external_ip", deploy_loc.get("has_internet", True)),
                "has_internet": deploy_loc.get("has_external_ip", deploy_loc.get("has_internet", True)),
                "covers_instances": instances,
                "cumulative_covered": cumulative_covered,
                "cumulative_percentage": (cumulative_covered / total_instances * 100) if total_instances > 0 else 0,
                "newly_covered_ids": [inst["instance_id"] for inst in covered_instances_detail],
                "covered_instances_detail": covered_instances_detail
            })
        
        return {
            "cloud": "gcp",
            "mode": "organization",
            "all_instances": all_instances,  # For HTML report
            "org_recommendation": {
                "status": "SUCCESS" if coverage_pct == 100 else "PARTIAL",
                "message": f"Best location covers {coverage_pct:.1f}% of instances",
                "deployment_location": best_location,
                "coverage": {
                    "percentage": coverage_pct,
                    "total_instances": total_instances,
                    "reachable_instances": best_coverage
                }
            },
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": cumulative_covered,
                "coverage_percentage": (cumulative_covered / total_instances * 100) if total_instances > 0 else 0,
                "unreachable_count": total_instances - cumulative_covered,
                "deployments": full_coverage_deployments
            },
            "summary": {
                "total_projects": len(self.projects),
                "successful_projects": sum(1 for r in self.project_results.values() if r['status'] == 'success'),
                "total_vpcs": total_vpcs,
                "total_networks": total_vpcs,
                "total_instances": total_instances,
                "total_peerings": total_peerings
            },
            "connectivity_summary": {
                "peered_vpcs": sum(1 for proj in self.project_results.values() if proj['status'] == 'success' and proj['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "isolated_vpcs": total_vpcs - sum(1 for proj in self.project_results.values() if proj['status'] == 'success' and proj['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "peered_networks": sum(1 for proj in self.project_results.values() if proj['status'] == 'success' and proj['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "isolated_networks": total_vpcs - sum(1 for proj in self.project_results.values() if proj['status'] == 'success' and proj['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "total_peering_connections": total_peerings
            },
            "projects": self.project_results,
            "generated_at": datetime.now().isoformat()
        }
