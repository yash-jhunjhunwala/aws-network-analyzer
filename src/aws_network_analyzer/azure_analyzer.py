#!/usr/bin/env python3
"""
Azure Network Reachability Analyzer

Finds the optimal VNet and subnet to deploy a VM that can reach
all other VMs across VNets, regions, and subscriptions.

Requires: pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-subscription

Refactored to use shared base classes and utilities.
"""

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
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    from azure.core.exceptions import HttpResponseError, ServiceRequestError
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
    HttpResponseError = Exception
    ServiceRequestError = Exception

# Azure-specific settings (reduced parallelism to avoid throttling)
AZURE_MAX_PARALLEL = 5
MAX_RETRIES = 5
BASE_DELAY = 2.0
MAX_DELAY = 60.0


def check_azure_sdk():
    """Check if Azure SDK is installed."""
    if not AZURE_SDK_AVAILABLE:
        raise ImportError(
            "Azure SDK not installed. Install with:\n"
            "pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-subscription"
        )


def azure_retry(func, *args, max_retries=MAX_RETRIES, **kwargs):
    """
    Execute Azure API call with retry logic for throttling (429) errors.
    
    Uses exponential backoff with jitter to handle Azure API rate limits.
    """
    last_exception = None
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except HttpResponseError as e:
            last_exception = e
            # Check for throttling (429) or server errors (5xx)
            if hasattr(e, 'status_code') and e.status_code in (429, 500, 502, 503, 504):
                delay = min(BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), MAX_DELAY)
                if e.status_code == 429:
                    # Try to get Retry-After header
                    retry_after = getattr(e, 'retry_after', None)
                    if retry_after:
                        delay = max(delay, float(retry_after))
                logger.debug(f"Azure API throttled, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                continue
            raise
        except ServiceRequestError as e:
            # Network/connection errors - retry with backoff
            last_exception = e
            delay = min(BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), MAX_DELAY)
            logger.debug(f"Azure service error, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
            time.sleep(delay)
            continue
        except Exception as e:
            # Unknown error - don't retry
            raise
    
    # Exhausted retries
    if last_exception:
        raise last_exception
    return None


# Use shared ProgressIndicator with Azure alias for backwards compatibility
AzureProgressIndicator = ProgressIndicator


@dataclass
class AzureVMInfo:
    """Information about an Azure VM."""
    vm_id: str
    name: str
    resource_group: str
    location: str
    vnet_id: str
    subnet_id: str
    private_ips: List[str]
    public_ip: Optional[str]
    nsg_ids: List[str]
    state: str


@dataclass
class AzureSubnetInfo:
    """Information about an Azure subnet."""
    subnet_id: str
    name: str
    address_prefix: str
    vnet_id: str
    location: str
    nsg_id: Optional[str]
    route_table_id: Optional[str]
    has_nat_gateway: bool
    has_service_endpoints: List[str]


@dataclass 
class AzureVNetInfo:
    """Information about an Azure VNet."""
    vnet_id: str
    name: str
    resource_group: str
    location: str
    address_space: List[str]
    subnets: Dict[str, Any] = field(default_factory=dict)
    vms: Dict[str, Any] = field(default_factory=dict)
    peerings: List[str] = field(default_factory=list)


class AzureNetworkAnalyzer:
    """
    Analyzes Azure network infrastructure to find optimal deployment locations.
    
    Discovers VNets, VMs, peering connections, and Virtual WANs across regions
    to calculate reachability and recommend deployment locations.
    
    Attributes:
        cloud_provider: CloudProvider enum indicating this is Azure
        version: Current analyzer version from base module
    """
    
    cloud_provider = CloudProvider.AZURE
    version = VERSION
    
    def __init__(self, subscription_id: str, credentials=None, regions: List[str] = None,
                 max_parallel: int = AZURE_MAX_PARALLEL, quiet: bool = False):
        """
        Initialize the Azure analyzer.
        
        Args:
            subscription_id: Azure subscription ID
            credentials: Azure credential object (DefaultAzureCredential or ClientSecretCredential)
            regions: List of Azure regions to analyze (if None, discovers all)
            max_parallel: Maximum parallel region scans
            quiet: Suppress progress output
        """
        check_azure_sdk()
        
        self.credentials = credentials
        if not self.credentials:
            self.credentials = DefaultAzureCredential()
        
        self.subscription_id = subscription_id
        self.subscription_name = subscription_id  # Default to ID, will try to get name
        self.regions = regions or []
        self.max_parallel = max_parallel
        self.quiet = quiet
        
        # Initialize clients
        self.subscription_client = SubscriptionClient(self.credentials)
        self.compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
        
        # Try to get subscription display name
        try:
            sub = self.subscription_client.subscriptions.get(self.subscription_id)
            if sub and sub.display_name:
                self.subscription_name = sub.display_name
        except Exception:
            pass  # Keep using subscription_id as name
        
        logger.debug(f"Initialized AzureNetworkAnalyzer v{VERSION} for subscription {subscription_id}")
        
        # Thread-safe data stores
        self._lock = threading.Lock()
        self.vnets: Dict[str, AzureVNetInfo] = {}
        self.vms: Dict[str, AzureVMInfo] = {}
        self.subnets: Dict[str, AzureSubnetInfo] = {}
        self.peerings: List[Dict] = []
        self.virtual_wans: List[Dict] = []
        
        # Results
        self.reachability_matrix: Dict[str, Dict[str, bool]] = {}
        self.discovery_data: Dict[str, Any] = {}
    
    def get_regions(self) -> List[str]:
        """Get list of Azure regions to scan."""
        if self.regions:
            return self.regions
        
        # Return all available regions (consistent with AWS/GCP behavior)
        return self.get_all_regions()
    
    def get_all_regions(self) -> List[str]:
        """Get ALL available Azure regions from the subscription."""
        locations = self.subscription_client.subscriptions.list_locations(self.subscription_id)
        return [loc.name for loc in locations if loc.name]
    
    def discover_all(self, progress_callback=None, quiet: bool = False) -> Dict[str, Any]:
        """
        Discover all network resources across configured regions.
        
        Returns:
            Dictionary with discovery summary
        """
        if not self.regions:
            self.regions = self.get_regions()
        
        print(f"Discovering Azure resources (filtering to {len(self.regions)} regions)...")
        
        # Fetch ALL resources ONCE (not per-region to avoid throttling)
        print("  Fetching VNets...", end=" ", flush=True)
        try:
            all_vnets = list(azure_retry(lambda: list(self.network_client.virtual_networks.list_all())))
            print(f"found {len(all_vnets)}")
        except Exception as e:
            print(f"error: {e}")
            all_vnets = []
        
        print("  Fetching VMs...", end=" ", flush=True)
        try:
            all_vms = list(azure_retry(lambda: list(self.compute_client.virtual_machines.list_all())))
            print(f"found {len(all_vms)}")
        except Exception as e:
            print(f"error: {e}")
            all_vms = []
        
        # Filter to configured regions
        region_set = set(self.regions)
        vnets_in_regions = [v for v in all_vnets if v.location in region_set]
        vms_in_regions = [v for v in all_vms if v.location in region_set]
        
        print(f"  Resources in target regions: {len(vnets_in_regions)} VNets, {len(vms_in_regions)} VMs")
        
        # Process VNets
        print("  Processing VNets...", end=" ", flush=True)
        for vnet in vnets_in_regions:
            vnet_info = AzureVNetInfo(
                vnet_id=vnet.id,
                name=vnet.name,
                resource_group=vnet.id.split('/')[4],
                location=vnet.location,
                address_space=vnet.address_space.address_prefixes if vnet.address_space else [],
                subnets={},
                vms={},
                peerings=[p.id for p in (vnet.virtual_network_peerings or [])]
            )
            
            # Get subnets
            if vnet.subnets:
                for subnet in vnet.subnets:
                    subnet_info = AzureSubnetInfo(
                        subnet_id=subnet.id,
                        name=subnet.name,
                        address_prefix=subnet.address_prefix or (subnet.address_prefixes[0] if subnet.address_prefixes else ""),
                        vnet_id=vnet.id,
                        location=vnet.location,
                        nsg_id=subnet.network_security_group.id if subnet.network_security_group else None,
                        route_table_id=subnet.route_table.id if subnet.route_table else None,
                        has_nat_gateway=subnet.nat_gateway is not None,
                        has_service_endpoints=[se.service for se in (subnet.service_endpoints or [])]
                    )
                    vnet_info.subnets[subnet.id] = asdict(subnet_info)
                    self.subnets[subnet.id] = subnet_info
            
            self.vnets[vnet.id] = vnet_info
        print("done")
        
        # Process VMs (with progress since NIC lookups are slow)
        if vms_in_regions:
            print(f"  Processing {len(vms_in_regions)} VMs...")
            progress = AzureProgressIndicator(len(vms_in_regions), "Processing VMs", quiet or self.quiet)
            
            for vm in vms_in_regions:
                self._process_vm(vm)
                progress.update(vm.name, "done")
            
            progress.finish()
        else:
            print("  No VMs found in target regions")
        
        # Discover VNet peerings and Virtual WANs
        print("  Discovering peerings...", end=" ", flush=True)
        self._discover_peerings()
        print(f"found {len(self.peerings)}")
        
        print("  Discovering Virtual WANs...", end=" ", flush=True)
        self._discover_virtual_wans()
        print(f"found {len(self.virtual_wans)}")
        
        # Analyze connectivity
        self._analyze_connectivity()
        
        # Validate discovered data
        self._validate_and_log_data()
        
        return {
            "total_vnets": len(self.vnets),
            "total_vms": len(self.vms),
            "total_peerings": len(self.peerings),
            "total_virtual_wans": len(self.virtual_wans),
            "regions_scanned": len(self.regions)
        }
    
    def _validate_and_log_data(self) -> None:
        """Validate discovered data and log any issues."""
        # Count VMs from vnets
        vms_from_vnets = 0
        for vnet in self.vnets.values():
            vms_from_vnets += len(vnet.vms)
        
        vms_from_self = len(self.vms)
        vnets_from_self = len(self.vnets)
        
        logger.debug(f"Azure Validation: self.vms={vms_from_self}, vnets.vms={vms_from_vnets}")
        
        if vms_from_self != vms_from_vnets:
            logger.warning(
                f"Azure data inconsistency: self.vms has {vms_from_self} entries, "
                f"but vnets have {vms_from_vnets} VMs"
            )
        
        # Verify all VMs have valid VNet references
        orphan_vms = 0
        for vm_id, vm in self.vms.items():
            if vm.vnet_id not in self.vnets:
                orphan_vms += 1
                logger.debug(f"VM {vm_id} references unknown VNet {vm.vnet_id}")
        
        if orphan_vms > 0:
            logger.warning(f"Azure: {orphan_vms} VMs reference unknown VNets")
        
        logger.info(f"Azure discovery complete: {vnets_from_self} VNets, {vms_from_self} VMs, "
                   f"{len(self.peerings)} peerings, {len(self.virtual_wans)} vWANs")
    
    def _process_vm(self, vm) -> None:
        """Process a single VM and extract network information."""
        # Get network interfaces
        private_ips = []
        public_ip = None
        nsg_ids = []
        vnet_id = None
        subnet_id = None
        
        if vm.network_profile and vm.network_profile.network_interfaces:
            for nic_ref in vm.network_profile.network_interfaces:
                try:
                    nic_rg = nic_ref.id.split('/')[4]
                    nic_name = nic_ref.id.split('/')[-1]
                    nic = azure_retry(lambda rg=nic_rg, n=nic_name: self.network_client.network_interfaces.get(rg, n))
                    
                    if nic.network_security_group:
                        nsg_ids.append(nic.network_security_group.id)
                    
                    for ip_config in (nic.ip_configurations or []):
                        if ip_config.private_ip_address:
                            private_ips.append(ip_config.private_ip_address)
                        if ip_config.subnet:
                            subnet_id = ip_config.subnet.id
                            vnet_id = '/'.join(subnet_id.split('/')[:-2])
                        if ip_config.public_ip_address:
                            try:
                                pip_rg = ip_config.public_ip_address.id.split('/')[4]
                                pip_name = ip_config.public_ip_address.id.split('/')[-1]
                                pip = azure_retry(lambda rg=pip_rg, n=pip_name: self.network_client.public_ip_addresses.get(rg, n))
                                public_ip = pip.ip_address
                            except:
                                pass
                except Exception:
                    continue
        
        if not vnet_id:
            return
        
        vm_info = AzureVMInfo(
            vm_id=vm.id,
            name=vm.name,
            resource_group=vm.id.split('/')[4],
            location=vm.location,
            vnet_id=vnet_id,
            subnet_id=subnet_id or "",
            private_ips=private_ips,
            public_ip=public_ip,
            nsg_ids=nsg_ids,
            state=vm.provisioning_state or "Unknown"
        )
        
        self.vms[vm.id] = vm_info
        if vnet_id in self.vnets:
            self.vnets[vnet_id].vms[vm.id] = asdict(vm_info)
    
    def _discover_peerings(self) -> None:
        """Discover all VNet peerings."""
        for vnet_id, vnet in self.vnets.items():
            try:
                rg = vnet.resource_group
                vnet_name = vnet.name
                peerings = azure_retry(lambda r=rg, v=vnet_name: list(self.network_client.virtual_network_peerings.list(r, v)))
                
                for peering in peerings:
                    peering_info = {
                        "peering_id": peering.id,
                        "name": peering.name,
                        "local_vnet_id": vnet_id,
                        "remote_vnet_id": peering.remote_virtual_network.id if peering.remote_virtual_network else None,
                        "peering_state": peering.peering_state,
                        "allow_forwarded_traffic": peering.allow_forwarded_traffic,
                        "allow_gateway_transit": peering.allow_gateway_transit,
                        "use_remote_gateways": peering.use_remote_gateways
                    }
                    
                    with self._lock:
                        # Avoid duplicates
                        if not any(p['peering_id'] == peering_info['peering_id'] for p in self.peerings):
                            self.peerings.append(peering_info)
            except Exception:
                continue
    
    def _discover_virtual_wans(self) -> None:
        """Discover Virtual WANs and Hubs."""
        try:
            vwans = azure_retry(lambda: list(self.network_client.virtual_wans.list()))
            for vwan in vwans:
                vwan_info = {
                    "vwan_id": vwan.id,
                    "name": vwan.name,
                    "location": vwan.location,
                    "type": vwan.type,
                    "virtual_hubs": []
                }
                
                # Get connected hubs
                if vwan.virtual_hubs:
                    for hub_ref in vwan.virtual_hubs:
                        vwan_info["virtual_hubs"].append(hub_ref.id)
                
                with self._lock:
                    self.virtual_wans.append(vwan_info)
        except Exception:
            pass
    
    def _analyze_connectivity(self) -> None:
        """Analyze VNet-to-VNet connectivity via peerings and Virtual WAN."""
        # Build connectivity matrix
        for vnet_id in self.vnets:
            self.reachability_matrix[vnet_id] = {}
            
            for other_vnet_id in self.vnets:
                if vnet_id == other_vnet_id:
                    self.reachability_matrix[vnet_id][other_vnet_id] = True
                    continue
                
                # Check direct peering
                is_peered = any(
                    p['local_vnet_id'] == vnet_id and p['remote_vnet_id'] == other_vnet_id and p['peering_state'] == 'Connected'
                    for p in self.peerings
                )
                
                # Check reverse peering
                if not is_peered:
                    is_peered = any(
                        p['local_vnet_id'] == other_vnet_id and p['remote_vnet_id'] == vnet_id and p['peering_state'] == 'Connected'
                        for p in self.peerings
                    )
                
                self.reachability_matrix[vnet_id][other_vnet_id] = is_peered
    
    def _find_best_location(self) -> Optional[Dict]:
        """Find the VNet/subnet with maximum reachability."""
        if not self.vnets:
            return None
        
        best_vnet = None
        best_coverage = 0
        best_subnet = None
        
        for vnet_id, vnet in self.vnets.items():
            # Count reachable VMs from this VNet
            reachable = 0
            for vm in self.vms.values():
                if vm.vnet_id == vnet_id or self.reachability_matrix.get(vnet_id, {}).get(vm.vnet_id, False):
                    reachable += 1
            
            if reachable > best_coverage:
                best_coverage = reachable
                best_vnet = vnet
                
                # Find best subnet (prefer one with NAT gateway or internet access)
                for subnet_id, subnet_data in vnet.subnets.items():
                    subnet = self.subnets.get(subnet_id)
                    if subnet and subnet.has_nat_gateway:
                        best_subnet = subnet
                        break
                
                if not best_subnet and vnet.subnets:
                    first_subnet_id = list(vnet.subnets.keys())[0]
                    best_subnet = self.subnets.get(first_subnet_id)
        
        if not best_vnet:
            return None
        
        return {
            "location": best_vnet.location,
            "vnet_id": best_vnet.vnet_id,
            "vnet_name": best_vnet.name,
            "vnet_address_space": best_vnet.address_space,
            "subnet_id": best_subnet.subnet_id if best_subnet else None,
            "subnet_name": best_subnet.name if best_subnet else None,
            "subnet_cidr": best_subnet.address_prefix if best_subnet else None,
            "has_nat_gateway": best_subnet.has_nat_gateway if best_subnet else False,
            "vms_reachable": best_coverage
        }
    
    def _find_full_coverage_deployments(self) -> List[Dict]:
        """
        Find the MINIMUM set of deployment locations needed to cover ALL VMs.
        Uses a greedy set cover algorithm.
        
        Returns:
            List of deployment locations, each covering a subset of VMs.
            Together they cover all reachable VMs.
        """
        if not self.vms:
            return []
        
        # Build a mapping of each VNet to the set of VMs it can reach
        candidates = {}  # vnet_id -> {"vnet": vnet, "subnet": subnet, "vms": set()}
        
        for vnet_id, vnet in self.vnets.items():
            # Find all VMs reachable from this VNet
            reachable_vm_ids = set()
            
            for vm_id, vm in self.vms.items():
                # VM is reachable if it's in the same VNet or in a peered VNet
                if vm.vnet_id == vnet_id or self.reachability_matrix.get(vnet_id, {}).get(vm.vnet_id, False):
                    reachable_vm_ids.add(vm_id)
            
            if reachable_vm_ids:
                # Find best subnet
                best_subnet = None
                for subnet_id in vnet.subnets:
                    subnet = self.subnets.get(subnet_id)
                    if subnet:
                        if subnet.has_nat_gateway:
                            best_subnet = subnet
                            break
                        if not best_subnet:
                            best_subnet = subnet
                
                candidates[vnet_id] = {
                    "vnet": vnet,
                    "subnet": best_subnet,
                    "vms": reachable_vm_ids
                }
        
        if not candidates:
            return []
        
        # Greedy set cover algorithm
        all_vms = set(self.vms.keys())
        uncovered = all_vms.copy()
        selected_deployments = []
        
        while uncovered:
            # Find the candidate that covers the most uncovered VMs
            best_candidate = None
            best_coverage = set()
            best_key = None
            
            for key, data in candidates.items():
                newly_covered = data["vms"] & uncovered
                if len(newly_covered) > len(best_coverage):
                    best_coverage = newly_covered
                    best_candidate = data
                    best_key = key
            
            if not best_candidate or not best_coverage:
                break
            
            vnet = best_candidate["vnet"]
            subnet = best_candidate["subnet"]
            
            # Get VNet peerings
            vnet_peerings = [p for p in self.peerings if p.get('local_vnet_id') == vnet.vnet_id]
            
            deploy = {
                "deployment_order": len(selected_deployments) + 1,
                # Subscription info
                "subscription_id": self.subscription_id,
                "subscription_name": self.subscription_name,
                # Resource Group
                "resource_group": vnet.resource_group,
                # Region info
                "region": vnet.location,
                "location": vnet.location,
                # VNet info  
                "vpc_id": vnet.vnet_id,
                "vnet_id": vnet.vnet_id,
                "vnet_name": vnet.name,
                "vpc_cidr": vnet.address_space[0] if vnet.address_space else None,
                "vnet_cidr": vnet.address_space[0] if vnet.address_space else None,
                "vnet_address_space": vnet.address_space,
                # Subnet info
                "subnet_id": subnet.subnet_id if subnet else None,
                "subnet_name": subnet.name if subnet else None,
                "subnet_cidr": subnet.address_prefix if subnet else None,
                # Network Security Group
                "nsg_id": subnet.nsg_id if subnet else None,
                # Route Table
                "route_table_id": subnet.route_table_id if subnet else None,
                # Internet connectivity - check NAT gateway OR if any VMs have public IPs
                "is_public": False,  # Azure subnets are not "public" like AWS
                "has_nat_gateway": subnet.has_nat_gateway if subnet else False,
                "has_public_ip_vms": any(vm.public_ip for vm in vnet.vms.values() if isinstance(vm, dict) and vm.get('public_ip')) if vnet.vms else False,
                "has_internet": (subnet.has_nat_gateway if subnet else False) or any(vm.public_ip for vm_id in best_coverage if (vm := self.vms.get(vm_id)) and vm.public_ip),
                "internet_access_method": "nat" if (subnet and subnet.has_nat_gateway) else ("public_ip" if any(vm.public_ip for vm_id in best_coverage if (vm := self.vms.get(vm_id)) and vm.public_ip) else "none"),
                "service_endpoints": subnet.has_service_endpoints if subnet else [],
                # Connectivity info
                "peering_connections": [p.get('remote_vnet_id') for p in vnet_peerings],
                # Coverage info
                "covers_instances": len(best_coverage),
                "covers_vms": len(best_coverage),
                "newly_covered_ids": list(best_coverage)[:20]
            }
            
            # Add details of newly covered VMs
            deploy["covered_vms_detail"] = []
            deploy["covered_instances_detail"] = []
            for vm_id in list(best_coverage)[:10]:
                vm = self.vms.get(vm_id)
                if vm:
                    detail = {
                        "vm_id": vm_id,
                        "instance_id": vm_id,
                        "name": vm.name,
                        "resource_group": vm.resource_group,
                        "private_ip": vm.private_ips[0] if vm.private_ips else "",
                        "public_ip": vm.public_ip or "",
                        "location": vm.location,
                        "vnet_id": vm.vnet_id,
                        "subnet_id": vm.subnet_id,
                        "nsg_ids": vm.nsg_ids,
                        "state": vm.state
                    }
                    deploy["covered_vms_detail"].append(detail)
                    deploy["covered_instances_detail"].append(detail)
            
            # Update running totals
            uncovered -= best_coverage
            selected_deployments.append(deploy)
            
            # Remove this candidate from future consideration
            del candidates[best_key]
        
        # Add cumulative coverage info
        cumulative = 0
        for deploy in selected_deployments:
            cumulative += deploy["covers_vms"]
            deploy["cumulative_covered"] = cumulative
            deploy["cumulative_percentage"] = (cumulative / len(all_vms) * 100) if all_vms else 0
        
        return selected_deployments
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        best_location = self._find_best_location()
        
        total_vms = len(self.vms)
        reachable_vms = 0
        unreachable = []
        
        if best_location:
            best_vnet = best_location['vnet_id']
            for vm_id, vm in self.vms.items():
                if vm.vnet_id == best_vnet or self.reachability_matrix.get(best_vnet, {}).get(vm.vnet_id, False):
                    reachable_vms += 1
                else:
                    unreachable.append({
                        "vm_id": vm_id,
                        "name": vm.name,
                        "vnet_id": vm.vnet_id,
                        "location": vm.location,
                        "private_ip": vm.private_ips[0] if vm.private_ips else "",
                        "public_ip": vm.public_ip or ""
                    })
        
        coverage_pct = (reachable_vms / total_vms * 100) if total_vms > 0 else 0
        
        if coverage_pct == 100:
            status = "SUCCESS"
            message = f"Deploy scanner in {best_location['location']} - {best_location['vnet_name']} for 100% coverage"
        elif coverage_pct > 0:
            status = "PARTIAL"
            message = f"Primary location covers {coverage_pct:.1f}% of VMs. Multi-region deployment recommended."
        else:
            status = "NO_VMS"
            message = "No VMs found in the analyzed regions"
        
        # Connectivity summary
        peered_vnets = set()
        for p in self.peerings:
            if p['peering_state'] == 'Connected':
                peered_vnets.add(p['local_vnet_id'])
                peered_vnets.add(p['remote_vnet_id'])
        
        isolated_vnets = len(self.vnets) - len(peered_vnets)
        
        # Calculate full coverage plan
        full_coverage_deployments = self._find_full_coverage_deployments()
        full_coverage_total = sum(d.get("covers_vms", 0) for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_vms * 100) if total_vms > 0 else 0
        remaining_unreachable = total_vms - full_coverage_total
        
        # Build complete list of all VMs with their IPs for HTML report
        all_vms_list = []
        reachable_vm_ids = set()
        
        if best_location:
            best_vnet = best_location['vnet_id']
            for vm_id, vm in self.vms.items():
                is_reachable = (vm.vnet_id == best_vnet or 
                               self.reachability_matrix.get(best_vnet, {}).get(vm.vnet_id, False))
                if is_reachable:
                    reachable_vm_ids.add(vm_id)
                
                all_vms_list.append({
                    "vm_id": vm_id,
                    "name": vm.name,
                    "vnet_id": vm.vnet_id,
                    "vnet_name": vm.vnet_id.split("/")[-1] if "/" in vm.vnet_id else vm.vnet_id,
                    "subnet_id": vm.subnet_id,
                    "location": vm.location,
                    "resource_group": vm.resource_group,
                    "private_ip": vm.private_ips[0] if vm.private_ips else "",
                    "private_ips": vm.private_ips,
                    "public_ip": vm.public_ip or "",
                    "nsg_ids": vm.nsg_ids,
                    "state": vm.state,
                    "reachable": is_reachable
                })
        else:
            for vm_id, vm in self.vms.items():
                all_vms_list.append({
                    "vm_id": vm_id,
                    "name": vm.name,
                    "vnet_id": vm.vnet_id,
                    "vnet_name": vm.vnet_id.split("/")[-1] if "/" in vm.vnet_id else vm.vnet_id,
                    "subnet_id": vm.subnet_id,
                    "location": vm.location,
                    "resource_group": vm.resource_group,
                    "private_ip": vm.private_ips[0] if vm.private_ips else "",
                    "private_ips": vm.private_ips,
                    "public_ip": vm.public_ip or "",
                    "nsg_ids": vm.nsg_ids,
                    "state": vm.state,
                    "reachable": False
                })
        
        # Normalize deployment_location to use standard field names
        normalized_location = None
        if best_location:
            # Check if any VMs in this location have public IPs
            has_public_ip_vms = best_location.get('has_public_ip_vms', False)
            has_nat = best_location.get('has_nat_gateway', False)
            has_internet = has_nat or has_public_ip_vms or best_location.get('has_internet', False)
            internet_method = "nat" if has_nat else ("public_ip" if has_public_ip_vms else "none")
            
            normalized_location = {
                "region": best_location.get('location', ''),
                "network_id": best_location.get('vnet_id', ''),
                "network_name": best_location.get('vnet_name', ''),
                "network_cidr": best_location.get('vnet_address_space', [''])[0] if best_location.get('vnet_address_space') else '',
                "subnet_id": best_location.get('subnet_id'),
                "subnet_name": best_location.get('subnet_name'),
                "subnet_cidr": best_location.get('subnet_cidr'),
                "has_internet": has_internet,
                "internet_access_method": internet_method,
                "instances_reachable": best_location.get('vms_reachable', 0),
                # Azure-specific fields preserved for backward compatibility
                "location": best_location.get('location', ''),
                "vnet_id": best_location.get('vnet_id', ''),
                "vnet_name": best_location.get('vnet_name', ''),
                "vnet_address_space": best_location.get('vnet_address_space', []),
                "has_nat_gateway": best_location.get('has_nat_gateway', False),
                "has_public_ip_vms": has_public_ip_vms,
                "vms_reachable": best_location.get('vms_reachable', 0)
            }
        
        report = {
            "cloud": "azure",
            "subscription_id": self.subscription_id,
            "all_instances": all_vms_list,  # Standardized field name
            "all_vms": all_vms_list,  # Backward compatibility alias
            "recommendation": {
                "status": status,
                "message": message,
                "deployment_location": normalized_location,
                "coverage": {
                    "percentage": coverage_pct,
                    "total_instances": total_vms,
                    "reachable_instances": reachable_vms,
                    # Backward compatibility
                    "total_vms": total_vms,
                    "reachable_vms": reachable_vms
                },
                "unreachable_instances": unreachable,
                "unreachable_vms": unreachable  # Backward compatibility
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
                "total_networks": len(self.vnets),
                "total_vnets": len(self.vnets),  # Backward compatibility
                "total_instances": total_vms,
                "total_vms": total_vms,  # Backward compatibility
                "total_peerings": len(self.peerings),
                "total_virtual_wans": len(self.virtual_wans)
            },
            "connectivity_summary": {
                "peered_networks": len(peered_vnets),
                "isolated_networks": isolated_vnets,
                "total_peering_connections": len(self.peerings),
                # Backward compatibility
                "peered_vnets": len(peered_vnets),
                "isolated_vnets": isolated_vnets
            },
            "generated_at": datetime.now().isoformat()
        }
        
        return report


class AzureOrgAnalyzer:
    """
    Analyzes Azure network infrastructure across multiple subscriptions.
    """
    
    def __init__(self, credentials=None, regions: List[str] = None,
                 max_parallel: int = MAX_PARALLEL_REGIONS,
                 max_parallel_subscriptions: int = MAX_PARALLEL_ACCOUNTS,
                 quiet: bool = False):
        check_azure_sdk()
        
        self.credentials = credentials
        if not self.credentials:
            self.credentials = DefaultAzureCredential()
        
        self.regions = regions
        self.max_parallel = max_parallel
        self.max_parallel_subscriptions = max_parallel_subscriptions
        self.quiet = quiet
        
        self.subscription_client = SubscriptionClient(self.credentials)
        self.subscriptions: List[Dict] = []
        self.subscription_results: Dict[str, Any] = {}
    
    def get_subscriptions(self) -> List[Dict]:
        """Get all accessible subscriptions."""
        subs = []
        for sub in self.subscription_client.subscriptions.list():
            if sub.state == "Enabled":
                subs.append({
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name,
                    "state": sub.state
                })
        return subs
    
    def discover_organization(self, quiet: bool = False, max_subscriptions: int = None) -> Dict[str, Any]:
        """Discover all subscriptions and analyze network infrastructure with parallel execution."""
        self.subscriptions = self.get_subscriptions()
        
        if max_subscriptions:
            self.subscriptions = self.subscriptions[:max_subscriptions]
        
        print(f"Found {len(self.subscriptions)} Azure subscriptions")
        
        # Thread-safe counters
        lock = threading.Lock()
        total_vnets = 0
        total_vms = 0
        successful = 0
        
        def analyze_subscription(sub: Dict) -> tuple:
            """Analyze a single subscription - runs in thread pool."""
            sub_id = sub['subscription_id']
            sub_name = sub['display_name']
            try:
                print(f"  Analyzing subscription: {sub_name} ({sub_id})")
                analyzer = AzureNetworkAnalyzer(
                    subscription_id=sub_id,
                    credentials=self.credentials,
                    regions=self.regions,
                    max_parallel=self.max_parallel,
                    quiet=True
                )
                
                summary = analyzer.discover_all(quiet=True)
                report = analyzer.generate_report()
                
                return sub_id, {
                    "name": sub_name,
                    "status": "success",
                    "vnets": summary['total_vnets'],
                    "vms": summary['total_vms'],
                    "report": report
                }
                
            except Exception as e:
                return sub_id, {
                    "name": sub_name,
                    "status": "error",
                    "error": str(e)
                }
        
        # Use ThreadPoolExecutor for parallel subscription scanning
        num_workers = min(self.max_parallel_subscriptions, len(self.subscriptions))
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(analyze_subscription, sub): sub for sub in self.subscriptions}
            
            for future in as_completed(futures):
                sub_id, result = future.result()
                
                with lock:
                    self.subscription_results[sub_id] = result
                    if result['status'] == 'success':
                        total_vnets += result['vnets']
                        total_vms += result['vms']
                        successful += 1
        
        return {
            "total_subscriptions": len(self.subscriptions),
            "successful_subscriptions": successful,
            "total_vnets": total_vnets,
            "total_vms": total_vms
        }
    
    def generate_org_report(self) -> Dict[str, Any]:
        """Generate organization-wide report."""
        # Find best overall location
        best_location = None
        best_coverage = 0
        
        # Aggregate all VMs from all subscriptions for the HTML report
        all_vms = []
        total_peerings = 0
        
        for sub_id, result in self.subscription_results.items():
            if result['status'] == 'success':
                report = result['report']
                coverage = report['recommendation']['coverage']['reachable_vms']
                if coverage > best_coverage:
                    best_coverage = coverage
                    best_location = report['recommendation']['deployment_location']
                    best_location['subscription_id'] = sub_id
                    best_location['subscription_name'] = result['name']
                
                # Aggregate VMs from this subscription
                sub_vms = report.get('all_vms', [])
                for vm in sub_vms:
                    vm['subscription_id'] = sub_id
                    vm['subscription_name'] = result['name']
                    all_vms.append(vm)
                
                # Count peerings
                total_peerings += report.get('connectivity_summary', {}).get('total_peering_connections', 0)
        
        total_vms = sum(
            r['vms'] for r in self.subscription_results.values() 
            if r['status'] == 'success'
        )
        
        total_vnets = sum(r['vnets'] for r in self.subscription_results.values() if r['status'] == 'success')
        
        coverage_pct = (best_coverage / total_vms * 100) if total_vms > 0 else 0
        
        # Build full coverage plan with deployments (like AWS org mode)
        full_coverage_deployments = []
        deployment_order = 0
        cumulative_covered = 0
        
        # Sort subscriptions by VM count descending for greedy coverage
        sorted_subs = sorted(
            [(sub_id, result) for sub_id, result in self.subscription_results.items() 
             if result['status'] == 'success' and result['vms'] > 0],
            key=lambda x: x[1]['vms'],
            reverse=True
        )
        
        for sub_id, result in sorted_subs:
            vms = result.get('vms', 0)
            if vms == 0:
                continue
            
            deployment_order += 1
            cumulative_covered += vms
            
            report = result['report']
            rec = report.get('recommendation', {})
            deploy_loc = rec.get('deployment_location', {}) or {}
            
            # Get covered VMs details
            covered_vms_detail = []
            for vm in report.get('all_vms', []):
                covered_vms_detail.append({
                    "instance_id": vm.get("vm_id", "N/A"),
                    "name": vm.get("name", "N/A"),
                    "private_ip": vm.get("private_ip", "N/A"),
                    "region": vm.get("location", "N/A"),
                    "subscription_id": sub_id,
                    "subscription_name": result['name']
                })
            
            full_coverage_deployments.append({
                "deployment_order": deployment_order,
                "subscription_id": sub_id,
                "subscription_name": result['name'],
                "location": deploy_loc.get("location", deploy_loc.get("region", "N/A")),
                "region": deploy_loc.get("location", deploy_loc.get("region", "N/A")),
                "vnet_id": deploy_loc.get("vnet_id", deploy_loc.get("network_id", "N/A")),
                "vnet_name": deploy_loc.get("vnet_name", deploy_loc.get("network_name", "N/A")),
                "vnet_cidr": deploy_loc.get("vnet_address_space", [deploy_loc.get("network_cidr", "")])[0] if deploy_loc.get("vnet_address_space") else deploy_loc.get("network_cidr", "N/A"),
                "subnet_id": deploy_loc.get("subnet_id", "N/A"),
                "subnet_name": deploy_loc.get("subnet_name", "N/A"),
                "subnet_cidr": deploy_loc.get("subnet_cidr", "N/A"),
                "is_public": True,
                "has_internet": deploy_loc.get("has_nat_gateway", deploy_loc.get("has_internet", True)),
                "covers_instances": vms,
                "covers_vms": vms,
                "cumulative_covered": cumulative_covered,
                "cumulative_percentage": (cumulative_covered / total_vms * 100) if total_vms > 0 else 0,
                "newly_covered_ids": [vm["instance_id"] for vm in covered_vms_detail],
                "covered_instances_detail": covered_vms_detail,
                "covered_vms_detail": covered_vms_detail
            })
        
        return {
            "cloud": "azure",
            "mode": "organization",
            "all_vms": all_vms,  # Include all VMs for HTML report
            "all_instances": all_vms,  # Standardized field name
            "org_recommendation": {
                "status": "SUCCESS" if coverage_pct == 100 else "PARTIAL",
                "message": f"Best location covers {coverage_pct:.1f}% of VMs",
                "deployment_location": best_location,
                "coverage": {
                    "percentage": coverage_pct,
                    "total_vms": total_vms,
                    "reachable_vms": best_coverage,
                    "total_instances": total_vms,
                    "reachable_instances": best_coverage
                }
            },
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": cumulative_covered,
                "total_vms_covered": cumulative_covered,
                "coverage_percentage": (cumulative_covered / total_vms * 100) if total_vms > 0 else 0,
                "unreachable_count": total_vms - cumulative_covered,
                "deployments": full_coverage_deployments
            },
            "summary": {
                "total_subscriptions": len(self.subscriptions),
                "successful_subscriptions": sum(1 for r in self.subscription_results.values() if r['status'] == 'success'),
                "total_vnets": total_vnets,
                "total_networks": total_vnets,
                "total_vms": total_vms,
                "total_instances": total_vms,
                "total_peerings": total_peerings
            },
            "connectivity_summary": {
                "peered_vnets": sum(1 for sub in self.subscription_results.values() if sub['status'] == 'success' and sub['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "isolated_vnets": total_vnets - sum(1 for sub in self.subscription_results.values() if sub['status'] == 'success' and sub['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "peered_networks": sum(1 for sub in self.subscription_results.values() if sub['status'] == 'success' and sub['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "isolated_networks": total_vnets - sum(1 for sub in self.subscription_results.values() if sub['status'] == 'success' and sub['report'].get('connectivity_summary', {}).get('total_peering_connections', 0) > 0),
                "total_peering_connections": total_peerings
            },
            "subscriptions": self.subscription_results,
            "generated_at": datetime.now().isoformat()
        }
