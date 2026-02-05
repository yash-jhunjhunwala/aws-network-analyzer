"""
AWS Network Analyzer Core Module

This module contains the AWSNetworkAnalyzer class for discovering and analyzing
AWS network infrastructure to find optimal deployment locations.

Refactored to use shared base classes and utilities.
"""

import boto3
import threading
from collections import defaultdict
from dataclasses import asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

# Import shared modules
from .base import (
    VERSION, MAX_PARALLEL_REGIONS, CloudProvider,
    SubnetInfo, InstanceInfo, NetworkInfo, PeeringInfo
)
from .utils import (
    retry_with_backoff, ProgressIndicator, extract_name_from_tags, logger
)


class AWSNetworkAnalyzer:
    """
    Analyzes AWS network infrastructure to find optimal deployment locations.
    
    This class discovers VPCs, instances, peering connections, and transit gateways
    across multiple regions and calculates reachability to recommend the best
    location for deploying scanner VMs.
    
    Attributes:
        cloud_provider: CloudProvider enum indicating this is AWS
        version: Current analyzer version from base module
    
    Example:
        >>> session = boto3.Session(profile_name="my-profile")
        >>> analyzer = AWSNetworkAnalyzer(session, ["us-east-1", "us-west-2"])
        >>> analyzer.discover_all()
        >>> report = analyzer.generate_report()
    """
    
    cloud_provider = CloudProvider.AWS
    version = VERSION
    
    def __init__(self, session: boto3.Session, regions: List[str], 
                 max_workers: int = MAX_PARALLEL_REGIONS, quiet: bool = False):
        """
        Initialize the analyzer.
        
        Args:
            session: Boto3 session with credentials
            regions: List of AWS region codes to analyze
            max_workers: Maximum parallel region scans (default 10)
            quiet: Suppress progress output
        """
        self.session = session
        self.regions = regions
        self.max_workers = max_workers
        self.quiet = quiet
        
        # Thread-safe data stores
        self._lock = threading.Lock()
        self.vpcs: Dict[str, Dict] = {}  # vpc_id -> vpc_info
        self.instances: Dict[str, InstanceInfo] = {}  # instance_id -> info
        self.subnets: Dict[str, SubnetInfo] = {}  # subnet_id -> info
        self.peering_connections: List[Dict] = []
        self.transit_gateways: List[Dict] = []
        self.tgw_attachments: List[Dict] = []
        
        # Results
        self.reachability_matrix: Dict[str, Dict[str, bool]] = {}
        self.discovery_data: Dict[str, Any] = {}
        
        logger.debug(f"Initialized AWSNetworkAnalyzer v{VERSION} for {len(regions)} regions")
    
    def discover_all(self) -> None:
        """
        Discover all network resources across configured regions.
        Uses parallel execution for efficiency.
        """
        progress = ProgressIndicator(len(self.regions), "Scanning regions", self.quiet)
        
        # Use parallel discovery
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._discover_region, region): region 
                for region in self.regions
            }
            
            for future in as_completed(futures):
                region = futures[future]
                try:
                    future.result()
                    progress.update(region, "done")
                except Exception as e:
                    logger.error(f"Error discovering region {region}: {e}")
                    progress.update(region, f"error: {e}")
        
        progress.finish()
        self._analyze_connectivity()
        
        # Validate discovered data
        self._validate_and_log_data()
    
    def _validate_and_log_data(self) -> None:
        """Validate discovered data and log any issues."""
        # Count instances from discovery_data
        instances_from_discovery = 0
        for region, data in self.discovery_data.items():
            if isinstance(data, dict):
                for vpc_id, vpc in data.get('vpcs', {}).items():
                    if isinstance(vpc, dict):
                        instances_from_discovery += len(vpc.get('instances', {}))
        
        instances_from_self = len(self.instances)
        vpcs_from_self = len(self.vpcs)
        
        logger.debug(f"Validation: self.instances={instances_from_self}, discovery_data instances={instances_from_discovery}")
        
        if instances_from_self != instances_from_discovery:
            logger.warning(
                f"Data inconsistency detected: self.instances has {instances_from_self} entries, "
                f"but discovery_data has {instances_from_discovery} instances"
            )
        
        # Log summary
        logger.info(f"Discovery complete: {vpcs_from_self} VPCs, {instances_from_self} instances, "
                   f"{len(self.peering_connections)} peerings, {len(self.transit_gateways)} TGWs")
    
    @retry_with_backoff()
    def _discover_region(self, region: str) -> None:
        """Discover all resources in a single region."""
        ec2 = self.session.client('ec2', region_name=region)
        
        region_data = {
            "vpcs": {},
            "instances": [],
            "peering_connections": [],
            "transit_gateways": []
        }
        
        # Discover VPCs
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            vpc_info = {
                "vpc_id": vpc_id,
                "cidr_block": vpc['CidrBlock'],
                "region": region,
                "is_default": vpc.get('IsDefault', False),
                "name": self._get_name_tag(vpc.get('Tags', [])),
                "subnets": {},
                "instances": {}
            }
            
            # Get subnets
            subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                has_internet = self._check_internet_access(ec2, subnet_id, vpc_id)
                subnet_info = SubnetInfo(
                    subnet_id=subnet_id,
                    name=self._get_name_tag(subnet.get('Tags', [])) or subnet_id,
                    cidr=subnet['CidrBlock'],
                    network_id=vpc_id,
                    region=region,
                    availability_zone=subnet['AvailabilityZone'],
                    is_public=subnet.get('MapPublicIpOnLaunch', False),
                    has_internet_access=has_internet
                )
                vpc_info["subnets"][subnet_id] = asdict(subnet_info)
                # Also store with vpc_id for backwards compatibility
                vpc_info["subnets"][subnet_id]["vpc_id"] = vpc_id
                vpc_info["subnets"][subnet_id]["has_internet"] = has_internet
                
                with self._lock:
                    self.subnets[subnet_id] = subnet_info
            
            # Get instances in this VPC
            instances = ec2.describe_instances(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
                ]
            )
            
            for reservation in instances['Reservations']:
                for inst in reservation['Instances']:
                    inst_info = InstanceInfo(
                        instance_id=inst['InstanceId'],
                        name=self._get_name_tag(inst.get('Tags', [])) or inst['InstanceId'],
                        network_id=vpc_id,
                        subnet_id=inst.get('SubnetId', ''),
                        region=region,
                        private_ips=[inst.get('PrivateIpAddress', '')] if inst.get('PrivateIpAddress') else [],
                        public_ip=inst.get('PublicIpAddress'),
                        state=inst['State']['Name'],
                        security_groups=[sg['GroupId'] for sg in inst.get('SecurityGroups', [])]
                    )
                    vpc_info["instances"][inst['InstanceId']] = asdict(inst_info)
                    region_data["instances"].append(inst_info)
                    
                    with self._lock:
                        self.instances[inst['InstanceId']] = inst_info
            
            region_data["vpcs"][vpc_id] = vpc_info
            
            with self._lock:
                self.vpcs[vpc_id] = vpc_info
        
        # Discover VPC Peering connections
        peerings = ec2.describe_vpc_peering_connections(
            Filters=[{'Name': 'status-code', 'Values': ['active']}]
        )['VpcPeeringConnections']
        
        for peering in peerings:
            peering_info = {
                "connection_id": peering['VpcPeeringConnectionId'],
                "requester_vpc": peering['RequesterVpcInfo']['VpcId'],
                "requester_region": peering['RequesterVpcInfo'].get('Region', region),
                "accepter_vpc": peering['AccepterVpcInfo']['VpcId'],
                "accepter_region": peering['AccepterVpcInfo'].get('Region', region)
            }
            region_data["peering_connections"].append(peering_info)
            
            with self._lock:
                # Avoid duplicates
                if not any(p['connection_id'] == peering_info['connection_id'] 
                          for p in self.peering_connections):
                    self.peering_connections.append(peering_info)
        
        # Discover Transit Gateways
        try:
            tgws = ec2.describe_transit_gateways()['TransitGateways']
            for tgw in tgws:
                if tgw['State'] == 'available':
                    tgw_info = {
                        "tgw_id": tgw['TransitGatewayId'],
                        "region": region,
                        "owner_id": tgw['OwnerId']
                    }
                    region_data["transit_gateways"].append(tgw_info)
                    
                    with self._lock:
                        if not any(t['tgw_id'] == tgw_info['tgw_id'] for t in self.transit_gateways):
                            self.transit_gateways.append(tgw_info)
            
            # Get TGW attachments
            attachments = ec2.describe_transit_gateway_attachments()['TransitGatewayAttachments']
            for att in attachments:
                if att['State'] == 'available' and att['ResourceType'] == 'vpc':
                    att_info = {
                        "attachment_id": att['TransitGatewayAttachmentId'],
                        "tgw_id": att['TransitGatewayId'],
                        "vpc_id": att.get('ResourceId'),
                        "region": region
                    }
                    with self._lock:
                        if not any(a['attachment_id'] == att_info['attachment_id'] 
                                  for a in self.tgw_attachments):
                            self.tgw_attachments.append(att_info)
        except ClientError:
            pass  # TGW may not be available in all regions
        
        # Add legacy-compatible fields for generate_recommendation
        region_data["internet_vpcs"] = []
        for vpc_id, vpc in region_data["vpcs"].items():
            # Check if any subnet has internet access
            has_internet = any(s.get("has_internet_access") or s.get("has_internet") 
                              for s in vpc.get("subnets", {}).values())
            if has_internet:
                region_data["internet_vpcs"].append(vpc_id)
            
            # Add default SG/NACL status (valid by default, conservative assumption)
            vpc["sgs"] = {"valid": True, "issues": []}
            vpc["nacls"] = {"valid": True, "issues": []}
            
            # Add alias for cidr -> cidr_block compatibility
            vpc["cidr"] = vpc.get("cidr_block", "")
            
            # Add subnet legacy fields
            for subnet_id, subnet in vpc.get("subnets", {}).items():
                subnet["public"] = subnet.get("is_public", False) or subnet.get("has_internet_access", False)
                subnet["peering_routes"] = []
                subnet["tgw_routes"] = []
        
        # Classify environment
        region_data["environment"] = self._classify_environment(region_data)
        region_data["tgw_present"] = len(region_data["transit_gateways"]) > 0
        region_data["vpc_peering_present"] = len(region_data["peering_connections"]) > 0
        
        with self._lock:
            self.discovery_data[region] = region_data
    
    def _classify_environment(self, region_data: Dict) -> str:
        """Classify the environment type based on network topology."""
        vpcs = region_data.get("vpcs", {})
        tgws = region_data.get("transit_gateways", [])
        peerings = region_data.get("peering_connections", [])
        
        if tgws:
            return "TGW_HUB"
        elif len(vpcs) == 1:
            return "SINGLE_VPC"
        elif peerings:
            return "VPC_HUB"
        elif len(vpcs) > 1:
            return "FLAT"
        return "EMPTY"
    
    def _get_name_tag(self, tags: List[Dict]) -> str:
        """Extract Name tag from AWS tags."""
        return extract_name_from_tags(tags)
    
    @retry_with_backoff()
    def _check_internet_access(self, ec2, subnet_id: str, vpc_id: str) -> bool:
        """Check if subnet has internet access via IGW."""
        try:
            # Check for IGW
            igws = ec2.describe_internet_gateways(
                Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
            )['InternetGateways']
            
            if not igws:
                return False
            
            # Check route table for route to IGW
            route_tables = ec2.describe_route_tables(
                Filters=[
                    {'Name': 'association.subnet-id', 'Values': [subnet_id]}
                ]
            )['RouteTables']
            
            if not route_tables:
                # Check main route table
                route_tables = ec2.describe_route_tables(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'association.main', 'Values': ['true']}
                    ]
                )['RouteTables']
            
            for rt in route_tables:
                for route in rt.get('Routes', []):
                    if route.get('GatewayId', '').startswith('igw-'):
                        if route.get('DestinationCidrBlock') == '0.0.0.0/0':
                            return True
            
            return False
        except Exception:
            return False
    
    def _analyze_connectivity(self) -> None:
        """Analyze connectivity between all VPCs."""
        # Build reachability graph
        vpc_ids = list(self.vpcs.keys())
        
        for vpc1 in vpc_ids:
            self.reachability_matrix[vpc1] = {}
            for vpc2 in vpc_ids:
                if vpc1 == vpc2:
                    self.reachability_matrix[vpc1][vpc2] = True
                else:
                    self.reachability_matrix[vpc1][vpc2] = self._can_reach(vpc1, vpc2)
    
    def _can_reach(self, source_vpc: str, dest_vpc: str) -> bool:
        """Check if source VPC can reach destination VPC."""
        # Check direct peering
        for peering in self.peering_connections:
            if ((peering['requester_vpc'] == source_vpc and peering['accepter_vpc'] == dest_vpc) or
                (peering['accepter_vpc'] == source_vpc and peering['requester_vpc'] == dest_vpc)):
                return True
        
        # Check Transit Gateway connectivity
        source_tgws = {att['tgw_id'] for att in self.tgw_attachments if att['vpc_id'] == source_vpc}
        dest_tgws = {att['tgw_id'] for att in self.tgw_attachments if att['vpc_id'] == dest_vpc}
        
        if source_tgws & dest_tgws:  # If they share a TGW
            return True
        
        return False
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report.
        
        Returns:
            Dictionary containing recommendation, summary, and regional analysis.
            Schema is consistent with Azure and GCP analyzers.
        """
        # Find best deployment location
        best_location = self._find_best_location()
        
        # Calculate coverage
        total_instances = len(self.instances)
        reachable_instances = 0
        unreachable = []
        reachable_instance_ids = set()
        
        if best_location:
            best_vpc = best_location['vpc_id']
            for inst_id, inst in self.instances.items():
                if inst.network_id == best_vpc or self.reachability_matrix.get(best_vpc, {}).get(inst.network_id, False):
                    reachable_instances += 1
                    reachable_instance_ids.add(inst_id)
                else:
                    unreachable.append({
                        "instance_id": inst_id,
                        "name": inst.name,
                        "vpc_id": inst.network_id,
                        "region": inst.region,
                        "private_ip": inst.private_ips[0] if inst.private_ips else "",
                        "public_ip": inst.public_ip or ""
                    })
        
        coverage_pct = (reachable_instances / total_instances * 100) if total_instances > 0 else 0
        
        # Determine status
        if coverage_pct == 100 and best_location:
            status = "SUCCESS"
            message = f"Deploy scanner in {best_location['region']} - {best_location['vpc_id']} for 100% coverage"
        elif coverage_pct > 0 and best_location:
            status = "PARTIAL"
            message = f"Primary location covers {coverage_pct:.1f}% of instances. Multi-region deployment recommended."
        elif total_instances > 0:
            status = "PARTIAL"
            message = "Instances found but no suitable deployment location identified"
        else:
            status = "NO_INSTANCES"
            message = "No instances found in the analyzed regions"
        
        # Build regional analysis
        regional_analysis = {}
        for region, data in self.discovery_data.items():
            instances_in_region = sum(len(vpc.get('instances', {})) for vpc in data['vpcs'].values())
            regional_analysis[region] = {
                "total_vpcs": len(data['vpcs']),
                "total_instances_in_region": instances_in_region,
                "peering_connections": len(data['peering_connections']),
                "transit_gateways": len(data['transit_gateways'])
            }
        
        # Build all_instances list (consistent with Azure/GCP)
        all_instances_list = []
        for inst_id, inst in self.instances.items():
            all_instances_list.append({
                "instance_id": inst_id,
                "name": inst.name,
                "vpc_id": inst.network_id,
                "vpc_name": self.vpcs.get(inst.network_id, {}).get('name', ''),
                "subnet_id": inst.subnet_id,
                "region": inst.region,
                "private_ip": inst.private_ips[0] if inst.private_ips else "",
                "private_ips": inst.private_ips,
                "public_ip": inst.public_ip or "",
                "security_groups": inst.security_groups,
                "state": inst.state,
                "reachable": inst_id in reachable_instance_ids
            })
        
        # Calculate full coverage plan using greedy set cover
        full_coverage_deployments = self._find_full_coverage_deployments()
        full_coverage_total = sum(d.get("covers_instances", 0) for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_instances * 100) if total_instances > 0 else 0
        
        # Calculate connectivity summary
        peered_vpcs = set()
        for p in self.peering_connections:
            peered_vpcs.add(p['requester_vpc'])
            peered_vpcs.add(p['accepter_vpc'])
        
        tgw_connected_vpcs = set()
        for att in self.tgw_attachments:
            if att.get('vpc_id'):
                tgw_connected_vpcs.add(att['vpc_id'])
        
        isolated_vpcs = len(self.vpcs) - len(peered_vpcs | tgw_connected_vpcs)
        
        # Normalize deployment_location to use standard field names
        normalized_location = None
        if best_location:
            normalized_location = {
                "region": best_location.get('region', ''),
                "network_id": best_location.get('vpc_id', ''),
                "network_name": best_location.get('vpc_name', ''),
                "network_cidr": best_location.get('vpc_cidr', ''),
                "subnet_id": best_location.get('subnet_id', ''),
                "subnet_name": best_location.get('subnet_name', ''),
                "subnet_cidr": best_location.get('subnet_cidr', ''),
                "has_internet": best_location.get('has_internet_access', False),
                "instances_reachable": best_location.get('instances_reachable', 0),
                # AWS-specific fields preserved for backward compatibility
                "vpc_id": best_location.get('vpc_id', ''),
                "vpc_name": best_location.get('vpc_name', ''),
                "vpc_cidr": best_location.get('vpc_cidr', ''),
                "has_internet_access": best_location.get('has_internet_access', False)
            }
        
        report = {
            "cloud": "aws",
            "all_instances": all_instances_list,
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
                "unreachable_count": total_instances - full_coverage_total,
                "deployments": full_coverage_deployments
            },
            "summary": {
                "total_regions_scanned": len(self.regions),
                "total_networks": len(self.vpcs),
                "total_vpcs": len(self.vpcs),  # Backward compatibility
                "total_instances": total_instances,
                "total_peering_connections": len(self.peering_connections),
                "total_transit_gateways": len(self.transit_gateways)
            },
            "connectivity_summary": {
                "peered_networks": len(peered_vpcs),
                "isolated_networks": isolated_vpcs,
                "total_peering_connections": len(self.peering_connections),
                "total_transit_gateways": len(self.transit_gateways),
                # Backward compatibility
                "peered_vpcs": len(peered_vpcs),
                "tgw_connected_vpcs": len(tgw_connected_vpcs),
                "isolated_vpcs": isolated_vpcs
            },
            "regional_analysis": regional_analysis,
            "generated_at": datetime.now().isoformat()
        }
        
        return report
    
    def _find_best_location(self) -> Optional[Dict]:
        """Find the VPC/subnet with maximum reachability."""
        if not self.vpcs:
            return None
        
        best_vpc = None
        best_coverage = 0
        best_subnet = None
        
        for vpc_id, vpc in self.vpcs.items():
            # Count reachable instances from this VPC
            reachable = 0
            for inst in self.instances.values():
                if inst.network_id == vpc_id or self.reachability_matrix.get(vpc_id, {}).get(inst.network_id, False):
                    reachable += 1
            
            if reachable > best_coverage:
                best_coverage = reachable
                best_vpc = vpc
                
                # Find best subnet (prefer public with internet access)
                for subnet_id, subnet in vpc.get('subnets', {}).items():
                    if subnet.get('has_internet_access') or subnet.get('has_internet'):
                        best_subnet = subnet
                        break
                
                if not best_subnet and vpc.get('subnets'):
                    best_subnet = list(vpc['subnets'].values())[0]
        
        if not best_vpc:
            return None
        
        return {
            "region": best_vpc['region'],
            "vpc_id": best_vpc['vpc_id'],
            "vpc_cidr": best_vpc['cidr_block'],
            "vpc_name": best_vpc.get('name', ''),
            "subnet_id": best_subnet['subnet_id'] if best_subnet else None,
            "subnet_cidr": best_subnet['cidr'] if best_subnet else None,
            "has_internet_access": best_subnet.get('has_internet', False) if best_subnet else False,
            "instances_reachable": best_coverage
        }
    
    def _plan_multi_region_deployment(self, primary: Dict, unreachable: List[Dict]) -> Dict:
        """Plan multi-region deployment for full coverage (legacy method)."""
        deployments = self._find_full_coverage_deployments()
        return {
            "total_deployments_needed": len(deployments),
            "deployment_locations": deployments,
            "total_instances": len(self.instances),
            "reason": f"Network isolation requires {len(deployments)} scanner deployments for full coverage"
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
        candidates = {}  # vpc_id -> {"vpc": vpc, "subnet": subnet, "instances": set()}
        
        for vpc_id, vpc in self.vpcs.items():
            # Find all instances reachable from this VPC
            reachable_inst_ids = set()
            
            for inst_id, inst in self.instances.items():
                # Instance is reachable if it's in the same VPC or in a connected VPC
                if inst.network_id == vpc_id or self.reachability_matrix.get(vpc_id, {}).get(inst.network_id, False):
                    reachable_inst_ids.add(inst_id)
            
            if reachable_inst_ids:
                # Find best subnet (prefer one with internet access)
                best_subnet = None
                for subnet_id, subnet_data in vpc.get('subnets', {}).items():
                    if subnet_data.get('has_internet_access') or subnet_data.get('has_internet'):
                        best_subnet = subnet_data
                        break
                    if not best_subnet:
                        best_subnet = subnet_data
                
                candidates[vpc_id] = {
                    "vpc": vpc,
                    "subnet": best_subnet,
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
            
            # Get VPC peerings for this VPC
            vpc_peerings = [p for p in self.peering_connections 
                          if p.get('requester_vpc') == vpc.get('vpc_id') or p.get('accepter_vpc') == vpc.get('vpc_id')]
            
            # Get TGW attachments for this VPC
            vpc_tgws = [att for att in self.tgw_attachments if att.get('vpc_id') == vpc.get('vpc_id')]
            
            deploy = {
                "deployment_order": len(selected_deployments) + 1,
                # Region info
                "region": vpc.get('region', 'unknown'),
                # VPC info
                "vpc_id": vpc.get('vpc_id'),
                "vpc_name": vpc.get('name', ''),
                "vpc_cidr": vpc.get('cidr_block') or vpc.get('cidr', ''),
                # Subnet info
                "subnet_id": subnet.get('subnet_id') if subnet else None,
                "subnet_name": subnet.get('name', '') if subnet else None,
                "subnet_cidr": subnet.get('cidr') if subnet else None,
                # Internet connectivity
                "is_public": subnet.get('is_public', False) if subnet else False,
                "has_internet": (subnet.get('has_internet_access') or subnet.get('has_internet', False)) if subnet else False,
                "internet_access_method": "igw" if (subnet and (subnet.get('has_internet_access') or subnet.get('has_internet'))) else "none",
                # Connectivity info
                "peering_connections": [p.get('connection_id') for p in vpc_peerings],
                "transit_gateways": [t.get('tgw_id') for t in vpc_tgws],
                # Coverage info
                "covers_instances": len(best_coverage),
                "newly_covered_ids": list(best_coverage)[:20]
            }
            
            # Add details of newly covered instances
            deploy["covered_instances_detail"] = []
            for inst_id in list(best_coverage)[:10]:
                inst = self.instances.get(inst_id)
                if inst:
                    detail = {
                        "instance_id": inst_id,
                        "name": inst.name,
                        "private_ip": inst.private_ips[0] if inst.private_ips else "",
                        "public_ip": inst.public_ip or "",
                        "vpc_id": inst.network_id,
                        "subnet_id": inst.subnet_id,
                        "region": inst.region,
                        "security_groups": inst.security_groups,
                        "state": inst.state
                    }
                    deploy["covered_instances_detail"].append(detail)
            
            # Update running totals
            uncovered -= best_coverage
            selected_deployments.append(deploy)
            
            # Remove this candidate from future consideration
            del candidates[best_key]
        
        # Add cumulative coverage info
        cumulative = 0
        total = len(all_instances)
        for deploy in selected_deployments:
            cumulative += deploy["covers_instances"]
            deploy["cumulative_covered"] = cumulative
            deploy["cumulative_percentage"] = (cumulative / total * 100) if total else 0
        
        return selected_deployments
    
    def get_discovery_data(self) -> Dict[str, Any]:
        """Return raw discovery data for all regions."""
        return self.discovery_data
