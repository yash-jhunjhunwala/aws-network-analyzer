#!/usr/bin/env python3
"""
AWS Network Reachability Analyzer

Finds the optimal VPC and subnet to deploy an EC2 instance that can reach
all other EC2 instances in the region/account. Provides detailed analysis
for both regional and cross-region reachability.

Author: Enhanced version with comprehensive reachability analysis
"""

import boto3
import argparse
import json
import ipaddress
import time
from functools import wraps
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
from botocore.exceptions import ClientError, EndpointConnectionError

DEFAULT_ASSUME_ROLE = "OrganizationAccountAccessRole"
EPHEMERAL_RANGE = (1024, 65535)
MAX_PARALLEL_REGIONS = 10
MAX_RETRIES = 3
BASE_DELAY = 1.0

# Common ports that an installer/scanner might need
SCAN_PORTS = [22, 443, 445, 5985, 5986]  # SSH, HTTPS, SMB, WinRM


def retry_with_backoff(max_retries=MAX_RETRIES, base_delay=BASE_DELAY):
    """
    Decorator for retrying AWS API calls with exponential backoff.
    Handles throttling (RequestLimitExceeded) and transient errors.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ('RequestLimitExceeded', 'Throttling', 'ThrottlingException',
                                      'TooManyRequestsException', 'ServiceUnavailable',
                                      'InternalError', 'RequestTimeout'):
                        last_exception = e
                        delay = base_delay * (2 ** attempt)
                        time.sleep(delay)
                    else:
                        raise
                except EndpointConnectionError as e:
                    last_exception = e
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                except Exception:
                    raise
            raise last_exception
        return wrapper
    return decorator


class ProgressIndicator:
    """Thread-safe progress indicator for multi-region scans."""
    
    def __init__(self, total: int, description: str = "Progress", quiet: bool = False):
        self.total = total
        self.description = description
        self.quiet = quiet
        self.completed = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.region_status = {}
    
    def update(self, region: str, status: str = "done"):
        """Update progress after completing a region."""
        with self.lock:
            self.completed += 1
            self.region_status[region] = status
            if not self.quiet:
                self._print_progress(region)
    
    def _print_progress(self, region: str):
        """Print progress bar to stderr."""
        pct = (self.completed / self.total) * 100
        elapsed = time.time() - self.start_time
        bar_len = 30
        filled = int(bar_len * self.completed / self.total)
        bar = '█' * filled + '░' * (bar_len - filled)
        
        sys.stderr.write(f"\r  [{bar}] {self.completed}/{self.total} ({pct:.0f}%) - {region} ({elapsed:.1f}s)")
        sys.stderr.flush()
        
        if self.completed == self.total:
            sys.stderr.write("\n")
    
    def finish(self):
        """Finalize progress indicator."""
        elapsed = time.time() - self.start_time
        if not self.quiet:
            sys.stderr.write(f"\r{' ' * 80}\r")
            print(f"  ✓ Completed {self.total} regions in {elapsed:.1f}s", file=sys.stderr)


@dataclass
class EC2Instance:
    """Represents an EC2 instance with network details."""
    instance_id: str
    vpc_id: str
    subnet_id: str
    region: str
    private_ip: str
    security_groups: List[str]
    state: str = "running"
    name: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class SubnetInfo:
    """Represents a subnet with routing and connectivity info."""
    subnet_id: str
    vpc_id: str
    region: str
    cidr: str
    availability_zone: str
    is_public: bool  # Has IGW route
    has_nat: bool  # Has NAT gateway route
    route_targets: Dict[str, List[str]] = field(default_factory=dict)  # cidr -> [tgw/pcx/lgw]
    tgw_attachments: List[str] = field(default_factory=list)
    peering_connections: List[str] = field(default_factory=list)
    instance_count: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class VPCInfo:
    """Represents a VPC with connectivity information."""
    vpc_id: str
    region: str
    cidr: str
    cidrs: List[str]  # All CIDRs (primary + secondary)
    has_igw: bool
    subnets: Dict[str, SubnetInfo] = field(default_factory=dict)
    tgw_attachments: List[str] = field(default_factory=list)
    peering_connections: List[str] = field(default_factory=list)
    sg_allows_outbound: bool = True
    nacl_allows_ephemeral: bool = True
    instance_count: int = 0

    def to_dict(self):
        d = asdict(self)
        d['subnets'] = {k: v.to_dict() if hasattr(v, 'to_dict') else v for k, v in self.subnets.items()}
        return d


@dataclass
class ConnectivityPath:
    """Represents a connectivity path between two points."""
    source_vpc: str
    source_region: str
    target_vpc: str
    target_region: str
    path_type: str  # 'same_vpc', 'tgw', 'peering', 'inter_region_tgw', 'inter_region_peering'
    via: Optional[str] = None  # TGW ID or Peering Connection ID


@dataclass
class ReachabilityResult:
    """Result of reachability analysis for a specific deployment location."""
    vpc_id: str
    subnet_id: str
    region: str
    total_instances: int
    reachable_instances: int
    reachable_in_region: int
    reachable_cross_region: int
    unreachable_instances: List[Dict] = field(default_factory=list)
    reachable_by_region: Dict[str, int] = field(default_factory=dict)
    coverage_percentage: float = 0.0
    has_internet_access: bool = False
    connectivity_issues: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class AWSNetworkAnalyzer:
    """Comprehensive AWS network reachability analyzer."""

    def __init__(self, session: boto3.Session, regions: List[str] = None, max_parallel: int = MAX_PARALLEL_REGIONS):
        self.session = session
        self.regions = regions or self._get_enabled_regions()
        self.max_parallel = max_parallel

        # Get account ID from STS
        try:
            sts = session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
        except Exception:
            self.account_id = None

        # Data stores with thread-safe access
        self._lock = threading.Lock()
        self.vpcs: Dict[str, VPCInfo] = {}  # vpc_id -> VPCInfo
        self.instances: Dict[str, EC2Instance] = {}  # instance_id -> EC2Instance
        self.tgw_attachments: Dict[str, Dict] = {}  # attachment_id -> attachment_info
        self.tgw_route_tables: Dict[str, List[Dict]] = {}  # tgw_id -> routes
        self.peering_connections: Dict[str, Dict] = {}  # pcx_id -> connection_info

        # Connectivity graph
        self.connectivity_graph: Dict[str, Set[str]] = defaultdict(set)  # vpc_id -> set of reachable vpc_ids

    def _get_enabled_regions(self) -> List[str]:
        """Get all enabled regions."""
        ec2 = self.session.client("ec2", region_name="us-east-1")
        return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]

    def _get_ec2_client(self, region: str):
        """Get EC2 client for a region."""
        return self.session.client("ec2", region_name=region)

    # Retry-wrapped API methods
    @staticmethod
    @retry_with_backoff()
    def _api_describe_vpcs(ec2):
        return ec2.describe_vpcs()["Vpcs"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_igws(ec2):
        return ec2.describe_internet_gateways()["InternetGateways"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_subnets(ec2):
        return ec2.describe_subnets()["Subnets"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_route_tables(ec2):
        return ec2.describe_route_tables()["RouteTables"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_nat_gateways(ec2):
        return ec2.describe_nat_gateways(Filters=[{"Name": "state", "Values": ["available"]}])["NatGateways"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_sgs(ec2, vpc_id):
        return ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_nacls(ec2, vpc_id):
        return ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_tgws(ec2):
        return ec2.describe_transit_gateways()["TransitGateways"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_tgw_attachments(ec2, tgw_id):
        return ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        )["TransitGatewayAttachments"]

    @staticmethod
    @retry_with_backoff()
    def _api_describe_peerings(ec2):
        return ec2.describe_vpc_peering_connections(
            Filters=[{"Name": "status-code", "Values": ["active"]}]
        )["VpcPeeringConnections"]

    def discover_all(self, progress_callback=None, quiet: bool = False) -> Dict:
        """
        Discover all network infrastructure across regions.
        Returns comprehensive network topology.
        Uses parallel scanning for faster results.
        """
        # Initialize progress indicator
        progress = ProgressIndicator(len(self.regions), "Scanning regions", quiet=quiet)

        def discover_region_wrapper(region):
            """Wrapper for parallel execution."""
            try:
                self._discover_region(region)
                return region, None
            except Exception as e:
                return region, str(e)

        if self.max_parallel > 1 and len(self.regions) > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(self.regions))) as executor:
                futures = {executor.submit(discover_region_wrapper, region): region for region in self.regions}
                
                for future in as_completed(futures):
                    region, error = future.result()
                    if error:
                        progress.update(region, status="error")
                        if not quiet:
                            print(f"  Warning: Error discovering {region}: {error}", file=sys.stderr)
                    else:
                        progress.update(region, status="done")
        else:
            # Sequential execution
            for region in self.regions:
                try:
                    self._discover_region(region)
                    progress.update(region, status="done")
                except Exception as e:
                    progress.update(region, status="error")
                    if not quiet:
                        print(f"  Warning: Error discovering {region}: {e}", file=sys.stderr)

        progress.finish()

        # Build connectivity graph after discovering all resources
        self._build_connectivity_graph()

        return self._get_topology_summary()

    def _discover_region(self, region: str):
        """Discover all network resources in a region."""
        ec2 = self._get_ec2_client(region)

        # Discover VPCs (with retry)
        vpcs = self._api_describe_vpcs(ec2)
        igws = self._api_describe_igws(ec2)

        # Map IGW to VPCs
        igw_vpc_map = {}
        for igw in igws:
            for att in igw.get("Attachments", []):
                if att.get("State") == "available" and "VpcId" in att:
                    igw_vpc_map[att["VpcId"]] = igw["InternetGatewayId"]

        # Process VPCs
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            cidrs = [vpc["CidrBlock"]]
            for assoc in vpc.get("CidrBlockAssociationSet", []):
                if assoc.get("CidrBlockState", {}).get("State") == "associated":
                    if assoc["CidrBlock"] not in cidrs:
                        cidrs.append(assoc["CidrBlock"])

            vpc_info = VPCInfo(
                vpc_id=vpc_id,
                region=region,
                cidr=vpc["CidrBlock"],
                cidrs=cidrs,
                has_igw=vpc_id in igw_vpc_map
            )

            # Check security groups and NACLs
            vpc_info.sg_allows_outbound = self._check_sg_outbound(ec2, vpc_id)
            vpc_info.nacl_allows_ephemeral = self._check_nacl_ephemeral(ec2, vpc_id)

            with self._lock:
                self.vpcs[vpc_id] = vpc_info

        # Discover subnets and route tables
        self._discover_subnets(ec2, region)

        # Discover Transit Gateways
        self._discover_transit_gateways(ec2, region)

        # Discover VPC Peering
        self._discover_vpc_peering(ec2, region)

        # Discover EC2 instances
        self._discover_instances(ec2, region)

    def _discover_subnets(self, ec2, region: str):
        """Discover subnets and their routing."""
        subnets = self._api_describe_subnets(ec2)
        route_tables = self._api_describe_route_tables(ec2)
        nat_gateways = self._api_describe_nat_gateways(ec2)

        # Map subnets to their route tables
        subnet_rt_map = {}
        main_rt_map = {}  # vpc_id -> main route table

        for rt in route_tables:
            vpc_id = rt["VpcId"]
            for assoc in rt.get("Associations", []):
                if assoc.get("Main"):
                    main_rt_map[vpc_id] = rt
                elif assoc.get("SubnetId"):
                    subnet_rt_map[assoc["SubnetId"]] = rt

        # Map NAT gateways to subnets
        nat_subnet_map = {nat["SubnetId"]: nat["NatGatewayId"] for nat in nat_gateways}

        for subnet in subnets:
            subnet_id = subnet["SubnetId"]
            vpc_id = subnet["VpcId"]

            if vpc_id not in self.vpcs:
                continue

            # Get route table for this subnet
            rt = subnet_rt_map.get(subnet_id) or main_rt_map.get(vpc_id)

            is_public = False
            has_nat = False
            route_targets = defaultdict(list)
            tgw_attachments = []
            peering_connections = []

            if rt:
                for route in rt.get("Routes", []):
                    dest = route.get("DestinationCidrBlock", route.get("DestinationPrefixListId", ""))

                    # Check for IGW (public subnet)
                    if route.get("GatewayId", "").startswith("igw-"):
                        if dest == "0.0.0.0/0":
                            is_public = True
                        route_targets[dest].append(route["GatewayId"])

                    # Check for NAT Gateway
                    if route.get("NatGatewayId"):
                        if dest == "0.0.0.0/0":
                            has_nat = True
                        route_targets[dest].append(route["NatGatewayId"])

                    # Check for Transit Gateway
                    if route.get("TransitGatewayId"):
                        tgw_attachments.append(route["TransitGatewayId"])
                        route_targets[dest].append(route["TransitGatewayId"])

                    # Check for VPC Peering
                    if route.get("VpcPeeringConnectionId"):
                        peering_connections.append(route["VpcPeeringConnectionId"])
                        route_targets[dest].append(route["VpcPeeringConnectionId"])

            subnet_info = SubnetInfo(
                subnet_id=subnet_id,
                vpc_id=vpc_id,
                region=region,
                cidr=subnet["CidrBlock"],
                availability_zone=subnet["AvailabilityZone"],
                is_public=is_public,
                has_nat=has_nat,
                route_targets=dict(route_targets),
                tgw_attachments=list(set(tgw_attachments)),
                peering_connections=list(set(peering_connections))
            )

            self.vpcs[vpc_id].subnets[subnet_id] = subnet_info

            # Track TGW and peering at VPC level
            self.vpcs[vpc_id].tgw_attachments = list(set(
                self.vpcs[vpc_id].tgw_attachments + tgw_attachments
            ))
            self.vpcs[vpc_id].peering_connections = list(set(
                self.vpcs[vpc_id].peering_connections + peering_connections
            ))

    def _discover_transit_gateways(self, ec2, region: str):
        """Discover Transit Gateway attachments and routes."""
        try:
            tgws = self._api_describe_tgws(ec2)

            for tgw in tgws:
                tgw_id = tgw["TransitGatewayId"]

                # Get attachments (with retry)
                attachments = self._api_describe_tgw_attachments(ec2, tgw_id)

                for att in attachments:
                    att_id = att["TransitGatewayAttachmentId"]
                    att_data = {
                        "tgw_id": tgw_id,
                        "resource_type": att["ResourceType"],
                        "resource_id": att.get("ResourceId"),
                        "resource_owner": att.get("ResourceOwnerId"),
                        "state": att["State"],
                        "region": region
                    }

                    # Track cross-region peering
                    if att["ResourceType"] == "peering":
                        att_data["is_cross_region"] = True
                    
                    with self._lock:
                        self.tgw_attachments[att_id] = att_data

                # Get route tables for this TGW
                try:
                    rt_response = ec2.describe_transit_gateway_route_tables(
                        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
                    )

                    for rt in rt_response.get("TransitGatewayRouteTables", []):
                        rt_id = rt["TransitGatewayRouteTableId"]
                        routes = ec2.search_transit_gateway_routes(
                            TransitGatewayRouteTableId=rt_id,
                            Filters=[{"Name": "state", "Values": ["active"]}]
                        ).get("Routes", [])

                        with self._lock:
                            self.tgw_route_tables[tgw_id] = routes
                except Exception:
                    pass  # Route table access might be restricted

        except Exception as e:
            pass  # TGW might not exist in this region

    def _discover_vpc_peering(self, ec2, region: str):
        """Discover VPC peering connections."""
        try:
            peerings = self._api_describe_peerings(ec2)

            for pcx in peerings:
                pcx_id = pcx["VpcPeeringConnectionId"]

                requester = pcx.get("RequesterVpcInfo", {})
                accepter = pcx.get("AccepterVpcInfo", {})

                pcx_data = {
                    "pcx_id": pcx_id,
                    "requester_vpc": requester.get("VpcId"),
                    "requester_region": requester.get("Region"),
                    "requester_cidr": requester.get("CidrBlock"),
                    "accepter_vpc": accepter.get("VpcId"),
                    "accepter_region": accepter.get("Region"),
                    "accepter_cidr": accepter.get("CidrBlock"),
                    "is_cross_region": requester.get("Region") != accepter.get("Region")
                }
                
                with self._lock:
                    self.peering_connections[pcx_id] = pcx_data
        except Exception:
            pass

    def _discover_instances(self, ec2, region: str):
        """Discover EC2 instances (only running instances)."""
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    instance_id = inst["InstanceId"]
                    vpc_id = inst.get("VpcId")
                    subnet_id = inst.get("SubnetId")

                    if not vpc_id or not subnet_id:
                        continue  # Skip EC2-Classic

                    # Get instance name from tags
                    name = ""
                    for tag in inst.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    ec2_inst = EC2Instance(
                        instance_id=instance_id,
                        vpc_id=vpc_id,
                        subnet_id=subnet_id,
                        region=region,
                        private_ip=inst.get("PrivateIpAddress", ""),
                        security_groups=[sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                        state=inst["State"]["Name"],
                        name=name
                    )

                    with self._lock:
                        self.instances[instance_id] = ec2_inst

                        # Update instance counts
                        if vpc_id in self.vpcs:
                            self.vpcs[vpc_id].instance_count += 1
                            if subnet_id in self.vpcs[vpc_id].subnets:
                                self.vpcs[vpc_id].subnets[subnet_id].instance_count += 1

    def _check_sg_outbound(self, ec2, vpc_id: str) -> bool:
        """Check if security groups allow outbound traffic."""
        sgs = self._api_describe_sgs(ec2, vpc_id)

        for sg in sgs:
            has_outbound = False
            for rule in sg.get("IpPermissionsEgress", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        has_outbound = True
                        break
            if has_outbound:
                return True

        return len(sgs) == 0  # No SGs means default allows

    def _check_nacl_ephemeral(self, ec2, vpc_id: str) -> bool:
        """Check if NACLs allow ephemeral port range."""
        nacls = self._api_describe_nacls(ec2, vpc_id)

        for nacl in nacls:
            for entry in nacl.get("Entries", []):
                if entry.get("Egress") and entry.get("RuleAction") == "allow":
                    if entry.get("CidrBlock") == "0.0.0.0/0":
                        port_range = entry.get("PortRange")
                        if not port_range:  # All traffic
                            return True
                        if (port_range.get("From", 0) <= EPHEMERAL_RANGE[0] and
                            port_range.get("To", 0) >= EPHEMERAL_RANGE[1]):
                            return True

        return False

    def _build_connectivity_graph(self):
        """Build a graph of VPC-to-VPC connectivity."""
        # Same VPC connectivity (always reachable within VPC)
        for vpc_id in self.vpcs:
            self.connectivity_graph[vpc_id].add(vpc_id)

        # Transit Gateway connectivity
        tgw_vpc_map = defaultdict(set)  # tgw_id -> set of vpc_ids

        for att_id, att in self.tgw_attachments.items():
            if att["state"] == "available" and att["resource_type"] == "vpc":
                tgw_vpc_map[att["tgw_id"]].add(att["resource_id"])

        # VPCs connected to the same TGW can reach each other
        for tgw_id, vpc_ids in tgw_vpc_map.items():
            for vpc_id in vpc_ids:
                for other_vpc_id in vpc_ids:
                    if vpc_id != other_vpc_id:
                        self.connectivity_graph[vpc_id].add(other_vpc_id)

        # VPC Peering connectivity
        for pcx_id, pcx in self.peering_connections.items():
            req_vpc = pcx.get("requester_vpc")
            acc_vpc = pcx.get("accepter_vpc")

            if req_vpc and acc_vpc:
                self.connectivity_graph[req_vpc].add(acc_vpc)
                self.connectivity_graph[acc_vpc].add(req_vpc)

    def _get_topology_summary(self) -> Dict:
        """Get a summary of the discovered topology."""
        return {
            "regions_scanned": len(self.regions),
            "total_vpcs": len(self.vpcs),
            "total_instances": len(self.instances),
            "total_tgw_attachments": len(self.tgw_attachments),
            "total_peering_connections": len(self.peering_connections),
            "vpcs_by_region": self._group_vpcs_by_region(),
            "instances_by_region": self._group_instances_by_region()
        }

    def _group_vpcs_by_region(self) -> Dict[str, int]:
        """Group VPC count by region."""
        counts = defaultdict(int)
        for vpc in self.vpcs.values():
            counts[vpc.region] += 1
        return dict(counts)

    def _group_instances_by_region(self) -> Dict[str, int]:
        """Group instance count by region."""
        counts = defaultdict(int)
        for inst in self.instances.values():
            counts[inst.region] += 1
        return dict(counts)

    def can_reach(self, source_vpc: str, target_vpc: str) -> Tuple[bool, Optional[str]]:
        """
        Check if source VPC can reach target VPC.
        Returns (reachable, path_type).
        """
        if source_vpc == target_vpc:
            return True, "same_vpc"

        if target_vpc in self.connectivity_graph.get(source_vpc, set()):
            # Determine path type
            source_info = self.vpcs.get(source_vpc)
            target_info = self.vpcs.get(target_vpc)

            if not source_info or not target_info:
                return False, None

            # Check for TGW path
            common_tgw = set(source_info.tgw_attachments) & set(target_info.tgw_attachments)
            if common_tgw:
                if source_info.region != target_info.region:
                    return True, "inter_region_tgw"
                return True, "tgw"

            # Check for peering path
            common_pcx = set(source_info.peering_connections) & set(target_info.peering_connections)
            if common_pcx:
                for pcx_id in common_pcx:
                    pcx = self.peering_connections.get(pcx_id, {})
                    if pcx.get("is_cross_region"):
                        return True, "inter_region_peering"
                return True, "peering"

            return True, "unknown"

        return False, None

    def analyze_deployment_location(self, vpc_id: str, subnet_id: str) -> ReachabilityResult:
        """
        Analyze how many instances can be reached from a specific deployment location.
        """
        vpc_info = self.vpcs.get(vpc_id)
        subnet_info = vpc_info.subnets.get(subnet_id) if vpc_info else None

        if not vpc_info or not subnet_info:
            return ReachabilityResult(
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                region="unknown",
                total_instances=len(self.instances),
                reachable_instances=0,
                reachable_in_region=0,
                reachable_cross_region=0,
                connectivity_issues=["Invalid VPC or subnet"]
            )

        result = ReachabilityResult(
            vpc_id=vpc_id,
            subnet_id=subnet_id,
            region=vpc_info.region,
            total_instances=len(self.instances),
            reachable_instances=0,
            reachable_in_region=0,
            reachable_cross_region=0,
            has_internet_access=subnet_info.is_public or subnet_info.has_nat
        )

        # Check connectivity to each instance
        for inst_id, inst in self.instances.items():
            reachable, path_type = self.can_reach(vpc_id, inst.vpc_id)

            if reachable:
                result.reachable_instances += 1
                result.reachable_by_region[inst.region] = result.reachable_by_region.get(inst.region, 0) + 1

                if inst.region == vpc_info.region:
                    result.reachable_in_region += 1
                else:
                    result.reachable_cross_region += 1
            else:
                result.unreachable_instances.append({
                    "instance_id": inst_id,
                    "vpc_id": inst.vpc_id,
                    "region": inst.region,
                    "private_ip": inst.private_ip,
                    "name": inst.name
                })

        # Calculate coverage
        if result.total_instances > 0:
            result.coverage_percentage = (result.reachable_instances / result.total_instances) * 100

        # Add connectivity issues
        if not vpc_info.sg_allows_outbound:
            result.connectivity_issues.append("Security groups may block outbound traffic")
        if not vpc_info.nacl_allows_ephemeral:
            result.connectivity_issues.append("NACLs may block ephemeral ports")
        if not result.has_internet_access:
            result.connectivity_issues.append("No internet access (no IGW or NAT)")

        return result

    def find_best_deployment_locations(self,
                                        require_internet: bool = True,
                                        prefer_public_subnet: bool = True,
                                        top_n: int = 5) -> List[ReachabilityResult]:
        """
        Find the best VPC/subnet combinations for deploying an instance
        that can reach all other instances.
        """
        candidates = []

        for vpc_id, vpc_info in self.vpcs.items():
            for subnet_id, subnet_info in vpc_info.subnets.items():
                # Skip if we require internet and subnet doesn't have it
                if require_internet and not (subnet_info.is_public or subnet_info.has_nat):
                    continue

                result = self.analyze_deployment_location(vpc_id, subnet_id)
                candidates.append(result)

        # Sort by coverage percentage (descending), then by preference
        def sort_key(r: ReachabilityResult):
            subnet_info = self.vpcs[r.vpc_id].subnets.get(r.subnet_id)
            is_public = subnet_info.is_public if subnet_info else False

            return (
                -r.coverage_percentage,  # Higher coverage first
                -r.reachable_instances,  # More reachable instances
                not is_public if prefer_public_subnet else is_public,  # Public subnets preferred
                len(r.connectivity_issues)  # Fewer issues
            )

        candidates.sort(key=sort_key)

        return candidates[:top_n]

    def get_regional_analysis(self) -> Dict[str, Dict]:
        """
        Get per-region analysis of reachability.
        For each region, find the best deployment location within that region.
        """
        regional_results = {}

        # Group VPCs by region
        vpcs_by_region = defaultdict(list)
        for vpc_id, vpc_info in self.vpcs.items():
            vpcs_by_region[vpc_info.region].append(vpc_id)

        # Group instances by region
        instances_by_region = defaultdict(list)
        for inst_id, inst in self.instances.items():
            instances_by_region[inst.region].append(inst)

        for region in self.regions:
            region_vpcs = vpcs_by_region.get(region, [])
            region_instances = instances_by_region.get(region, [])

            if not region_vpcs:
                regional_results[region] = {
                    "status": "no_vpcs",
                    "total_instances": len(region_instances),
                    "best_location": None,
                    "cross_region_reachable": 0
                }
                continue

            # Find best location in this region
            best_result = None
            best_coverage = -1

            for vpc_id in region_vpcs:
                vpc_info = self.vpcs[vpc_id]
                for subnet_id in vpc_info.subnets:
                    result = self.analyze_deployment_location(vpc_id, subnet_id)
                    if result.coverage_percentage > best_coverage:
                        best_coverage = result.coverage_percentage
                        best_result = result

            # Calculate cross-region reachability from this region
            cross_region_count = 0
            if best_result:
                for other_region, count in best_result.reachable_by_region.items():
                    if other_region != region:
                        cross_region_count += count

            regional_results[region] = {
                "status": "analyzed",
                "total_instances_in_region": len(region_instances),
                "total_vpcs": len(region_vpcs),
                "best_location": best_result.to_dict() if best_result else None,
                "cross_region_reachable": cross_region_count,
                "can_reach_all_regions": best_result.coverage_percentage == 100 if best_result else False
            }

        return regional_results

    def generate_report(self) -> Dict:
        """Generate a comprehensive reachability report."""
        # Find best global deployment location
        best_locations = self.find_best_deployment_locations(top_n=5)

        # Get regional analysis
        regional_analysis = self.get_regional_analysis()
        
        # Get full coverage deployments (multiple locations to cover ALL instances)
        full_coverage_deployments = self.find_full_coverage_deployments()

        # Determine if we have full global reachability
        global_coverage = best_locations[0].coverage_percentage if best_locations else 0
        
        # Calculate full coverage summary
        total_instances = len(self.instances)
        full_coverage_total = sum(d.get("covers_instances", 0) for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_instances * 100) if total_instances > 0 else 0
        remaining_unreachable = total_instances - full_coverage_total

        # Build the report
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_regions_scanned": len(self.regions),
                "total_vpcs": len(self.vpcs),
                "total_instances": total_instances,
                "global_reachability_possible": global_coverage == 100,
                "best_coverage_percentage": global_coverage,
                "deployments_for_full_coverage": len(full_coverage_deployments),
                "full_coverage_percentage": full_coverage_pct,
                "unreachable_instances": remaining_unreachable
            },
            "recommendation": None,
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": full_coverage_total,
                "coverage_percentage": full_coverage_pct,
                "unreachable_count": remaining_unreachable,
                "deployments": full_coverage_deployments
            },
            "top_deployment_locations": [loc.to_dict() for loc in best_locations],
            "regional_analysis": regional_analysis,
            "connectivity_summary": {
                "tgw_connected_vpcs": sum(1 for v in self.vpcs.values() if v.tgw_attachments),
                "peered_vpcs": sum(1 for v in self.vpcs.values() if v.peering_connections),
                "isolated_vpcs": sum(1 for v in self.vpcs.values()
                                    if not v.tgw_attachments and not v.peering_connections),
                "total_tgw_attachments": len(self.tgw_attachments),
                "total_peering_connections": len(self.peering_connections)
            }
        }

        # Generate recommendation
        if best_locations:
            best = best_locations[0]
            vpc_info = self.vpcs.get(best.vpc_id)
            subnet_info = vpc_info.subnets.get(best.subnet_id) if vpc_info else None

            report["recommendation"] = {
                "status": "SUCCESS" if best.coverage_percentage == 100 else "PARTIAL",
                "message": self._generate_recommendation_message(best),
                "deployment_location": {
                    "region": best.region,
                    "vpc_id": best.vpc_id,
                    "vpc_cidr": vpc_info.cidr if vpc_info else None,
                    "subnet_id": best.subnet_id,
                    "subnet_cidr": subnet_info.cidr if subnet_info else None,
                    "is_public_subnet": subnet_info.is_public if subnet_info else False,
                    "has_internet_access": best.has_internet_access
                },
                "coverage": {
                    "total_instances": best.total_instances,
                    "reachable_instances": best.reachable_instances,
                    "percentage": best.coverage_percentage,
                    "reachable_in_same_region": best.reachable_in_region,
                    "reachable_cross_region": best.reachable_cross_region
                },
                "unreachable_instances": best.unreachable_instances[:10],  # Limit to 10
                "unreachable_count": len(best.unreachable_instances),
                "issues": best.connectivity_issues
            }
        else:
            report["recommendation"] = {
                "status": "FAILED",
                "message": "No suitable deployment location found. No VPCs with internet access.",
                "deployment_location": None
            }

        return report

    def _generate_recommendation_message(self, result: ReachabilityResult) -> str:
        """Generate a human-readable recommendation message."""
        if result.coverage_percentage == 100:
            if result.reachable_cross_region > 0:
                return (f"Deploy in {result.region} to reach ALL {result.total_instances} instances "
                       f"across {len(result.reachable_by_region)} regions. "
                       f"({result.reachable_in_region} in-region, {result.reachable_cross_region} cross-region)")
            else:
                return (f"Deploy in {result.region} to reach all {result.total_instances} instances "
                       f"in this single-region setup.")
        else:
            return (f"Deploy in {result.region} to reach {result.reachable_instances}/{result.total_instances} "
                   f"instances ({result.coverage_percentage:.1f}% coverage). "
                   f"{len(result.unreachable_instances)} instances in isolated VPCs cannot be reached.")

    def get_per_region_recommendations(self) -> List[Dict]:
        """
        Get the best deployment location for each region that has instances.
        Returns a list of per-region recommendations sorted by instance count.
        """
        recommendations = []

        # Group instances by region
        instances_by_region = defaultdict(list)
        for inst_id, inst in self.instances.items():
            instances_by_region[inst.region].append(inst)

        # Group VPCs by region
        vpcs_by_region = defaultdict(list)
        for vpc_id, vpc_info in self.vpcs.items():
            vpcs_by_region[vpc_info.region].append(vpc_id)

        for region, region_instances in instances_by_region.items():
            if not region_instances:
                continue

            region_vpcs = vpcs_by_region.get(region, [])
            if not region_vpcs:
                recommendations.append({
                    "region": region,
                    "instance_count": len(region_instances),
                    "vpc_id": None,
                    "vpc_cidr": None,
                    "subnet_id": None,
                    "subnet_cidr": None,
                    "is_public": False,
                    "has_internet": False,
                    "local_reachable": 0,
                    "status": "NO_VPC",
                    "instances": [{"id": i.instance_id, "name": i.name, "ip": i.private_ip} for i in region_instances]
                })
                continue

            # Find the best subnet in this region for reaching local instances
            best_subnet = None
            best_vpc = None
            best_local_count = -1
            best_is_public = False

            for vpc_id in region_vpcs:
                vpc_info = self.vpcs[vpc_id]
                for subnet_id, subnet_info in vpc_info.subnets.items():
                    # Count how many local instances this VPC can reach
                    local_reachable = sum(1 for inst in region_instances if inst.vpc_id == vpc_id)

                    # Prefer subnets with more local instances, then public subnets
                    is_public = subnet_info.is_public or subnet_info.has_nat
                    if (local_reachable > best_local_count or
                        (local_reachable == best_local_count and is_public and not best_is_public)):
                        best_local_count = local_reachable
                        best_subnet = subnet_info
                        best_vpc = vpc_info
                        best_is_public = is_public

            if best_subnet and best_vpc:
                recommendations.append({
                    "region": region,
                    "instance_count": len(region_instances),
                    "vpc_id": best_vpc.vpc_id,
                    "vpc_cidr": best_vpc.cidr,
                    "subnet_id": best_subnet.subnet_id,
                    "subnet_cidr": best_subnet.cidr,
                    "subnet_az": best_subnet.availability_zone,
                    "is_public": best_subnet.is_public,
                    "has_nat": best_subnet.has_nat,
                    "has_internet": best_subnet.is_public or best_subnet.has_nat,
                    "local_reachable": best_local_count,
                    "status": "OK" if best_local_count == len(region_instances) else "PARTIAL",
                    "instances": [{"id": i.instance_id, "name": i.name, "ip": i.private_ip,
                                   "vpc": i.vpc_id, "reachable": i.vpc_id == best_vpc.vpc_id}
                                  for i in region_instances]
                })
            else:
                recommendations.append({
                    "region": region,
                    "instance_count": len(region_instances),
                    "vpc_id": None,
                    "subnet_id": None,
                    "status": "NO_SUITABLE_SUBNET",
                    "instances": [{"id": i.instance_id, "name": i.name, "ip": i.private_ip} for i in region_instances]
                })

        # Sort by instance count (descending)
        recommendations.sort(key=lambda x: -x["instance_count"])
        return recommendations

    def find_full_coverage_deployments(self, require_internet: bool = True) -> List[Dict]:
        """
        Find the MINIMUM set of deployment locations needed to cover ALL instances.
        Uses a greedy set cover algorithm.
        
        This provides multiple deployment recommendations that together cover 100% 
        of instances (or as close as possible if some are truly isolated).
        
        Returns:
            List of deployment locations, each covering a subset of instances.
            Together they cover all reachable instances.
        """
        if not self.instances:
            return []
        
        # Build a mapping of each candidate location to the set of instances it can reach
        candidates = {}  # (vpc_id, subnet_id) -> {"result": result, "instances": set()}
        
        for vpc_id, vpc_info in self.vpcs.items():
            for subnet_id, subnet_info in vpc_info.subnets.items():
                # Skip if we require internet and subnet doesn't have it
                if require_internet and not (subnet_info.is_public or subnet_info.has_nat):
                    continue
                
                result = self.analyze_deployment_location(vpc_id, subnet_id)
                
                # Build set of reachable instance IDs
                all_instance_ids = set(self.instances.keys())
                unreachable_ids = set(u["instance_id"] for u in result.unreachable_instances)
                reachable_ids = all_instance_ids - unreachable_ids
                
                candidates[(vpc_id, subnet_id)] = {
                    "result": result,
                    "instances": reachable_ids
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
                # How many currently uncovered instances does this cover?
                newly_covered = data["instances"] & uncovered
                
                if len(newly_covered) > len(best_coverage):
                    best_coverage = newly_covered
                    best_candidate = data
                    best_key = key
            
            if not best_candidate or not best_coverage:
                # No candidate can cover any remaining instances - they're unreachable
                break
            
            # Add this deployment to our selection
            result = best_candidate["result"]
            vpc_info = self.vpcs.get(result.vpc_id)
            subnet_info = vpc_info.subnets.get(result.subnet_id) if vpc_info else None
            
            # Determine internet access method
            internet_access_method = "none"
            if subnet_info:
                if subnet_info.is_public:
                    internet_access_method = "igw"  # Internet Gateway (public subnet)
                elif subnet_info.has_nat:
                    internet_access_method = "nat"  # NAT Gateway (private subnet)
            
            deploy = {
                "deployment_order": len(selected_deployments) + 1,
                # Account info
                "account_id": self.account_id if hasattr(self, 'account_id') else None,
                # Region info
                "region": result.region,
                "availability_zone": subnet_info.availability_zone if subnet_info else None,
                # VPC info
                "vpc_id": result.vpc_id,
                "vpc_cidr": vpc_info.cidr if vpc_info else None,
                "vpc_cidrs": vpc_info.cidrs if vpc_info else [],
                "vpc_has_igw": vpc_info.has_igw if vpc_info else False,
                # Subnet info
                "subnet_id": result.subnet_id,
                "subnet_cidr": subnet_info.cidr if subnet_info else None,
                "is_public": subnet_info.is_public if subnet_info else False,
                "has_nat_gateway": subnet_info.has_nat if subnet_info else False,
                # Internet connectivity
                "has_internet": result.has_internet_access,
                "internet_access_method": internet_access_method,
                # Connectivity info
                "tgw_attachments": list(vpc_info.tgw_attachments) if vpc_info else [],
                "peering_connections": list(vpc_info.peering_connections) if vpc_info else [],
                # Coverage info
                "covers_instances": len(best_coverage),
                "newly_covered_ids": list(best_coverage)[:20],  # Limit for readability
            }
            
            # Add details of newly covered instances
            deploy["covered_instances_detail"] = []
            for inst_id in list(best_coverage)[:20]:
                inst = self.instances.get(inst_id)
                if inst:
                    deploy["covered_instances_detail"].append({
                        "instance_id": inst_id,
                        "name": inst.name,
                        "private_ip": inst.private_ip,
                        "region": inst.region,
                        "vpc_id": inst.vpc_id,
                        "subnet_id": inst.subnet_id,
                        "security_groups": inst.security_groups
                    })
            
            selected_deployments.append(deploy)
            
            # Remove covered instances from uncovered set
            uncovered -= best_coverage
            
            # Remove this candidate so we don't select it again
            del candidates[best_key]
        
        # Calculate cumulative coverage for each deployment
        total_instances = len(all_instances)
        cumulative = 0
        for deploy in selected_deployments:
            cumulative += deploy["covers_instances"]
            deploy["cumulative_covered"] = cumulative
            deploy["cumulative_percentage"] = (cumulative / total_instances * 100) if total_instances > 0 else 0
        
        # Add info about any remaining unreachable instances
        if uncovered:
            unreachable_details = []
            for inst_id in list(uncovered)[:50]:
                inst = self.instances.get(inst_id)
                if inst:
                    unreachable_details.append({
                        "instance_id": inst_id,
                        "vpc_id": inst.vpc_id,
                        "region": inst.region,
                        "name": inst.name,
                        "private_ip": inst.private_ip
                    })
            
            # Add metadata about unreachable instances to the last deployment
            if selected_deployments:
                selected_deployments[-1]["remaining_unreachable"] = len(uncovered)
                selected_deployments[-1]["unreachable_details"] = unreachable_details
        
        return selected_deployments

    def generate_text_report(self, report: Dict, output_file: str = "reachability_report.txt"):
        """Generate a detailed text report file."""
        lines = []
        lines.append("=" * 80)
        lines.append("AWS NETWORK REACHABILITY ANALYSIS - DETAILED REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {report.get('generated_at', datetime.now().isoformat())}")
        lines.append("")

        # Summary
        summary = report.get("summary", {})
        lines.append("-" * 80)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Regions Scanned:     {summary.get('total_regions_scanned', 0)}")
        lines.append(f"Total VPCs:          {summary.get('total_vpcs', 0)}")
        lines.append(f"Total EC2 Instances: {summary.get('total_instances', 0)}")
        lines.append(f"Global Reachability: {'YES' if summary.get('global_reachability_possible') else 'NO'}")
        lines.append(f"Best Coverage:       {summary.get('best_coverage_percentage', 0):.1f}%")
        lines.append("")

        # Connectivity Summary
        conn = report.get("connectivity_summary", {})
        lines.append("-" * 80)
        lines.append("CONNECTIVITY ANALYSIS")
        lines.append("-" * 80)
        lines.append(f"TGW-Connected VPCs:  {conn.get('tgw_connected_vpcs', 0)}")
        lines.append(f"Peered VPCs:         {conn.get('peered_vpcs', 0)}")
        lines.append(f"Isolated VPCs:       {conn.get('isolated_vpcs', 0)}")
        lines.append("")

        # Main Recommendation
        rec = report.get("recommendation", {})
        lines.append("-" * 80)
        lines.append(f"RECOMMENDATION: {rec.get('status', 'UNKNOWN')}")
        lines.append("-" * 80)
        lines.append(rec.get("message", "No recommendation available"))
        lines.append("")

        if rec.get("deployment_location"):
            loc = rec["deployment_location"]
            lines.append("Best Global Deployment Location:")
            lines.append(f"  Region:      {loc.get('region')}")
            lines.append(f"  VPC ID:      {loc.get('vpc_id')}")
            lines.append(f"  VPC CIDR:    {loc.get('vpc_cidr')}")
            lines.append(f"  Subnet ID:   {loc.get('subnet_id')}")
            lines.append(f"  Subnet CIDR: {loc.get('subnet_cidr')}")
            lines.append(f"  Public:      {'Yes' if loc.get('is_public_subnet') else 'No'}")
            lines.append(f"  Internet:    {'Yes' if loc.get('has_internet_access') else 'No'}")
            lines.append("")

        # Per-Region Deployment Table
        per_region = self.get_per_region_recommendations()
        if per_region:
            lines.append("-" * 80)
            lines.append("PER-REGION DEPLOYMENT RECOMMENDATIONS")
            lines.append("-" * 80)
            lines.append("")
            lines.append("Use this table when VPCs are isolated (no TGW/Peering between regions).")
            lines.append("Deploy one scanner instance in each region to reach all local instances.")
            lines.append("")

            # Table header
            header = f"{'Region':<20} {'Instances':<10} {'VPC ID':<25} {'Subnet ID':<27} {'CIDR':<18} {'Public':<8} {'Status':<10}"
            lines.append(header)
            lines.append("-" * len(header))

            for rec_item in per_region:
                region = rec_item.get("region", "N/A")
                inst_count = rec_item.get("instance_count", 0)
                vpc_id = rec_item.get("vpc_id", "N/A") or "N/A"
                subnet_id = rec_item.get("subnet_id", "N/A") or "N/A"
                subnet_cidr = rec_item.get("subnet_cidr", "N/A") or "N/A"
                is_public = "Yes" if rec_item.get("is_public") or rec_item.get("has_nat") else "No"
                status = rec_item.get("status", "N/A")

                # Truncate IDs for display
                vpc_short = vpc_id[-21:] if len(vpc_id) > 21 else vpc_id
                subnet_short = subnet_id[-24:] if len(subnet_id) > 24 else subnet_id

                line = f"{region:<20} {inst_count:<10} {vpc_short:<25} {subnet_short:<27} {subnet_cidr:<18} {is_public:<8} {status:<10}"
                lines.append(line)

            lines.append("")

            # Detailed per-region info
            lines.append("-" * 80)
            lines.append("DETAILED REGIONAL INFORMATION")
            lines.append("-" * 80)

            for rec_item in per_region:
                region = rec_item.get("region", "N/A")
                lines.append("")
                lines.append(f"=== {region} ===")
                lines.append(f"  Total Instances: {rec_item.get('instance_count', 0)}")
                lines.append(f"  Status: {rec_item.get('status', 'N/A')}")

                if rec_item.get("vpc_id"):
                    lines.append(f"  Recommended VPC: {rec_item.get('vpc_id')} ({rec_item.get('vpc_cidr')})")
                    lines.append(f"  Recommended Subnet: {rec_item.get('subnet_id')} ({rec_item.get('subnet_cidr')})")
                    if rec_item.get("subnet_az"):
                        lines.append(f"  Availability Zone: {rec_item.get('subnet_az')}")
                    lines.append(f"  Public Subnet: {'Yes' if rec_item.get('is_public') else 'No'}")
                    lines.append(f"  Has NAT: {'Yes' if rec_item.get('has_nat') else 'No'}")
                    lines.append(f"  Local Instances Reachable: {rec_item.get('local_reachable', 0)}/{rec_item.get('instance_count', 0)}")

                # List instances
                instances = rec_item.get("instances", [])
                if instances:
                    lines.append(f"  Instances ({len(instances)}):")
                    for inst in instances:
                        name = f" ({inst.get('name')})" if inst.get('name') else ""
                        reachable = " [REACHABLE]" if inst.get('reachable', True) else " [UNREACHABLE]"
                        lines.append(f"    - {inst.get('id')}{name}")
                        lines.append(f"      IP: {inst.get('ip', 'N/A')}, VPC: {inst.get('vpc', 'N/A')}{reachable}")

        # Unreachable instances details
        if rec.get("unreachable_count", 0) > 0:
            lines.append("")
            lines.append("-" * 80)
            lines.append(f"UNREACHABLE INSTANCES ({rec.get('unreachable_count', 0)})")
            lines.append("-" * 80)
            lines.append("These instances cannot be reached from the recommended deployment location.")
            lines.append("Deploy additional scanners in their respective regions/VPCs.")
            lines.append("")

            for inst in rec.get("unreachable_instances", []):
                name = f" ({inst.get('name')})" if inst.get('name') else ""
                lines.append(f"  - {inst.get('instance_id')}{name}")
                lines.append(f"    Region: {inst.get('region')}")
                lines.append(f"    VPC: {inst.get('vpc_id')}")
                lines.append(f"    IP: {inst.get('private_ip', 'N/A')}")
                lines.append("")

        # Footer
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        # Write to file
        with open(output_file, "w") as f:
            f.write("\n".join(lines))

        return output_file


class OrgNetworkAnalyzer:
    """
    Organization-wide network analyzer that aggregates data across all accounts
    to provide cross-account reachability analysis.
    
    Unlike single-account analysis, this considers:
    - Cross-account TGW connectivity
    - Cross-account VPC peering
    - Centralized deployment recommendations for the entire organization
    """
    
    # Parallel settings for org scanning
    MAX_PARALLEL_ACCOUNTS = 20  # Concurrent account scans
    MAX_PARALLEL_REGIONS_PER_ACCOUNT = 5  # Regions per account (reduced to avoid throttling)
    
    def __init__(self, management_session: boto3.Session, regions: List[str] = None, 
                 assume_role_name: str = DEFAULT_ASSUME_ROLE, max_parallel: int = MAX_PARALLEL_REGIONS,
                 max_parallel_accounts: int = None):
        self.management_session = management_session
        self.regions = regions or self._get_enabled_regions()
        self.assume_role_name = assume_role_name
        self.max_parallel = min(max_parallel, self.MAX_PARALLEL_REGIONS_PER_ACCOUNT)
        self.max_parallel_accounts = max_parallel_accounts or self.MAX_PARALLEL_ACCOUNTS
        
        # Aggregated data stores
        self._lock = threading.Lock()
        
        # Data indexed by account
        self.accounts: Dict[str, Dict] = {}  # account_id -> {name, status, error, ...}
        
        # Global aggregated data (prefixed with account_id for uniqueness)
        self.all_vpcs: Dict[str, VPCInfo] = {}  # "account_id:vpc_id" -> VPCInfo
        self.all_instances: Dict[str, EC2Instance] = {}  # instance_id -> EC2Instance (with account_id field)
        self.all_tgw_attachments: Dict[str, Dict] = {}  # attachment_id -> {account_id, ...}
        self.all_peerings: Dict[str, Dict] = {}  # pcx_id -> {requester_account, accepter_account, ...}
        
        # Cross-account connectivity graph
        self.cross_account_graph: Dict[str, Set[str]] = defaultdict(set)  # "account:vpc" -> set of "account:vpc"
        
        # Progress tracking
        self._completed_accounts = 0
        self._total_accounts = 0
        self._start_time = None
        
    def _get_enabled_regions(self) -> List[str]:
        """Get all enabled regions."""
        ec2 = self.management_session.client("ec2", region_name="us-east-1")
        return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
    
    def _assume_role(self, account_id: str) -> Optional[boto3.Session]:
        """Assume a role in the target account."""
        try:
            sts = self.management_session.client("sts")
            role_arn = f"arn:aws:iam::{account_id}:role/{self.assume_role_name}"
            
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"OrgNetworkAnalyzer-{account_id}"
            )
            
            credentials = response["Credentials"]
            return boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"]
            )
        except Exception as e:
            return None
    
    def _scan_single_account(self, acct: Dict) -> Tuple[str, Dict]:
        """
        Scan a single account. Returns (account_id, result_dict).
        Designed to be run in parallel.
        """
        acct_id = acct["Id"]
        acct_name = acct.get("Name", "Unknown")
        
        try:
            # Assume role into account
            session = self._assume_role(acct_id)
            if not session:
                return acct_id, {
                    "name": acct_name,
                    "status": "error",
                    "error": f"Could not assume role {self.assume_role_name}"
                }
            
            # Use AWSNetworkAnalyzer for this account with reduced parallelism
            analyzer = AWSNetworkAnalyzer(session, self.regions, max_parallel=self.max_parallel)
            analyzer.discover_all(quiet=True)
            
            # Generate report
            report = analyzer.generate_report()
            
            return acct_id, {
                "name": acct_name,
                "status": "success",
                "vpcs": len(analyzer.vpcs),
                "instances": len(analyzer.instances),
                "report": report,
                # Store raw data for aggregation
                "_vpcs": analyzer.vpcs,
                "_instances": analyzer.instances,
                "_tgw_attachments": analyzer.tgw_attachments,
                "_peerings": analyzer.peering_connections
            }
            
        except Exception as e:
            return acct_id, {
                "name": acct_name,
                "status": "error",
                "error": str(e)
            }
    
    def discover_organization(self, quiet: bool = False, max_accounts: int = None) -> Dict:
        """
        Discover all network infrastructure across all accounts in the organization.
        Uses parallel scanning for dramatically improved performance.
        
        Args:
            quiet: Suppress progress output
            max_accounts: Limit number of accounts to scan (for testing)
        
        Returns:
            Comprehensive cross-account network topology summary
        """
        self._start_time = time.time()
        
        # Get organization accounts
        org = self.management_session.client("organizations")
        org_info = org.describe_organization()["Organization"]
        org_id = org_info["Id"]
        
        accounts = []
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page["Accounts"])
        
        active_accounts = [a for a in accounts if a["Status"] == "ACTIVE"]
        
        # Optionally limit accounts for testing
        if max_accounts:
            active_accounts = active_accounts[:max_accounts]
        
        self._total_accounts = len(active_accounts)
        
        if not quiet:
            print(f"\nOrganization: {org_id}")
            print(f"Accounts to analyze: {len(active_accounts)}")
            print(f"Regions per account: {len(self.regions)}")
            print(f"Parallel accounts: {self.max_parallel_accounts}")
            print(f"Parallel regions/account: {self.max_parallel}")
            est_time = (len(active_accounts) / self.max_parallel_accounts) * 3  # ~3s per account batch
            print(f"Estimated time: {est_time/60:.1f} minutes")
        
        # Parallel account scanning
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_parallel_accounts) as executor:
            futures = {executor.submit(self._scan_single_account, acct): acct for acct in active_accounts}
            
            for future in as_completed(futures):
                acct_id, result = future.result()
                results[acct_id] = result
                
                # Update progress
                with self._lock:
                    self._completed_accounts += 1
                    
                if not quiet:
                    elapsed = time.time() - self._start_time
                    pct = (self._completed_accounts / self._total_accounts) * 100
                    rate = self._completed_accounts / elapsed if elapsed > 0 else 0
                    eta = (self._total_accounts - self._completed_accounts) / rate if rate > 0 else 0
                    
                    status = "✓" if result.get("status") == "success" else "✗"
                    sys.stderr.write(f"\r  [{self._completed_accounts}/{self._total_accounts}] "
                                   f"({pct:.0f}%) {status} {acct_id} | "
                                   f"{rate:.1f} acct/s | ETA: {eta:.0f}s   ")
                    sys.stderr.flush()
        
        if not quiet:
            elapsed = time.time() - self._start_time
            sys.stderr.write(f"\n  ✓ Completed {self._total_accounts} accounts in {elapsed:.1f}s "
                           f"({self._total_accounts/elapsed:.1f} acct/s)\n")
        
        # Aggregate results
        for acct_id, result in results.items():
            acct_name = result.get("name", "Unknown")
            
            if result.get("status") == "success":
                # Aggregate VPCs
                for vpc_id, vpc_info in result.get("_vpcs", {}).items():
                    key = f"{acct_id}:{vpc_id}"
                    vpc_info.account_id = acct_id
                    self.all_vpcs[key] = vpc_info
                
                # Aggregate instances
                for inst_id, inst in result.get("_instances", {}).items():
                    inst.account_id = acct_id
                    self.all_instances[inst_id] = inst
                
                # Aggregate TGW attachments
                for att_id, att in result.get("_tgw_attachments", {}).items():
                    att["account_id"] = acct_id
                    self.all_tgw_attachments[att_id] = att
                
                # Aggregate peering connections
                for pcx_id, pcx in result.get("_peerings", {}).items():
                    pcx["discovered_in_account"] = acct_id
                    self.all_peerings[pcx_id] = pcx
                
                # Store account result (without raw data)
                self.accounts[acct_id] = {
                    "name": acct_name,
                    "status": "success",
                    "vpcs": result.get("vpcs", 0),
                    "instances": result.get("instances", 0),
                    "report": result.get("report", {})
                }
            else:
                self.accounts[acct_id] = {
                    "name": acct_name,
                    "status": "error",
                    "error": result.get("error", "Unknown error")
                }
        
        # Build cross-account connectivity graph
        self._build_cross_account_connectivity()
        
        return {
            "org_id": org_id,
            "total_accounts": len(active_accounts),
            "successful_accounts": sum(1 for a in self.accounts.values() if a.get("status") == "success"),
            "total_vpcs": len(self.all_vpcs),
            "total_instances": len(self.all_instances)
        }
    
    def _build_cross_account_connectivity(self):
        """
        Build the cross-account connectivity graph considering:
        - Same VPC (always connected)
        - Same-account TGW connectivity
        - Cross-account TGW connectivity (shared TGWs via RAM)
        - Same-account VPC peering
        - Cross-account VPC peering
        """
        # Same VPC connectivity
        for key in self.all_vpcs:
            self.cross_account_graph[key].add(key)
        
        # TGW connectivity - VPCs connected to the same TGW can reach each other
        tgw_vpc_map = defaultdict(set)  # tgw_id -> set of "account:vpc"
        
        for att_id, att in self.all_tgw_attachments.items():
            if att.get("state") == "available" and att.get("resource_type") == "vpc":
                tgw_id = att["tgw_id"]
                account_id = att["account_id"]
                vpc_id = att["resource_id"]
                key = f"{account_id}:{vpc_id}"
                tgw_vpc_map[tgw_id].add(key)
        
        # Connect all VPCs on the same TGW (including cross-account)
        for tgw_id, vpc_keys in tgw_vpc_map.items():
            for key1 in vpc_keys:
                for key2 in vpc_keys:
                    if key1 != key2:
                        self.cross_account_graph[key1].add(key2)
        
        # VPC Peering connectivity
        for pcx_id, pcx in self.all_peerings.items():
            req_vpc = pcx.get("requester_vpc")
            req_acct = pcx.get("requester_owner_id", pcx.get("discovered_in_account"))
            acc_vpc = pcx.get("accepter_vpc")
            acc_acct = pcx.get("accepter_owner_id", pcx.get("discovered_in_account"))
            
            if req_vpc and acc_vpc and req_acct and acc_acct:
                key1 = f"{req_acct}:{req_vpc}"
                key2 = f"{acc_acct}:{acc_vpc}"
                self.cross_account_graph[key1].add(key2)
                self.cross_account_graph[key2].add(key1)
    
    def can_reach_cross_account(self, source_key: str, target_key: str) -> Tuple[bool, Optional[str]]:
        """
        Check if source VPC (account:vpc) can reach target VPC.
        Returns (reachable, path_type).
        """
        if source_key == target_key:
            return True, "same_vpc"
        
        if target_key in self.cross_account_graph.get(source_key, set()):
            # Determine path type
            source_acct, source_vpc = source_key.split(":", 1)
            target_acct, target_vpc = target_key.split(":", 1)
            
            if source_acct == target_acct:
                # Same account - check if TGW or peering
                source_info = self.all_vpcs.get(source_key)
                target_info = self.all_vpcs.get(target_key)
                
                if source_info and target_info:
                    if source_info.tgw_attachments and target_info.tgw_attachments:
                        if source_info.region != target_info.region:
                            return True, "inter_region_tgw"
                        return True, "tgw"
                    if source_info.peering_connections and target_info.peering_connections:
                        return True, "peering"
                
                return True, "same_account"
            else:
                # Cross-account connectivity
                return True, "cross_account"
        
        return False, None
    
    def analyze_org_deployment_location(self, account_id: str, vpc_id: str, subnet_id: str) -> Dict:
        """
        Analyze how many instances across the ENTIRE organization can be reached
        from a specific deployment location.
        """
        key = f"{account_id}:{vpc_id}"
        vpc_info = self.all_vpcs.get(key)
        
        if not vpc_info:
            return {
                "account_id": account_id,
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "error": "VPC not found"
            }
        
        subnet_info = vpc_info.subnets.get(subnet_id) if vpc_info else None
        
        result = {
            "account_id": account_id,
            "account_name": self.accounts.get(account_id, {}).get("name", "Unknown"),
            "vpc_id": vpc_id,
            "vpc_cidr": vpc_info.cidr,
            "subnet_id": subnet_id,
            "subnet_cidr": subnet_info.cidr if subnet_info else None,
            "region": vpc_info.region,
            "is_public": subnet_info.is_public if subnet_info else False,
            "has_internet": (subnet_info.is_public or subnet_info.has_nat) if subnet_info else False,
            "total_instances": len(self.all_instances),
            "reachable_instances": 0,
            "reachable_same_account": 0,
            "reachable_cross_account": 0,
            "reachable_by_account": {},
            "unreachable_instances": [],
            "coverage_percentage": 0.0
        }
        
        for inst_id, inst in self.all_instances.items():
            inst_account = getattr(inst, "account_id", "unknown")
            inst_vpc_key = f"{inst_account}:{inst.vpc_id}"
            
            reachable, path_type = self.can_reach_cross_account(key, inst_vpc_key)
            
            if reachable:
                result["reachable_instances"] += 1
                result["reachable_by_account"][inst_account] = result["reachable_by_account"].get(inst_account, 0) + 1
                
                if inst_account == account_id:
                    result["reachable_same_account"] += 1
                else:
                    result["reachable_cross_account"] += 1
            else:
                result["unreachable_instances"].append({
                    "instance_id": inst_id,
                    "account_id": inst_account,
                    "vpc_id": inst.vpc_id,
                    "region": inst.region,
                    "private_ip": inst.private_ip,
                    "name": inst.name
                })
        
        if result["total_instances"] > 0:
            result["coverage_percentage"] = (result["reachable_instances"] / result["total_instances"]) * 100
        
        return result
    
    def find_best_org_deployment_location(self, require_internet: bool = True, top_n: int = 5) -> List[Dict]:
        """
        Find the best deployment location across the ENTIRE organization.
        This is the key feature - finding a single location that can reach
        the most instances across all accounts.
        """
        candidates = []
        
        for key, vpc_info in self.all_vpcs.items():
            account_id, vpc_id = key.split(":", 1)
            
            for subnet_id, subnet_info in vpc_info.subnets.items():
                # Skip if we require internet and subnet doesn't have it
                if require_internet and not (subnet_info.is_public or subnet_info.has_nat):
                    continue
                
                result = self.analyze_org_deployment_location(account_id, vpc_id, subnet_id)
                candidates.append(result)
        
        # Sort by coverage percentage, then by cross-account reachability
        candidates.sort(key=lambda x: (
            -x["coverage_percentage"],
            -x["reachable_cross_account"],
            -x["reachable_instances"],
            not x.get("is_public", False)
        ))
        
        return candidates[:top_n]
    
    def find_full_coverage_deployments(self, require_internet: bool = True) -> List[Dict]:
        """
        Find the MINIMUM set of deployment locations needed to cover ALL instances
        across the entire organization. Uses a greedy set cover algorithm.
        
        This is similar to account mode's per-region recommendations - provides
        multiple deployment locations that together cover 100% of instances.
        
        Returns:
            List of deployment locations, each covering a subset of instances.
            Together they cover all instances in the organization.
        """
        if not self.all_instances:
            return []
        
        # Build a mapping of each candidate location to the set of instances it can reach
        candidates = {}  # (account_id, vpc_id, subnet_id) -> {"result": result, "instances": set()}
        
        for key, vpc_info in self.all_vpcs.items():
            account_id, vpc_id = key.split(":", 1)
            
            for subnet_id, subnet_info in vpc_info.subnets.items():
                # Skip if we require internet and subnet doesn't have it
                if require_internet and not (subnet_info.is_public or subnet_info.has_nat):
                    continue
                
                result = self.analyze_org_deployment_location(account_id, vpc_id, subnet_id)
                
                # Build set of reachable instance IDs
                all_instance_ids = set(self.all_instances.keys())
                unreachable_ids = set(u["instance_id"] for u in result.get("unreachable_instances", []))
                reachable_ids = all_instance_ids - unreachable_ids
                
                candidates[(account_id, vpc_id, subnet_id)] = {
                    "result": result,
                    "instances": reachable_ids
                }
        
        if not candidates:
            return []
        
        # Greedy set cover algorithm
        all_instances = set(self.all_instances.keys())
        uncovered = all_instances.copy()
        selected_deployments = []
        
        while uncovered:
            # Find the candidate that covers the most uncovered instances
            best_candidate = None
            best_coverage = set()
            best_key = None
            
            for key, data in candidates.items():
                # How many currently uncovered instances does this cover?
                newly_covered = data["instances"] & uncovered
                
                if len(newly_covered) > len(best_coverage):
                    best_coverage = newly_covered
                    best_candidate = data
                    best_key = key
            
            if not best_candidate or not best_coverage:
                # No candidate can cover any remaining instances - they're unreachable
                break
            
            # Add this deployment to our selection
            result = best_candidate["result"].copy()
            result["covers_instances"] = len(best_coverage)
            result["newly_covered_ids"] = list(best_coverage)[:20]  # Limit for readability
            result["deployment_order"] = len(selected_deployments) + 1
            
            # Add details of newly covered instances
            result["covered_instances_detail"] = []
            for inst_id in list(best_coverage)[:20]:
                inst = self.all_instances.get(inst_id)
                if inst:
                    result["covered_instances_detail"].append({
                        "instance_id": inst_id,
                        "account_id": getattr(inst, "account_id", "unknown"),
                        "name": inst.name,
                        "private_ip": inst.private_ip,
                        "region": inst.region
                    })
            
            selected_deployments.append(result)
            
            # Remove covered instances from uncovered set
            uncovered -= best_coverage
            
            # Remove this candidate so we don't select it again
            del candidates[best_key]
        
        # Calculate cumulative coverage for each deployment
        cumulative = 0
        for deploy in selected_deployments:
            cumulative += deploy["covers_instances"]
            deploy["cumulative_covered"] = cumulative
            deploy["cumulative_percentage"] = (cumulative / len(all_instances)) * 100
        
        # Add info about any remaining unreachable instances
        if uncovered:
            unreachable_details = []
            for inst_id in list(uncovered)[:50]:
                inst = self.all_instances.get(inst_id)
                if inst:
                    unreachable_details.append({
                        "instance_id": inst_id,
                        "account_id": getattr(inst, "account_id", "unknown"),
                        "vpc_id": inst.vpc_id,
                        "region": inst.region,
                        "name": inst.name,
                        "private_ip": inst.private_ip
                    })
            
            # Add metadata about unreachable instances to the last deployment
            if selected_deployments:
                selected_deployments[-1]["remaining_unreachable"] = len(uncovered)
                selected_deployments[-1]["unreachable_details"] = unreachable_details
        
        return selected_deployments
    
    def generate_org_report(self) -> Dict:
        """Generate comprehensive organization-wide reachability report."""
        best_locations = self.find_best_org_deployment_location(top_n=5)
        best = best_locations[0] if best_locations else None
        
        # Get full coverage deployments (multiple locations to cover ALL instances)
        full_coverage_deployments = self.find_full_coverage_deployments()
        
        # Calculate totals
        total_instances = len(self.all_instances)
        total_vpcs = len(self.all_vpcs)
        successful_accounts = sum(1 for a in self.accounts.values() if a.get("status") == "success")
        
        # Count cross-account connectivity
        cross_account_tgw_vpcs = 0
        cross_account_peering_vpcs = 0
        
        for key, connected in self.cross_account_graph.items():
            account_id = key.split(":")[0]
            for conn_key in connected:
                if conn_key != key:
                    conn_account = conn_key.split(":")[0]
                    if conn_account != account_id:
                        # Check if TGW or peering
                        vpc_info = self.all_vpcs.get(key)
                        if vpc_info and vpc_info.tgw_attachments:
                            cross_account_tgw_vpcs += 1
                        elif vpc_info and vpc_info.peering_connections:
                            cross_account_peering_vpcs += 1
                        break
        
        # Count same-account connectivity (VPCs with TGW or peering within same account)
        same_account_tgw_vpcs = sum(1 for v in self.all_vpcs.values() if v.tgw_attachments)
        same_account_peered_vpcs = sum(1 for v in self.all_vpcs.values() if v.peering_connections)
        isolated_vpcs = sum(1 for v in self.all_vpcs.values() 
                          if not v.tgw_attachments and not v.peering_connections)
        
        # Calculate full coverage summary
        full_coverage_total = sum(d.get("covers_instances", 0) for d in full_coverage_deployments)
        full_coverage_pct = (full_coverage_total / total_instances * 100) if total_instances > 0 else 0
        remaining_unreachable = total_instances - full_coverage_total
        
        report = {
            "mode": "organization",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_accounts_scanned": len(self.accounts),
                "successful_accounts": successful_accounts,
                "failed_accounts": len(self.accounts) - successful_accounts,
                "total_vpcs": total_vpcs,
                "total_instances": total_instances,
                "total_regions": len(self.regions),
                "global_reachability_possible": best["coverage_percentage"] == 100 if best else False,
                "best_coverage_percentage": best["coverage_percentage"] if best else 0,
                "deployments_for_full_coverage": len(full_coverage_deployments),
                "full_coverage_percentage": full_coverage_pct,
                "unreachable_instances": remaining_unreachable
            },
            "org_recommendation": None,
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": full_coverage_total,
                "coverage_percentage": full_coverage_pct,
                "unreachable_count": remaining_unreachable,
                "deployments": full_coverage_deployments
            },
            "top_deployment_locations": best_locations[:5],
            "per_account_summary": {},
            "connectivity_summary": {
                "cross_account_tgw_connected_vpcs": cross_account_tgw_vpcs // 2,  # Divide by 2 to avoid double counting
                "cross_account_peered_vpcs": cross_account_peering_vpcs // 2,
                "tgw_connected_vpcs": same_account_tgw_vpcs,
                "peered_vpcs": same_account_peered_vpcs,
                "isolated_vpcs": isolated_vpcs,
                "total_tgw_attachments": len(self.all_tgw_attachments),
                "total_peering_connections": len(self.all_peerings)
            },
            "accounts": {}
        }
        
        # Generate org-wide recommendation
        if best:
            report["org_recommendation"] = {
                "status": "SUCCESS" if best["coverage_percentage"] == 100 else "PARTIAL",
                "message": self._generate_org_recommendation_message(best),
                "deployment_location": {
                    "account_id": best["account_id"],
                    "account_name": best["account_name"],
                    "region": best["region"],
                    "vpc_id": best["vpc_id"],
                    "vpc_cidr": best["vpc_cidr"],
                    "subnet_id": best["subnet_id"],
                    "subnet_cidr": best["subnet_cidr"],
                    "is_public_subnet": best.get("is_public", False),
                    "has_internet_access": best.get("has_internet", False)
                },
                "coverage": {
                    "total_instances": best["total_instances"],
                    "reachable_instances": best["reachable_instances"],
                    "percentage": best["coverage_percentage"],
                    "reachable_same_account": best["reachable_same_account"],
                    "reachable_cross_account": best["reachable_cross_account"],
                    "reachable_by_account": best["reachable_by_account"]
                },
                "unreachable_instances": best["unreachable_instances"][:20],
                "unreachable_count": len(best["unreachable_instances"])
            }
        else:
            report["org_recommendation"] = {
                "status": "FAILED",
                "message": "No suitable deployment location found across the organization.",
                "deployment_location": None
            }
        
        # Add per-account details
        for acct_id, acct_data in self.accounts.items():
            if acct_data.get("status") == "success":
                acct_report = acct_data.get("report", {})
                report["accounts"][acct_id] = {
                    "name": acct_data.get("name"),
                    "status": "success",
                    "vpcs": acct_data.get("vpcs", 0),
                    "instances": acct_data.get("instances", 0),
                    "per_account_recommendation": acct_report.get("recommendation", {}),
                    "enhanced_report": acct_report
                }
            else:
                report["accounts"][acct_id] = {
                    "name": acct_data.get("name"),
                    "status": "error",
                    "error": acct_data.get("error", "Unknown error")
                }
        
        return report
    
    def _generate_org_recommendation_message(self, result: Dict) -> str:
        """Generate human-readable organization-wide recommendation message."""
        if result["coverage_percentage"] == 100:
            accounts_reached = len(result["reachable_by_account"])
            return (f"Deploy in account {result['account_id']} ({result['account_name']}), "
                   f"region {result['region']} to reach ALL {result['total_instances']} instances "
                   f"across {accounts_reached} accounts. "
                   f"({result['reachable_same_account']} same-account, "
                   f"{result['reachable_cross_account']} cross-account via TGW/peering)")
        else:
            return (f"Deploy in account {result['account_id']} ({result['account_name']}), "
                   f"region {result['region']} to reach {result['reachable_instances']}/{result['total_instances']} "
                   f"instances ({result['coverage_percentage']:.1f}% coverage). "
                   f"{len(result['unreachable_instances'])} instances in isolated VPCs cannot be reached.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AWS Network Reachability Analyzer - Find optimal EC2 deployment location"
    )
    parser.add_argument(
        "--mode",
        choices=["account", "org"],
        default="account",
        help="Analysis mode: single account or organization"
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions (default: all enabled regions)"
    )
    parser.add_argument(
        "--assume-role",
        default=DEFAULT_ASSUME_ROLE,
        help="IAM role to assume for org mode"
    )
    parser.add_argument(
        "--output",
        default="reachability_report.json",
        help="Output file for the report"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    return parser.parse_args()


def assume_role(account_id: str, role_name: str) -> boto3.Session:
    """Assume a role in another account."""
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="network-reachability")["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def print_summary(report: Dict, per_region_recs: Optional[List[Dict]] = None):
    """Print a formatted summary of the report."""
    print("\n" + "=" * 70)
    print("AWS NETWORK REACHABILITY ANALYSIS REPORT")
    print("=" * 70)

    summary = report["summary"]
    print(f"\nScanned: {summary['total_regions_scanned']} regions, "
          f"{summary['total_vpcs']} VPCs, {summary['total_instances']} EC2 instances")

    # Connectivity summary
    conn = report.get("connectivity_summary", {})
    print(f"\nConnectivity: {conn.get('tgw_connected_vpcs', 0)} TGW-connected, "
          f"{conn.get('peered_vpcs', 0)} Peered, {conn.get('isolated_vpcs', 0)} Isolated VPCs")

    rec = report["recommendation"]
    if rec:
        print(f"\n--- RECOMMENDATION ---")
        print(f"Status: {rec['status']}")
        print(f"{rec['message']}")

        if rec.get("deployment_location"):
            loc = rec["deployment_location"]
            print(f"\nBest Global Deploy Location:")
            print(f"  Region:     {loc['region']}")
            print(f"  VPC:        {loc['vpc_id']} ({loc['vpc_cidr']})")
            print(f"  Subnet:     {loc['subnet_id']} ({loc['subnet_cidr']})")
            print(f"  Public:     {'Yes' if loc['is_public_subnet'] else 'No'}")
            print(f"  Internet:   {'Yes' if loc['has_internet_access'] else 'No'}")

        if rec.get("coverage"):
            cov = rec["coverage"]
            print(f"\nCoverage:")
            print(f"  Reachable:  {cov['reachable_instances']}/{cov['total_instances']} ({cov['percentage']:.1f}%)")
            print(f"  In-Region:  {cov['reachable_in_same_region']}")
            print(f"  Cross-Region: {cov['reachable_cross_region']}")

    # Show per-region deployment table when coverage < 100%
    if per_region_recs and rec.get("coverage", {}).get("percentage", 0) < 100:
        print(f"\n--- PER-REGION DEPLOYMENT TABLE ---")
        print("(Use when VPCs are isolated - deploy one scanner per region)")
        print("")

        # Table header
        print(f"{'Region':<18} {'#Inst':<6} {'VPC':<24} {'Subnet':<26} {'CIDR':<16} {'Pub':<5} {'Status':<8}")
        print("-" * 110)

        for rec_item in per_region_recs:
            region = rec_item.get("region", "N/A")[:17]
            inst_count = rec_item.get("instance_count", 0)
            vpc_id = rec_item.get("vpc_id") or "N/A"
            subnet_id = rec_item.get("subnet_id") or "N/A"
            subnet_cidr = rec_item.get("subnet_cidr") or "N/A"
            is_public = "Yes" if rec_item.get("is_public") or rec_item.get("has_nat") else "No"
            status = rec_item.get("status", "N/A")

            # Truncate IDs for display
            vpc_short = vpc_id[-20:] if len(vpc_id) > 20 else vpc_id
            subnet_short = subnet_id[-23:] if len(subnet_id) > 23 else subnet_id

            print(f"{region:<18} {inst_count:<6} {vpc_short:<24} {subnet_short:<26} {subnet_cidr:<16} {is_public:<5} {status:<8}")

        print("")

    # Show unreachable instances
    if rec and rec.get("unreachable_count", 0) > 0:
        print(f"\n--- UNREACHABLE INSTANCES ({rec['unreachable_count']}) ---")
        for inst in rec.get("unreachable_instances", [])[:10]:
            name = f" ({inst.get('name')})" if inst.get('name') else ""
            print(f"  {inst['instance_id']}{name}")
            print(f"    Region: {inst['region']}, VPC: {inst['vpc_id']}, IP: {inst.get('private_ip', 'N/A')}")
        if rec["unreachable_count"] > 10:
            print(f"  ... and {rec['unreachable_count'] - 10} more (see text report for full list)")

    if rec and rec.get("issues"):
        print(f"\nPotential Issues:")
        for issue in rec["issues"]:
            print(f"  - {issue}")

    print("\n" + "=" * 70)


def main():
    args = parse_args()

    # Determine regions
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",")]
    else:
        regions = None  # Will discover all enabled regions

    if args.mode == "account":
        print("Starting AWS Network Reachability Analysis...")

        session = boto3.Session()
        account_id = boto3.client("sts").get_caller_identity()["Account"]
        print(f"Account: {account_id}")

        analyzer = AWSNetworkAnalyzer(session, regions)

        def progress(msg):
            print(f"  {msg}")

        print("\nDiscovering network infrastructure...")
        topology = analyzer.discover_all(progress_callback=progress)

        print(f"\nFound: {topology['total_vpcs']} VPCs, {topology['total_instances']} instances")

        print("\nAnalyzing reachability...")
        report = analyzer.generate_report()
        report["account_id"] = account_id

        # Get per-region recommendations
        per_region_recs = analyzer.get_per_region_recommendations()
        report["per_region_recommendations"] = per_region_recs

        # Print summary with per-region table
        print_summary(report, per_region_recs)

        # Save full JSON report
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nJSON report saved to: {args.output}")

        # Generate detailed text report
        txt_output = args.output.replace(".json", ".txt")
        analyzer.generate_text_report(report, txt_output)
        print(f"Text report saved to: {txt_output}")

    elif args.mode == "org":
        print("Organization mode - analyzing multiple accounts...")

        org = boto3.client("organizations")
        accounts = org.list_accounts()["Accounts"]

        org_report = {
            "mode": "organization",
            "generated_at": datetime.now().isoformat(),
            "accounts": {}
        }

        for acct in accounts:
            if acct["Status"] != "ACTIVE":
                continue

            acct_id = acct["Id"]
            print(f"\nAnalyzing account: {acct_id} ({acct.get('Name', 'Unknown')})...")

            try:
                session = assume_role(acct_id, args.assume_role)
                analyzer = AWSNetworkAnalyzer(session, regions)
                analyzer.discover_all()
                report = analyzer.generate_report()
                org_report["accounts"][acct_id] = report

                # Print brief summary
                rec = report.get("recommendation", {})
                coverage = rec.get("coverage", {}).get("percentage", 0)
                print(f"  Coverage: {coverage:.1f}%")

            except Exception as e:
                print(f"  Error: {e}")
                org_report["accounts"][acct_id] = {"error": str(e)}

        # Save org report
        with open(args.output, "w") as f:
            json.dump(org_report, f, indent=2, default=str)
        print(f"\nOrganization report saved to: {args.output}")


if __name__ == "__main__":
    main()
