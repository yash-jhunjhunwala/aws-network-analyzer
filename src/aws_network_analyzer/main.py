#!/usr/bin/env python3
"""
Multi-Cloud Network Reachability Analyzer

Finds the optimal VPC/VNet and subnet to deploy a VM that can reach
all other VMs. Supports AWS, Azure, and GCP clouds.

Usage:
    AWS Single Account:  python main.py --cloud aws --mode account --regions us-east-1,us-west-2
    AWS Organization:    python main.py --cloud aws --mode org
    Azure Subscription:  python main.py --cloud azure --mode account
    Azure Organization:  python main.py --cloud azure --mode org
    GCP Project:         python main.py --cloud gcp --mode account --project my-project
    GCP Organization:    python main.py --cloud gcp --mode org
"""
import boto3
import argparse
import json
import csv
import ipaddress
import sys
import signal
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from functools import wraps
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, ProfileNotFound

# Import enhanced features (lazy import for performance)
_html_report_module = None
_cache_module = None

def _get_html_report_module():
    """Lazy import of html_report module."""
    global _html_report_module
    if _html_report_module is None:
        try:
            from aws_network_analyzer.html_report import generate_html_report
            _html_report_module = generate_html_report
        except ImportError:
            from html_report import generate_html_report
            _html_report_module = generate_html_report
    return _html_report_module

def _get_cache_module():
    """Lazy import of cache module."""
    global _cache_module
    if _cache_module is None:
        try:
            from aws_network_analyzer import cache as cache_mod
            _cache_module = cache_mod
        except ImportError:
            import cache as cache_mod
            _cache_module = cache_mod
    return _cache_module

# Version - import from base module for single source of truth
from aws_network_analyzer.base import VERSION

# Exit codes
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1  # Partial coverage - some instances unreachable
EXIT_ERROR = 2    # Error during execution
EXIT_TIMEOUT = 3  # Timeout exceeded
EXIT_INTERRUPTED = 130  # Ctrl+C (128 + SIGINT)

DEFAULT_ASSUME_ROLE = "OrganizationAccountAccessRole"
MAX_PARALLEL_REGIONS = 10  # Limit concurrent API calls to avoid throttling
MAX_PARALLEL_ACCOUNTS = 20  # Limit concurrent account/subscription/project scans
EPHEMERAL_RANGE = (1024, 65535)
MAX_RETRIES = 3
BASE_DELAY = 1.0  # Base delay for exponential backoff
DEFAULT_TIMEOUT = 600  # 10 minutes default timeout

# Global shutdown flag for graceful termination
_shutdown_requested = False
_executor = None  # Reference to ThreadPoolExecutor for cleanup

# Configure logging
logger = logging.getLogger('aws_network_analyzer')


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logger.setLevel(level)
    logger.addHandler(console_handler)
    
    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")


def signal_handler(signum, frame):
    """Handle interrupt signals for graceful shutdown."""
    global _shutdown_requested, _executor
    
    signal_name = signal.Signals(signum).name
    logger.warning(f"\nReceived {signal_name}, initiating graceful shutdown...")
    _shutdown_requested = True
    
    # Cancel pending futures if executor exists
    if _executor:
        _executor.shutdown(wait=False, cancel_futures=True)
    
    print("\n⚠ Scan interrupted. Partial results may be available.", file=sys.stderr)
    sys.exit(EXIT_INTERRUPTED)


def check_shutdown():
    """Check if shutdown was requested and raise exception if so."""
    if _shutdown_requested:
        raise KeyboardInterrupt("Shutdown requested")


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
                    # Retry on throttling or transient errors
                    if error_code in ('RequestLimitExceeded', 'Throttling', 'ThrottlingException',
                                      'TooManyRequestsException', 'ServiceUnavailable',
                                      'InternalError', 'RequestTimeout'):
                        last_exception = e
                        delay = base_delay * (2 ** attempt)  # Exponential backoff
                        time.sleep(delay)
                    else:
                        raise  # Non-retryable error
                except EndpointConnectionError as e:
                    last_exception = e
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                except Exception:
                    raise  # Unknown errors should not be retried
            # All retries exhausted
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
        self.region_status = {}  # Track status per region
    
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
        
        # Use \r for in-place update
        sys.stderr.write(f"\r  [{bar}] {self.completed}/{self.total} ({pct:.0f}%) - {region} ({elapsed:.1f}s)")
        sys.stderr.flush()
        
        if self.completed == self.total:
            sys.stderr.write("\n")  # Newline when complete
    
    def message(self, msg: str):
        """Print a message (with newline handling)."""
        if not self.quiet:
            sys.stderr.write(f"\r{' ' * 80}\r")  # Clear line
            print(msg, file=sys.stderr)
    
    def finish(self):
        """Finalize progress indicator."""
        elapsed = time.time() - self.start_time
        if not self.quiet:
            sys.stderr.write(f"\r{' ' * 80}\r")  # Clear line
            print(f"  ✓ Completed {self.total} regions in {elapsed:.1f}s", file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Multi-Cloud Network Discovery & Reachability Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  AWS - Analyze single account, all regions:
    python main.py --cloud aws --mode account

  AWS - Analyze single account, specific regions:
    python main.py --cloud aws --mode account --regions us-east-1,us-west-2

  AWS - Analyze entire organization:
    python main.py --cloud aws --mode org --assume-role OrganizationAccountAccessRole

  Azure - Analyze single subscription:
    python main.py --cloud azure --mode account

  Azure - Analyze single subscription with explicit credentials:
    python main.py --cloud azure --mode account --tenant-id xxx --client-id xxx --client-secret xxx

  Azure - Analyze all subscriptions:
    python main.py --cloud azure --mode org

  GCP - Analyze single project:
    python main.py --cloud gcp --mode account --project my-project

  GCP - Analyze all accessible projects:
    python main.py --cloud gcp --mode org

  Save report to file:
    python main.py --cloud aws --mode account --output report.json

  Use specific AWS profile:
    python main.py --cloud aws --mode account --profile my-profile

  Use explicit AWS credentials:
    python main.py --cloud aws --mode account --access-key AKIA... --secret-key ...

  Export as CSV:
    python main.py --cloud aws --mode account --format csv --output report.csv

  Dry run (preview scan scope):
    python main.py --cloud aws --mode account --dry-run

AWS Authentication Priority:
  1. Explicit credentials (--access-key, --secret-key)
  2. AWS profile (--profile)
  3. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  4. IAM role (EC2 instance profile, ECS task role, etc.)
  5. Default credential chain (~/.aws/credentials)

Azure Authentication Priority:
  1. Explicit credentials (--tenant-id, --client-id, --client-secret)
  2. Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
  3. Azure CLI credentials
  4. Managed Identity

GCP Authentication Priority:
  1. Service account key file (--key-file)
  2. Environment variable (GOOGLE_APPLICATION_CREDENTIALS)
  3. Application Default Credentials (gcloud auth)
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], default="aws",
                        help="Cloud provider: aws, azure, or gcp (default: aws)")
    # Mode accepts cloud-specific aliases: AWS (account/org), Azure (subscription/tenant), GCP (project/org)
    parser.add_argument("--mode", choices=["account", "org", "subscription", "tenant", "project"], required=True,
                        help="Analysis mode: AWS (account/org), Azure (subscription/tenant), GCP (project/org)")
    parser.add_argument("--regions", help="Comma-separated regions (default: all enabled regions)")
    
    # AWS Credential options
    aws_cred_group = parser.add_argument_group('AWS Authentication', 'AWS credential options')
    aws_cred_group.add_argument("--profile", help="AWS profile name from ~/.aws/credentials or ~/.aws/config")
    aws_cred_group.add_argument("--access-key", dest="access_key",
                           help="AWS access key ID (use with --secret-key)")
    aws_cred_group.add_argument("--secret-key", dest="secret_key",
                           help="AWS secret access key (use with --access-key)")
    aws_cred_group.add_argument("--session-token", dest="session_token",
                           help="AWS session token for temporary credentials (optional, use with --access-key)")
    aws_cred_group.add_argument("--region", dest="default_region", default="us-east-1",
                           help="Default AWS region for API calls (default: us-east-1)")
    
    # Azure Credential options
    azure_cred_group = parser.add_argument_group('Azure Authentication', 'Azure credential options')
    azure_cred_group.add_argument("--tenant-id", dest="tenant_id",
                                  help="Azure tenant ID for service principal authentication")
    azure_cred_group.add_argument("--client-id", dest="client_id",
                                  help="Azure client/application ID for service principal authentication")
    azure_cred_group.add_argument("--client-secret", dest="client_secret",
                                  help="Azure client secret for service principal authentication")
    azure_cred_group.add_argument("--subscription-id", dest="subscription_id",
                                  help="Azure subscription ID (for subscription mode)")
    
    # GCP Credential options
    gcp_cred_group = parser.add_argument_group('GCP Authentication', 'GCP credential options')
    gcp_cred_group.add_argument("--project", dest="gcp_project",
                                help="GCP project ID (required for gcp --mode account)")
    gcp_cred_group.add_argument("--key-file", dest="key_file",
                                help="Path to GCP service account key JSON file")
    
    parser.add_argument("--assume-role", default=DEFAULT_ASSUME_ROLE,
                        help=f"IAM role to assume for AWS org mode (default: {DEFAULT_ASSUME_ROLE})")
    parser.add_argument("--output", default="reachability_report.json",
                        help="Output file for report (default: reachability_report.json)")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json",
                        help="Output format: json, csv, or html (default: json)")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed output, only show summary")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--log-file", help="Write logs to file")
    parser.add_argument("--parallel", type=int, default=MAX_PARALLEL_REGIONS,
                        help=f"Max parallel region scans (default: {MAX_PARALLEL_REGIONS})")
    parser.add_argument("--parallel-accounts", type=int, default=MAX_PARALLEL_ACCOUNTS,
                        help=f"Max parallel account scans for org mode (default: {MAX_PARALLEL_ACCOUNTS})")
    parser.add_argument("--max-accounts", type=int, default=None,
                        help="Limit number of accounts to scan in org mode (for testing)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Global timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview scan scope without executing (validates credentials and regions)")
    
    # Enhanced features
    enhanced_group = parser.add_argument_group('Enhanced Features', 'Caching and resume')
    enhanced_group.add_argument("--cache", action="store_true",
                                help="Cache discovery results to speed up re-runs")
    enhanced_group.add_argument("--cache-ttl", type=int, default=24,
                                help="Cache TTL in hours (default: 24)")
    enhanced_group.add_argument("--no-cache", action="store_true",
                                help="Ignore cached data and force fresh discovery")
    enhanced_group.add_argument("--resume", metavar="SCAN_ID",
                                help="Resume an interrupted organization scan by scan ID")
    enhanced_group.add_argument("--list-resumable", action="store_true",
                                help="List scans that can be resumed")
    
    args = parser.parse_args()
    
    # Normalize and validate mode based on cloud provider
    # Each cloud has specific terminology:
    # - AWS: account (single account), org (organization)
    # - Azure: subscription (single subscription), tenant (all subscriptions in tenant)
    # - GCP: project (single project), org (organization)
    mode_mapping = {
        "aws": {"account": "account", "org": "org"},
        "azure": {"subscription": "account", "tenant": "org"},
        "gcp": {"project": "account", "org": "org"}
    }
    
    valid_modes = {
        "aws": ["account", "org"],
        "azure": ["subscription", "tenant"],
        "gcp": ["project", "org"]
    }
    
    # Check if user used the correct mode for the cloud
    if args.mode not in mode_mapping.get(args.cloud, {}):
        parser.error(f"Invalid mode '{args.mode}' for {args.cloud}. Valid modes: {', '.join(valid_modes[args.cloud])}")
    
    # Store original mode for display purposes
    args.original_mode = args.mode
    
    # Normalize mode to internal representation (account/org)
    args.mode = mode_mapping[args.cloud][args.mode]
    
    # Validate AWS credential argument combinations
    if args.cloud == "aws":
        if args.access_key and not args.secret_key:
            parser.error("--access-key requires --secret-key")
        if args.secret_key and not args.access_key:
            parser.error("--secret-key requires --access-key")
        if args.session_token and not args.access_key:
            parser.error("--session-token requires --access-key and --secret-key")
        if args.access_key and args.profile:
            parser.error("Cannot use both --access-key and --profile. Choose one authentication method.")
    
    # Validate Azure credential argument combinations
    if args.cloud == "azure":
        # Service principal requires all three
        if args.client_id and not (args.tenant_id and args.client_secret):
            parser.error("Azure service principal requires --tenant-id, --client-id, and --client-secret")
        if args.client_secret and not (args.tenant_id and args.client_id):
            parser.error("Azure service principal requires --tenant-id, --client-id, and --client-secret")
    
    # Validate GCP credential argument combinations
    if args.cloud == "gcp":
        if args.mode == "account" and not args.gcp_project:
            parser.error("GCP project mode requires --project")
    
    return args


def create_session(args):
    """
    Create a boto3 session based on provided arguments.
    
    Priority:
    1. Explicit credentials (--access-key, --secret-key)
    2. AWS profile (--profile)
    3. Default credential chain (env vars, instance profile, etc.)
    """
    try:
        if args.access_key and args.secret_key:
            # Use explicit credentials
            logger.info("Using explicit AWS credentials")
            session_kwargs = {
                'aws_access_key_id': args.access_key,
                'aws_secret_access_key': args.secret_key,
                'region_name': args.default_region
            }
            if args.session_token:
                session_kwargs['aws_session_token'] = args.session_token
                logger.info("Using temporary credentials with session token")
            return boto3.Session(**session_kwargs), "explicit"
        
        elif args.profile:
            # Use named profile
            logger.info(f"Using AWS profile: {args.profile}")
            return boto3.Session(profile_name=args.profile), f"profile:{args.profile}"
        
        else:
            # Use default credential chain
            logger.info("Using default AWS credential chain")
            return boto3.Session(region_name=args.default_region), "default"
    
    except ProfileNotFound:
        raise ValueError(f"AWS profile '{args.profile}' not found in ~/.aws/credentials or ~/.aws/config")
    except Exception as e:
        raise ValueError(f"Failed to create AWS session: {e}")


def validate_credentials(session, profile_name=None):
    """
    Validate AWS credentials before starting scan.
    Returns (account_id, error_message) tuple.
    """
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        user_arn = identity["Arn"]
        logger.debug(f"Authenticated as: {user_arn}")
        return account_id, None
    except NoCredentialsError:
        return None, "No AWS credentials found. Configure credentials via AWS CLI, environment variables, or IAM role."
    except ProfileNotFound:
        return None, f"AWS profile '{profile_name}' not found in ~/.aws/credentials or ~/.aws/config"
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ExpiredToken':
            return None, "AWS session token has expired. Please refresh your credentials."
        elif error_code == 'InvalidClientTokenId':
            return None, "Invalid AWS access key. Please check your credentials."
        else:
            return None, f"AWS authentication failed: {e}"
    except Exception as e:
        return None, f"Failed to validate credentials: {e}"


def validate_regions(session, requested_regions):
    """
    Validate that requested regions exist and are enabled.
    Returns (valid_regions, invalid_regions) tuple.
    """
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        all_regions = {r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"]}
        enabled_regions = {r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]}
        
        valid = []
        invalid = []
        disabled = []
        
        for region in requested_regions:
            region = region.strip()
            if region not in all_regions:
                invalid.append(region)
            elif region not in enabled_regions:
                disabled.append(region)
            else:
                valid.append(region)
        
        return valid, invalid, disabled
    except Exception as e:
        logger.error(f"Failed to validate regions: {e}")
        return requested_regions, [], []  # Proceed with requested regions


def get_regions(session=None):
    """Get all enabled regions for the account."""
    if session:
        ec2 = session.client("ec2", region_name="us-east-1")
    else:
        ec2 = boto3.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]


def assume_role(account_id, role_name):
    """Assume IAM role in target account."""
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="network-discovery")["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


@retry_with_backoff()
def _api_describe_vpcs(ec2):
    return ec2.describe_vpcs()["Vpcs"]

@retry_with_backoff()
def _api_describe_igws(ec2):
    return ec2.describe_internet_gateways()["InternetGateways"]

@retry_with_backoff()
def _api_describe_peerings(ec2):
    return ec2.describe_vpc_peering_connections()["VpcPeeringConnections"]

@retry_with_backoff()
def _api_describe_tgws(ec2):
    return ec2.describe_transit_gateways()["TransitGateways"]

@retry_with_backoff()
def _api_describe_subnets(ec2, vpc_id):
    return ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]

@retry_with_backoff()
def _api_describe_route_tables(ec2, subnet_id):
    return ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["RouteTables"]

@retry_with_backoff()
def _api_describe_sgs(ec2, vpc_id):
    return ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]

@retry_with_backoff()
def _api_describe_nacls(ec2, vpc_id):
    return ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]

@retry_with_backoff()
def _api_describe_instances(ec2, vpc_id):
    return ec2.describe_instances(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "instance-state-name", "Values": ["running"]}
    ])["Reservations"]


def discover_region(session, region):
    """Discover all network resources in a region."""
    ec2 = session.client("ec2", region_name=region)
    result = {"vpcs": {}, "internet_vpcs": [], "tgw_present": False, "vpc_peering_present": False}

    vpcs = _api_describe_vpcs(ec2)
    igws = _api_describe_igws(ec2)
    peerings = _api_describe_peerings(ec2)
    tgws = _api_describe_tgws(ec2)

    result["tgw_present"] = len(tgws) > 0
    result["vpc_peering_present"] = len(peerings) > 0

    igw_vpcs = set()
    for igw in igws:
        for att in igw.get("Attachments", []):
            if "VpcId" in att:
                igw_vpcs.add(att["VpcId"])
    result["internet_vpcs"] = list(igw_vpcs)

    # VPCs
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        result["vpcs"][vpc_id] = {"cidr": vpc["CidrBlock"], "subnets": {}, "sgs": {}, "nacls": {}, "instances": {}}

        # Subnets + route tables
        subnets = _api_describe_subnets(ec2, vpc_id)
        for subnet in subnets:
            subnet_id = subnet["SubnetId"]
            rts = _api_describe_route_tables(ec2, subnet_id)
            has_internet_route = False
            routes_vpc_peering = []
            routes_tgw = []
            for rt in rts:
                for route in rt["Routes"]:
                    if route.get("DestinationCidrBlock") == "0.0.0.0/0" and "GatewayId" in route and route["GatewayId"].startswith("igw-"):
                        has_internet_route = True
                    if "VpcPeeringConnectionId" in route:
                        routes_vpc_peering.append(route["VpcPeeringConnectionId"])
                    if "TransitGatewayId" in route:
                        routes_tgw.append(route["TransitGatewayId"])
            result["vpcs"][vpc_id]["subnets"][subnet_id] = {
                "cidr": subnet["CidrBlock"],
                "public": has_internet_route,
                "peering_routes": routes_vpc_peering,
                "tgw_routes": routes_tgw
            }

        # Security Groups
        sgs = _api_describe_sgs(ec2, vpc_id)
        sg_valid = True
        sg_issues = []
        for sg in sgs:
            has_0_0_0_0 = False
            for rule in sg.get("IpPermissionsEgress", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        has_0_0_0_0 = True
            if not has_0_0_0_0:
                sg_valid = False
                sg_issues.append(f"SG {sg['GroupId']} outbound does not allow 0.0.0.0/0")
        result["vpcs"][vpc_id]["sgs"] = {"valid": sg_valid, "issues": sg_issues}

        # NACLs
        nacls = _api_describe_nacls(ec2, vpc_id)
        nacl_valid = True
        nacl_issues = []
        for nacl in nacls:
            allowed_ephemeral = False
            for entry in nacl.get("Entries", []):
                if entry.get("Egress") and entry.get("RuleAction") == "allow":
                    cidr = entry.get("CidrBlock")
                    port = entry.get("PortRange")
                    if cidr == "0.0.0.0/0":
                        if port:
                            from_p, to_p = port["From"], port["To"]
                            if from_p <= EPHEMERAL_RANGE[0] and to_p >= EPHEMERAL_RANGE[1]:
                                allowed_ephemeral = True
                        else:
                            allowed_ephemeral = True
            if not allowed_ephemeral:
                nacl_valid = False
                nacl_issues.append(f"NACL {nacl['NetworkAclId']} may block ephemeral ports")
        result["vpcs"][vpc_id]["nacls"] = {"valid": nacl_valid, "issues": nacl_issues}

        # EC2 instances (only running instances)
        instances = _api_describe_instances(ec2, vpc_id)
        for res in instances:
            for inst in res["Instances"]:
                instance_id = inst["InstanceId"]
                private_ips = [inst.get("PrivateIpAddress")] if inst.get("PrivateIpAddress") else []
                
                # Get instance name from tags
                instance_name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        instance_name = tag["Value"]
                        break
                
                result["vpcs"][vpc_id]["instances"][instance_id] = {
                    "name": instance_name,
                    "subnet_id": inst["SubnetId"],
                    "private_ips": private_ips,
                    "sg_ids": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                    "state": inst["State"]["Name"]
                }

    return result


def classify_environment(region_data):
    """Classify the network environment type."""
    if region_data["tgw_present"]:
        return "TGW_HUB"
    if region_data["vpc_peering_present"] and len(region_data["internet_vpcs"]) >= 1:
        return "VPC_HUB"
    if len(region_data["vpcs"]) > 1:
        return "FLAT"
    return "SINGLE_VPC"


def discover_account(session, regions, progress_callback=None, max_parallel=1, quiet=False):
    """Discover network resources across all specified regions."""
    account_result = {}
    all_cidrs = []
    result_lock = threading.Lock()
    
    # Initialize progress indicator
    progress = ProgressIndicator(len(regions), "Scanning regions", quiet=quiet)
    
    def discover_single_region(region):
        """Worker function for parallel discovery."""
        try:
            data = discover_region(session, region)
            env = classify_environment(data)
            return region, {"environment": env, **data}, None
        except Exception as e:
            return region, None, str(e)
    
    if max_parallel > 1 and len(regions) > 1:
        # Parallel execution
        with ThreadPoolExecutor(max_workers=min(max_parallel, len(regions))) as executor:
            futures = {executor.submit(discover_single_region, region): region for region in regions}
            
            for future in as_completed(futures):
                region, data, error = future.result()
                with result_lock:
                    if error:
                        account_result[region] = {"error": error}
                        progress.update(region, status="error")
                    else:
                        account_result[region] = data
                        for vpc in data["vpcs"].values():
                            all_cidrs.append(vpc["cidr"])
                        progress.update(region, status="done")
    else:
        # Sequential execution
        for region in regions:
            try:
                data = discover_region(session, region)
                env = classify_environment(data)
                account_result[region] = {"environment": env, **data}
                for vpc in data["vpcs"].values():
                    all_cidrs.append(vpc["cidr"])
                progress.update(region, status="done")
            except Exception as e:
                account_result[region] = {"error": str(e)}
                progress.update(region, status="error")
    
    progress.finish()
    return account_result, all_cidrs


def check_cidr_overlap(cidrs):
    """Check for overlapping CIDR blocks."""
    overlaps = []
    networks = [ipaddress.IPv4Network(c) for c in cidrs]
    for i, net1 in enumerate(networks):
        for j, net2 in enumerate(networks):
            if i >= j:
                continue
            if net1.overlaps(net2):
                overlaps.append((str(net1), str(net2)))
    return overlaps


def select_best_region(account_data):
    """Select the best region for deployment based on environment type."""
    for region, data in account_data.items():
        if data.get("environment") == "TGW_HUB":
            return region
    for region, data in account_data.items():
        if data.get("environment") == "SINGLE_VPC":
            return region
    for region, data in account_data.items():
        if data.get("environment") == "VPC_HUB":
            return region
    return None


def select_public_subnet(vpc_data):
    """Select a public subnet with IGW route, or fall back to any subnet."""
    # First, try to find a public subnet with IGW route
    for subnet_id, subnet in vpc_data.get("subnets", {}).items():
        if subnet.get("public"):
            return subnet_id
    # Fall back to any subnet if no public one found
    subnets = vpc_data.get("subnets", {})
    if subnets:
        return next(iter(subnets.keys()))
    return None


def static_reachability(instances, account_data, current_region, installer_ip="10.0.0.10"):
    """Analyze static reachability from a given region."""
    reach = {}
    for region, data in account_data.items():
        for vpc_id, vpc in data.get("vpcs", {}).items():
            for instance_id, inst in vpc.get("instances", {}).items():
                reachable = True
                # Same VPC/subnet check
                if region == current_region and vpc_id in data.get("internet_vpcs", []):
                    reachable = True
                else:
                    # Check VPC peering or TGW route
                    found_route = False
                    for subnet in vpc.get("subnets", {}).values():
                        if subnet.get("peering_routes") or subnet.get("tgw_routes"):
                            found_route = True
                    if not found_route:
                        reachable = False
                # SG/NACL check
                if not vpc.get("sgs", {}).get("valid", False):
                    reachable = False
                if not vpc.get("nacls", {}).get("valid", False):
                    reachable = False
                reach.setdefault(region, {})[instance_id] = "PASS" if reachable else "WARN"
    return reach


def generate_recommendation(account_data, all_cidrs):
    """Generate deployment recommendation based on network analysis."""
    best_region = select_best_region(account_data)
    overlaps = check_cidr_overlap(all_cidrs)

    if best_region:
        vpc_id = account_data[best_region]["internet_vpcs"][0] if account_data[best_region]["internet_vpcs"] else None
        vpc_data = account_data[best_region]["vpcs"].get(vpc_id, {})
        sg_valid = vpc_data.get("sgs", {}).get("valid", False)
        nacl_valid = vpc_data.get("nacls", {}).get("valid", False)
        subnet_id = select_public_subnet(vpc_data)
        reachability = static_reachability(vpc_data.get("instances", {}), account_data, best_region)
    else:
        vpc_id = None
        sg_valid = False
        nacl_valid = False
        subnet_id = None
        reachability = {}

    status = "FAIL" if not best_region else "WARN"
    explanation = f"Selected region {best_region}, VPC {vpc_id}, subnet {subnet_id}."
    if not sg_valid:
        explanation += " Warning: SG may block outbound internet."
    if not nacl_valid:
        explanation += " Warning: NACL may block ephemeral ports."
    if not subnet_id:
        explanation += " No public subnet with IGW route found."

    return {
        "status": status,
        "selected_region": best_region,
        "selected_vpc": vpc_id,
        "selected_subnet": subnet_id,
        "cidr_overlaps": overlaps,
        "sg_valid": sg_valid,
        "nacl_valid": nacl_valid,
        "explanation": explanation,
        "reachability": reachability
    }


def discover_org(regions, assume_role_name, progress_callback=None, max_parallel_accounts=MAX_PARALLEL_ACCOUNTS):
    """Discover network resources across all accounts in an organization using parallel execution."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    org = boto3.client("organizations")
    accounts = org.list_accounts()["Accounts"]
    active_accounts = [a for a in accounts if a["Status"] == "ACTIVE"]
    org_result = {}
    
    def analyze_account(acct):
        acct_id = acct["Id"]
        acct_name = acct.get("Name", "Unknown")
        if progress_callback:
            progress_callback(f"Analyzing account: {acct_id} ({acct_name})")
        try:
            session = assume_role(acct_id, assume_role_name)
            account_data, all_cidrs = discover_account(session, regions)
            recommendation = generate_recommendation(account_data, all_cidrs)
            return acct_id, {
                "name": acct_name,
                "discovery": account_data,
                "recommendation": recommendation
            }
        except Exception as e:
            return acct_id, {"name": acct_name, "error": str(e)}
    
    # Use parallel execution for accounts
    with ThreadPoolExecutor(max_workers=min(max_parallel_accounts, len(active_accounts))) as executor:
        futures = {executor.submit(analyze_account, acct): acct for acct in active_accounts}
        for future in as_completed(futures):
            acct_id, result = future.result()
            org_result[acct_id] = result
    
    return org_result


class OrgNetworkAnalyzer:
    """
    Organization-wide AWS Network Analyzer for cross-account analysis.
    
    This class discovers network resources across all accounts in an AWS Organization
    and provides recommendations for deploying scanner VMs with cross-account reach.
    """
    
    def __init__(self, management_session, regions, assume_role_name="OrganizationAccountAccessRole",
                 max_parallel=MAX_PARALLEL_REGIONS, max_parallel_accounts=MAX_PARALLEL_ACCOUNTS):
        """
        Initialize the organization analyzer.
        
        Args:
            management_session: Boto3 session for the management account
            regions: List of AWS regions to scan
            assume_role_name: IAM role name to assume in member accounts
            max_parallel: Max parallel region scans per account (default: 10)
            max_parallel_accounts: Max parallel account scans (default: 20)
        """
        self.session = management_session
        self.regions = regions
        self.assume_role_name = assume_role_name
        self.max_parallel = max_parallel
        self.max_parallel_accounts = max_parallel_accounts
        
        # Results storage
        self.accounts_data = {}
        self.org_id = None
        self.total_vpcs = 0
        self.total_instances = 0
        self.successful_accounts = 0
        self.failed_accounts = 0
        
    def discover_organization(self, quiet=False, max_accounts=None):
        """
        Discover network resources across all organization accounts.
        
        Args:
            quiet: Suppress progress output
            max_accounts: Limit number of accounts to scan (None = all)
            
        Returns:
            dict: Summary of discovery results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        # Get organization info
        org_client = self.session.client("organizations")
        
        try:
            org_info = org_client.describe_organization()
            self.org_id = org_info["Organization"]["Id"]
        except Exception as e:
            logger.warning(f"Could not get org ID: {e}")
            self.org_id = "unknown"
        
        # List all accounts
        accounts = []
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page["Accounts"])
        
        # Filter active accounts
        active_accounts = [a for a in accounts if a["Status"] == "ACTIVE"]
        
        if max_accounts:
            active_accounts = active_accounts[:max_accounts]
        
        if not quiet:
            print(f"\nDiscovering {len(active_accounts)} accounts with {self.max_parallel_accounts} parallel workers...")
        
        # Get management account ID once
        mgmt_account_id = self.session.client("sts").get_caller_identity()["Account"]
        
        # Thread-safe counters
        lock = threading.Lock()
        completed = [0]  # Use list for mutable counter
        
        def analyze_single_account(acct):
            """Analyze a single account - thread-safe."""
            acct_id = acct["Id"]
            acct_name = acct.get("Name", "Unknown")
            
            try:
                # Try to assume role in member account
                if acct_id == mgmt_account_id:
                    # This is the management account, use current session
                    account_session = self.session
                else:
                    account_session = assume_role(acct_id, self.assume_role_name)
                
                # Discover account resources
                account_data, all_cidrs = discover_account(
                    account_session, 
                    self.regions, 
                    max_parallel=self.max_parallel,
                    quiet=True
                )
                
                # Generate recommendation for this account
                recommendation = generate_recommendation(account_data, all_cidrs)
                
                # Count resources
                account_vpcs = 0
                account_instances = 0
                for region_data in account_data.values():
                    vpcs = region_data.get("vpcs", {})
                    account_vpcs += len(vpcs)
                    for vpc_data in vpcs.values():
                        account_instances += len(vpc_data.get("instances", {}))
                
                return acct_id, {
                    "name": acct_name,
                    "discovery": account_data,
                    "recommendation": recommendation,
                    "vpcs": account_vpcs,
                    "instances": account_instances,
                    "success": True
                }
                    
            except Exception as e:
                return acct_id, {
                    "name": acct_name,
                    "error": str(e),
                    "success": False
                }
        
        # Execute account analysis in parallel
        num_workers = min(self.max_parallel_accounts, len(active_accounts))
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(analyze_single_account, acct): acct for acct in active_accounts}
            
            for future in as_completed(futures):
                acct_id, result = future.result()
                
                with lock:
                    completed[0] += 1
                    self.accounts_data[acct_id] = result
                    
                    if result.get("success"):
                        self.total_vpcs += result.get("vpcs", 0)
                        self.total_instances += result.get("instances", 0)
                        self.successful_accounts += 1
                        if not quiet:
                            print(f"  [{completed[0]}/{len(active_accounts)}] ✓ {acct_id} ({result['name']}): {result['vpcs']} VPCs, {result['instances']} instances")
                    else:
                        self.failed_accounts += 1
                        if not quiet:
                            print(f"  [{completed[0]}/{len(active_accounts)}] ✗ {acct_id} ({result['name']}): {result.get('error', 'Unknown error')}")
        
        return {
            "org_id": self.org_id,
            "total_accounts": len(active_accounts),
            "successful_accounts": self.successful_accounts,
            "failed_accounts": self.failed_accounts,
            "total_vpcs": self.total_vpcs,
            "total_instances": self.total_instances
        }
    
    def generate_org_report(self):
        """
        Generate organization-wide report with cross-account analysis.
        
        Returns:
            dict: Complete organization report with recommendations
        """
        # Find best deployment location across all accounts
        best_location = None
        best_coverage = 0
        
        account_summaries = []
        
        for acct_id, acct_data in self.accounts_data.items():
            if "error" in acct_data:
                account_summaries.append({
                    "account_id": acct_id,
                    "account_name": acct_data.get("name", "Unknown"),
                    "status": "ERROR",
                    "error": acct_data["error"],
                    "vpcs": 0,
                    "instances": 0
                })
                continue
            
            rec = acct_data.get("recommendation", {})
            vpcs = acct_data.get("vpcs", 0)
            instances = acct_data.get("instances", 0)
            
            # Count reachable instances in this account
            reachability = rec.get("reachability", {})
            reachable_count = 0
            for region_reach in reachability.values():
                for inst_status in region_reach.values():
                    if inst_status in ["PASS", "WARN"]:
                        reachable_count += 1
            
            account_summaries.append({
                "account_id": acct_id,
                "account_name": acct_data.get("name", "Unknown"),
                "status": rec.get("status", "UNKNOWN"),
                "vpcs": vpcs,
                "instances": instances,
                "reachable_from_best": reachable_count,
                "selected_region": rec.get("selected_region"),
                "selected_vpc": rec.get("selected_vpc"),
                "selected_subnet": rec.get("selected_subnet")
            })
            
            # Track best overall location
            if reachable_count > best_coverage:
                best_coverage = reachable_count
                best_location = {
                    "account_id": acct_id,
                    "account_name": acct_data.get("name", "Unknown"),
                    "region": rec.get("selected_region"),
                    "vpc_id": rec.get("selected_vpc"),
                    "subnet_id": rec.get("selected_subnet"),
                    "vpc_cidr": "",
                    "subnet_cidr": "",
                    "is_public_subnet": True,
                    "has_internet_access": True
                }
        
        # Build full coverage plan (greedy algorithm for multiple deployments)
        full_coverage_deployments = []
        covered_instances = set()
        
        # Sort accounts by instances (most first) for greedy coverage
        sorted_accounts = sorted(
            [(aid, ad) for aid, ad in self.accounts_data.items() if "error" not in ad],
            key=lambda x: x[1].get("instances", 0),
            reverse=True
        )
        
        deployment_order = 0
        cumulative_covered = 0
        
        for acct_id, acct_data in sorted_accounts:
            instances = acct_data.get("instances", 0)
            if instances == 0:
                continue
                
            deployment_order += 1
            cumulative_covered += instances
            
            rec = acct_data.get("recommendation", {})
            
            # Get the selected VPC and extract CIDR info from discovery
            selected_region = rec.get("selected_region")
            selected_vpc = rec.get("selected_vpc")
            selected_subnet = rec.get("selected_subnet")
            vpc_cidr = ""
            subnet_cidr = ""
            
            # Extract VPC and subnet CIDR from discovery data
            discovery = acct_data.get("discovery", {})
            if selected_region and selected_vpc:
                region_data = discovery.get(selected_region, {})
                vpcs = region_data.get("vpcs", {})
                vpc_data = vpcs.get(selected_vpc, {})
                vpc_cidr = vpc_data.get("cidr", "")
                
                # Find subnet CIDR if subnet is selected
                if selected_subnet:
                    subnets = vpc_data.get("subnets", {})
                    subnet_data = subnets.get(selected_subnet, {})
                    subnet_cidr = subnet_data.get("cidr", "")
            
            # Extract instance details from discovery data
            covered_instances_detail = []
            for region, region_data in discovery.items():
                vpcs = region_data.get("vpcs", {})
                for vpc_id, vpc_data in vpcs.items():
                    instances_dict = vpc_data.get("instances", {})
                    for inst_id, inst_info in instances_dict.items():
                        # Get first private IP from the list
                        private_ips = inst_info.get("private_ips", [])
                        private_ip = private_ips[0] if private_ips else "N/A"
                        covered_instances_detail.append({
                            "instance_id": inst_id,
                            "name": inst_info.get("name", "N/A"),
                            "private_ip": private_ip,
                            "region": region,
                            "account_id": acct_id
                        })
            
            full_coverage_deployments.append({
                "deployment_order": deployment_order,
                "account_id": acct_id,
                "account_name": acct_data.get("name", "Unknown"),
                "region": selected_region,
                "vpc_id": selected_vpc,
                "vpc_cidr": vpc_cidr,
                "subnet_id": selected_subnet,
                "subnet_cidr": subnet_cidr,
                "is_public": True,
                "has_internet": True,
                "covers_instances": instances,
                "cumulative_covered": cumulative_covered,
                "cumulative_percentage": (cumulative_covered / self.total_instances * 100) if self.total_instances > 0 else 0,
                "newly_covered_ids": [inst["instance_id"] for inst in covered_instances_detail],
                "covered_instances_detail": covered_instances_detail
            })
        
        return {
            "mode": "org",
            "org_id": self.org_id,
            "accounts": account_summaries,
            "total_accounts": len(self.accounts_data),
            "successful_accounts": self.successful_accounts,
            "failed_accounts": self.failed_accounts,
            "total_vpcs": self.total_vpcs,
            "total_instances": self.total_instances,
            "org_recommendation": {
                "status": "SUCCESS" if best_coverage == self.total_instances else "PARTIAL",
                "message": f"Best single location can reach {best_coverage}/{self.total_instances} instances",
                "deployment_location": best_location,
                "coverage": {
                    "total_instances": self.total_instances,
                    "reachable_instances": best_coverage,
                    "percentage": (best_coverage / self.total_instances * 100) if self.total_instances > 0 else 0,
                    "reachable_same_account": best_coverage,
                    "reachable_cross_account": 0
                }
            },
            "full_coverage_plan": {
                "total_deployments_needed": len(full_coverage_deployments),
                "total_instances_covered": cumulative_covered,
                "coverage_percentage": (cumulative_covered / self.total_instances * 100) if self.total_instances > 0 else 0,
                "unreachable_count": self.total_instances - cumulative_covered,
                "deployments": full_coverage_deployments
            },
            "connectivity_summary": {
                "tgw_connected_vpcs": 0,
                "peered_vpcs": 0,
                "isolated_vpcs": self.total_vpcs,
                "cross_account_tgw_connected_vpcs": 0,
                "cross_account_peered_vpcs": 0,
                "total_tgw_attachments": 0,
                "total_peering_connections": 0
            },
            "generated_at": datetime.now().isoformat()
        }


def generate_multi_region_recommendation(report):
    """
    Generate multi-region deployment recommendations when single location
    cannot reach all instances.
    """
    regional = report.get("regional_analysis", {})
    total_instances = report.get("summary", {}).get("total_instances", 0)
    
    if total_instances == 0:
        return None
    
    # Check if single deployment can reach all
    rec = report.get("recommendation", {})
    cov = rec.get("coverage", {})
    if cov.get("percentage", 0) == 100:
        return None  # Single deployment is sufficient
    
    # Build list of regions with instances and their best deployment locations
    deployment_regions = []
    covered_instances = set()
    
    for region, data in regional.items():
        if data.get("status") == "no_vpcs":
            continue
        
        instances_in_region = data.get("total_instances_in_region", 0)
        if instances_in_region == 0:
            continue
        
        best = data.get("best_location", {})
        if not best:
            continue
        
        deployment_regions.append({
            "region": region,
            "instances_reachable": best.get("reachable_in_region", instances_in_region),
            "vpc_id": best.get("vpc_id"),
            "subnet_id": best.get("subnet_id"),
            "has_internet": best.get("has_internet_access", False),
            "coverage_in_region": instances_in_region
        })
    
    # Sort by number of instances reachable (descending)
    deployment_regions.sort(key=lambda x: x["instances_reachable"], reverse=True)
    
    # Greedy selection: pick regions until all instances are covered
    selected_regions = []
    remaining_instances = total_instances
    
    for dep in deployment_regions:
        if remaining_instances <= 0:
            break
        selected_regions.append(dep)
        remaining_instances -= dep["instances_reachable"]
    
    return {
        "multi_region_required": True,
        "reason": "Instances are distributed across isolated VPCs in multiple regions with no TGW or VPC peering connectivity.",
        "total_deployments_needed": len(selected_regions),
        "total_instances": total_instances,
        "deployment_locations": selected_regions
    }


def format_reachability_summary(report):
    """Format the reachability summary and return as string."""
    lines = []
    
    lines.append("")
    lines.append("=" * 70)
    lines.append("AWS NETWORK REACHABILITY ANALYSIS")
    lines.append("=" * 70)

    summary = report.get("summary", {})
    total_instances = summary.get('total_instances', 0)
    lines.append(f"\nScanned: {summary.get('total_regions_scanned', 0)} regions, "
                 f"{summary.get('total_vpcs', 0)} VPCs, {total_instances} EC2 instances")

    # Display full coverage plan first (similar to org mode)
    full_cov_plan = report.get("full_coverage_plan", {})
    full_cov_deployments = full_cov_plan.get("deployments", [])
    
    if full_cov_deployments and total_instances > 0:
        total_deploy = full_cov_plan.get("total_deployments_needed", 0)
        total_covered = full_cov_plan.get("total_instances_covered", 0)
        cov_pct = full_cov_plan.get("coverage_percentage", 0)
        unreachable = full_cov_plan.get("unreachable_count", 0)
        
        lines.append(f"\n{'=' * 70}")
        lines.append(f"📋 FULL COVERAGE PLAN: {total_deploy} DEPLOYMENT{'S' if total_deploy != 1 else ''} NEEDED")
        lines.append(f"{'=' * 70}")
        
        if cov_pct == 100:
            lines.append(f"✅ Deploy in these {total_deploy} locations to reach ALL {total_covered} instances:")
        else:
            lines.append(f"⚠️  Deploy in these {total_deploy} locations to reach {total_covered}/{total_instances} instances ({cov_pct:.1f}%):")
            lines.append(f"   ({unreachable} instances in isolated VPCs cannot be reached)")
        
        for deploy in full_cov_deployments:
            order = deploy.get("deployment_order", 0)
            covers = deploy.get("covers_instances", 0)
            cumulative = deploy.get("cumulative_covered", 0)
            cum_pct = deploy.get("cumulative_percentage", 0)
            
            lines.append(f"\n   #{order}. {deploy.get('region')}")
            lines.append(f"       VPC:    {deploy.get('vpc_id')} ({deploy.get('vpc_cidr')})")
            lines.append(f"       Subnet: {deploy.get('subnet_id')}")
            lines.append(f"       Type:   {'Public' if deploy.get('is_public') else 'Private'} | "
                        f"Internet: {'Yes' if deploy.get('has_internet') else 'No'}")
            lines.append(f"       ➜ Covers: +{covers} instances (cumulative: {cumulative}/{total_instances} = {cum_pct:.0f}%)")
        
        lines.append("")

    rec = report.get("recommendation")
    if rec:
        lines.append(f"{'=' * 70}")
        lines.append(f"🎯 BEST SINGLE LOCATION: {rec.get('status', 'UNKNOWN')}")
        lines.append(f"{'=' * 70}")
        lines.append(f"{rec.get('message', 'No recommendation available')}")

        loc = rec.get("deployment_location")
        if loc:
            lines.append(f"\n>> BEST SINGLE DEPLOYMENT LOCATION:")
            lines.append(f"   Region:  {loc.get('region')}")
            lines.append(f"   VPC:     {loc.get('vpc_id')} ({loc.get('vpc_cidr')})")
            lines.append(f"   Subnet:  {loc.get('subnet_id')} ({loc.get('subnet_cidr')})")
            lines.append(f"   Type:    {'Public (has IGW)' if loc.get('is_public_subnet') else 'Private'}")
            lines.append(f"   Internet: {'Yes' if loc.get('has_internet_access') else 'No'}")

        cov = rec.get("coverage")
        if cov:
            lines.append(f"\n>> COVERAGE FROM THIS LOCATION:")
            lines.append(f"   Reachable: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                         f"({cov.get('percentage', 0):.1f}%)")
            lines.append(f"   Same Region: {cov.get('reachable_in_same_region', 0)}")
            lines.append(f"   Cross-Region: {cov.get('reachable_cross_region', 0)}")

    # Connectivity summary
    conn = report.get("connectivity_summary", {})
    if conn:
        lines.append(f"\n>> CONNECTIVITY:")
        lines.append(f"   TGW-connected VPCs: {conn.get('tgw_connected_vpcs', 0)}")
        lines.append(f"   Peered VPCs: {conn.get('peered_vpcs', 0)}")
        lines.append(f"   Isolated VPCs: {conn.get('isolated_vpcs', 0)}")
        if conn.get('total_tgw_attachments'):
            lines.append(f"   Total TGW Attachments: {conn.get('total_tgw_attachments', 0)}")
        if conn.get('total_peering_connections'):
            lines.append(f"   Total Peering Connections: {conn.get('total_peering_connections', 0)}")

    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def print_reachability_summary(report):
    """Print a formatted summary of reachability analysis."""
    summary_text = format_reachability_summary(report)
    print(summary_text)
    return summary_text


def export_to_csv(result, output_file):
    """Export results to CSV format with proper reachability data."""
    csv_rows = []
    
    # Extract data from the report
    enhanced = result.get("enhanced_report", {})
    discovery = result.get("discovery", {})
    recommendation = enhanced.get("recommendation", {})
    
    # Build a set of unreachable instance IDs for quick lookup
    unreachable_ids = set()
    for inst in recommendation.get("unreachable_instances", []):
        unreachable_ids.add(inst.get("instance_id"))
    
    # Get the recommended deployment location
    deploy_loc = recommendation.get("deployment_location", {})
    deploy_region = deploy_loc.get("region", "")
    deploy_vpc = deploy_loc.get("vpc_id", "")
    
    # Build CSV rows from discovery data with reachability info
    for region, region_data in discovery.items():
        if "error" in region_data or not isinstance(region_data, dict):
            continue
        
        for vpc_id, vpc_data in region_data.get("vpcs", {}).items():
            # Determine VPC connectivity type
            has_tgw = bool(vpc_data.get("subnets", {}) and 
                         any(s.get("tgw_routes") for s in vpc_data.get("subnets", {}).values()))
            has_peering = bool(vpc_data.get("subnets", {}) and 
                              any(s.get("peering_routes") for s in vpc_data.get("subnets", {}).values()))
            
            if has_tgw:
                connectivity = "tgw"
            elif has_peering:
                connectivity = "peering"
            elif region == deploy_region and vpc_id == deploy_vpc:
                connectivity = "same_vpc"
            elif region == deploy_region:
                connectivity = "same_region"
            else:
                connectivity = "isolated"
            
            for instance_id, inst_data in vpc_data.get("instances", {}).items():
                # Determine reachability
                is_reachable = instance_id not in unreachable_ids
                
                # For instances in deployment VPC, they're always reachable
                if region == deploy_region and vpc_id == deploy_vpc:
                    is_reachable = True
                    connectivity = "same_vpc"
                
                row = {
                    "region": region,
                    "vpc_id": vpc_id,
                    "subnet_id": inst_data.get("subnet_id", ""),
                    "instance_id": instance_id,
                    "instance_name": inst_data.get("name", ""),
                    "private_ip": inst_data.get("private_ips", [""])[0] if inst_data.get("private_ips") else "",
                    "state": inst_data.get("state", "running"),
                    "reachable_from_primary": "Yes" if is_reachable else "No",
                    "connectivity_type": connectivity
                }
                csv_rows.append(row)
    
    # Write CSV
    if csv_rows:
        # Sort by region, then vpc, then instance_id
        csv_rows.sort(key=lambda x: (x["region"], x["vpc_id"], x["instance_id"]))
        
        fieldnames = ["region", "vpc_id", "subnet_id", "instance_id", "instance_name", 
                     "private_ip", "state", "reachable_from_primary", "connectivity_type"]
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        logger.info(f"CSV exported: {output_file} ({len(csv_rows)} instances)")
    else:
        # Write summary CSV if no instances
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])
            writer.writerow(["account_id", result.get("account_id", "")])
            writer.writerow(["total_regions", enhanced.get("summary", {}).get("total_regions_scanned", 0)])
            writer.writerow(["total_vpcs", enhanced.get("summary", {}).get("total_vpcs", 0)])
            writer.writerow(["total_instances", enhanced.get("summary", {}).get("total_instances", 0)])
            writer.writerow(["recommendation_status", recommendation.get("status", "")])
            if recommendation.get("deployment_location"):
                loc = recommendation["deployment_location"]
                writer.writerow(["recommended_region", loc.get("region", "")])
                writer.writerow(["recommended_vpc", loc.get("vpc_id", "")])
                writer.writerow(["recommended_subnet", loc.get("subnet_id", "")])
        logger.info(f"CSV summary exported: {output_file}")


# =============================================================================
# DEPRECATED: Legacy HTML export functions (kept for backward compatibility)
# Use generate_html_report() from html_report.py for single account/subscription/project
# Use export_org_to_html_unified() for org/tenant mode
# =============================================================================

def export_to_html(result, output_file):
    """Export results to a beautiful HTML report."""
    enhanced = result.get("enhanced_report", {})
    discovery = result.get("discovery", {})
    recommendation = enhanced.get("recommendation", {})
    summary = enhanced.get("summary", {})
    
    # Build instance data
    instances = []
    unreachable_ids = {inst.get("instance_id") for inst in recommendation.get("unreachable_instances", [])}
    deploy_loc = recommendation.get("deployment_location") or {}
    deploy_region = deploy_loc.get("region", "")
    deploy_vpc = deploy_loc.get("vpc_id", "")
    
    for region, region_data in discovery.items():
        if "error" in region_data or not isinstance(region_data, dict):
            continue
        for vpc_id, vpc_data in region_data.get("vpcs", {}).items():
            for instance_id, inst_data in vpc_data.get("instances", {}).items():
                is_reachable = instance_id not in unreachable_ids
                if region == deploy_region and vpc_id == deploy_vpc:
                    is_reachable = True
                instances.append({
                    "region": region,
                    "vpc_id": vpc_id,
                    "instance_id": instance_id,
                    "name": inst_data.get("name", ""),
                    "private_ip": inst_data.get("private_ips", [""])[0] if inst_data.get("private_ips") else "",
                    "reachable": is_reachable
                })
    
    # Sort instances
    instances.sort(key=lambda x: (x["region"], x["vpc_id"], x["instance_id"]))
    
    # Calculate stats
    total = len(instances)
    reachable = sum(1 for i in instances if i["reachable"])
    unreachable = total - reachable
    coverage_pct = (reachable / total * 100) if total > 0 else 0
    
    # Status badge color
    status = recommendation.get("status", "UNKNOWN")
    if status == "SUCCESS":
        status_color = "#10b981"
        status_bg = "#d1fae5"
    elif status == "PARTIAL":
        status_color = "#f59e0b"
        status_bg = "#fef3c7"
    else:
        status_color = "#ef4444"
        status_bg = "#fee2e2"
    
    # Build regional breakdown
    regional = enhanced.get("regional_analysis", {})
    region_rows = []
    for region, data in sorted(regional.items()):
        if data.get("total_instances_in_region", 0) > 0:
            best = data.get("best_location", {})
            coverage = best.get("coverage_percentage", 0) if best else 0
            region_rows.append(f'''
                <tr>
                    <td>{region}</td>
                    <td>{data.get("total_instances_in_region", 0)}</td>
                    <td>{data.get("total_vpcs", 0)}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {coverage}%; background: {'#10b981' if coverage == 100 else '#f59e0b' if coverage > 0 else '#ef4444'}"></div>
                        </div>
                        <span class="progress-text">{coverage:.0f}%</span>
                    </td>
                </tr>
            ''')
    
    # Get the full coverage plan for deployment recommendations
    full_coverage = enhanced.get("full_coverage_plan", {})
    deployments = full_coverage.get("deployments", [])
    
    # Multi-region deployment section - show each deployment with its instances
    
    # Build a map of instance details by instance_id for quick lookup
    instance_details_map = {inst["instance_id"]: inst for inst in instances}
    
    # Only show if multiple deployments are needed (partial coverage situation)
    if len(deployments) > 1:
        deployment_cards = ""
        total_instances = full_coverage.get("total_instances_covered", 0) + full_coverage.get("unreachable_count", 0)
        
        for i, dep in enumerate(deployments):
            covers = dep.get("covers_instances", 0)
            cumulative_pct = dep.get("cumulative_percentage", 0)
            has_internet = dep.get("has_internet", False)
            newly_covered_ids = dep.get("newly_covered_ids", [])
            
            # Build instance rows for this deployment
            dep_instance_rows = ""
            for inst_id in newly_covered_ids:
                inst = instance_details_map.get(inst_id, {})
                if inst:
                    dep_instance_rows += f'''
                        <tr>
                            <td><code>{inst.get("instance_id", "")}</code></td>
                            <td>{inst.get("name", "") or "<em>No name</em>"}</td>
                            <td><code>{inst.get("private_ip", "")}</code></td>
                            <td><code>{inst.get("vpc_id", "")}</code></td>
                        </tr>
                    '''
            
            deployment_cards += f'''
            <div class="deployment-card" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
                <h3 style="color: #1e3a5f; margin-bottom: 15px;">🎯 Deployment #{i+1}: {dep.get("region", "")}</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px;">
                    <div><strong>VPC:</strong> <code>{dep.get("vpc_id", "")}</code></div>
                    <div><strong>VPC CIDR:</strong> {dep.get("vpc_cidr", "")}</div>
                    <div><strong>Subnet:</strong> <code>{dep.get("subnet_id", "")}</code></div>
                    <div><strong>Subnet CIDR:</strong> {dep.get("subnet_cidr", "") or "N/A"}</div>
                    <div><strong>Internet Access:</strong> {"✓ Yes" if has_internet else "✗ No"}</div>
                    <div><strong>Instances Covered:</strong> {covers} ({cumulative_pct:.0f}% cumulative)</div>
                </div>
                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; font-weight: 600; color: #2563eb;">View {len(newly_covered_ids)} Instance(s) Covered</summary>
                    <table style="margin-top: 10px; width: 100%;">
                        <thead>
                            <tr>
                                <th>Instance ID</th>
                                <th>Name</th>
                                <th>Private IP</th>
                                <th>VPC</th>
                            </tr>
                        </thead>
                        <tbody>
                            {dep_instance_rows if dep_instance_rows else '<tr><td colspan="4">No instances</td></tr>'}
                        </tbody>
                    </table>
                </details>
            </div>
            '''
        
        multi_region_html = f'''
        <div class="card warning">
            <h2>⚠️ Multi-Region Deployment Required</h2>
            <p style="margin-bottom: 15px;">Instances are distributed across isolated VPCs in multiple regions with no TGW or VPC peering connectivity.</p>
            <p style="margin-bottom: 20px;">To reach all <strong>{total_instances}</strong> instances, 
               deploy scanners in <strong>{len(deployments)}</strong> locations:</p>
            {deployment_cards}
        </div>
        '''
    
    # Build HTML
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Network Reachability Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f3f4f6;
            color: #1f2937;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header-meta {{ opacity: 0.9; font-size: 14px; }}
        .stats-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #1e3a5f; }}
        .stat-label {{ color: #6b7280; font-size: 14px; margin-top: 5px; }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .card h2 {{ margin-bottom: 15px; color: #1e3a5f; font-size: 20px; }}
        .card.warning {{ border-left: 4px solid #f59e0b; }}
        .card.success {{ border-left: 4px solid #10b981; }}
        .status-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            background: {status_bg};
            color: {status_color};
        }}
        .recommendation-box {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-top: 15px;
        }}
        .recommendation-box h3 {{ color: #1e3a5f; margin-bottom: 10px; }}
        .recommendation-box code {{ 
            background: #e2e8f0; 
            padding: 2px 6px; 
            border-radius: 4px;
            font-size: 13px;
        }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; color: #374151; }}
        tr:hover {{ background: #f9fafb; }}
        code {{ font-family: 'Monaco', 'Consolas', monospace; font-size: 12px; }}
        .status-yes {{ color: #10b981; font-weight: 600; }}
        .status-no {{ color: #ef4444; font-weight: 600; }}
        .progress-bar {{ 
            width: 100px; 
            height: 8px; 
            background: #e5e7eb; 
            border-radius: 4px; 
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
        }}
        .progress-fill {{ height: 100%; border-radius: 4px; }}
        .progress-text {{ margin-left: 8px; font-size: 13px; }}
        .footer {{ 
            text-align: center; 
            color: #9ca3af; 
            font-size: 12px; 
            margin-top: 30px;
            padding: 20px;
        }}
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            table {{ font-size: 14px; }}
            th, td {{ padding: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AWS Network Reachability Report</h1>
            <div class="header-meta">
                Account: <strong>{result.get("account_id", "N/A")}</strong> | 
                Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong> |
                Version: <strong>{VERSION}</strong>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{summary.get("total_regions_scanned", 0)}</div>
                <div class="stat-label">Regions Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{summary.get("total_vpcs", 0)}</div>
                <div class="stat-label">VPCs Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total}</div>
                <div class="stat-label">EC2 Instances</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {'#10b981' if coverage_pct == 100 else '#f59e0b'}">{coverage_pct:.0f}%</div>
                <div class="stat-label">Coverage</div>
            </div>
        </div>
        
        {multi_region_html}
        
        <div class="footer">
            Generated by AWS Network Reachability Analyzer v{VERSION}<br>
            <a href="https://github.com/your-org/aws-network-analyzer" style="color: #6b7280;">Documentation</a>
        </div>
    </div>
</body>
</html>'''
    
    with open(output_file, 'w') as f:
        f.write(html)
    logger.info(f"HTML report exported: {output_file}")


def export_org_to_html(org_result, output_file):
    """Export organization results to a beautiful HTML report with cross-account analysis."""
    org_id = org_result.get("org_id", "N/A")
    accounts_raw = org_result.get("accounts", [])
    org_rec = org_result.get("org_recommendation", {})
    summary = org_result.get("summary", {})
    conn_summary = org_result.get("connectivity_summary", {})
    
    # Normalize accounts to dict format if it's a list
    if isinstance(accounts_raw, list):
        accounts = {a.get("account_id", str(i)): a for i, a in enumerate(accounts_raw)}
    else:
        accounts = accounts_raw
    
    # Calculate totals
    total_accounts = summary.get("total_accounts_scanned", len(accounts))
    successful = summary.get("successful_accounts", sum(1 for a in accounts.values() if a.get("status") != "error" and not a.get("error")))
    failed = summary.get("failed_accounts", total_accounts - successful)
    total_instances = summary.get("total_instances", org_result.get("total_instances", 0))
    total_vpcs = summary.get("total_vpcs", org_result.get("total_vpcs", 0))
    
    # Organization-wide recommendation details
    org_status = org_rec.get("status", "UNKNOWN")
    org_coverage = org_rec.get("coverage", {})
    org_deploy = org_rec.get("deployment_location", {})
    overall_coverage = org_coverage.get("percentage", 0)
    org_cov_color = "#10b981" if overall_coverage == 100 else "#f59e0b" if overall_coverage > 0 else "#ef4444"
    
    # Build account rows
    account_rows = []
    org_reachable_by_account = org_coverage.get("reachable_by_account", {})
    
    for acct_id, acct_data in sorted(accounts.items()):
        # Get account name - handle both 'name' and 'account_name' fields
        acct_name = acct_data.get("account_name", acct_data.get("name", "Unknown"))
        
        if acct_data.get("status") == "error" or acct_data.get("error"):
            account_rows.append(f'''
                <tr class="error-row">
                    <td><code>{acct_id}</code></td>
                    <td>{acct_name}</td>
                    <td><span class="status-badge error">ERROR</span></td>
                    <td colspan="5">{acct_data.get("error", "Unknown error")}</td>
                </tr>
            ''')
        else:
            # Per-account recommendation (individual account analysis)
            per_acct_rec = acct_data.get("per_account_recommendation", acct_data.get("recommendation", {}))
            per_acct_cov = per_acct_rec.get("coverage", {})
            per_acct_status = acct_data.get("status", per_acct_rec.get("status", "UNKNOWN"))
            per_acct_deploy = per_acct_rec.get("deployment_location", {})
            
            instances = acct_data.get("instances", 0)
            vpcs = acct_data.get("vpcs", 0)
            per_acct_pct = per_acct_cov.get("percentage", 0)
            
            # How many instances from this account are reachable from org deployment
            org_reachable = org_reachable_by_account.get(acct_id, 0)
            org_pct = (org_reachable / instances * 100) if instances > 0 else 0
            
            status_class = "success" if per_acct_status == "SUCCESS" else "warning" if per_acct_status == "PARTIAL" else "error"
            
            # Handle None deploy location
            deploy_region = per_acct_deploy.get("region", "N/A") if per_acct_deploy else "N/A"
            
            account_rows.append(f'''
                <tr>
                    <td><code>{acct_id}</code></td>
                    <td>{acct_name}</td>
                    <td><span class="status-badge {status_class}">{per_acct_status}</span></td>
                    <td>{vpcs}</td>
                    <td>{instances}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {per_acct_pct}%; background: {'#10b981' if per_acct_pct == 100 else '#f59e0b' if per_acct_pct > 0 else '#ef4444'}"></div>
                        </div>
                        <span class="progress-text">{per_acct_pct:.0f}%</span>
                    </td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {org_pct}%; background: {'#3b82f6' if org_pct == 100 else '#8b5cf6' if org_pct > 0 else '#ef4444'}"></div>
                        </div>
                        <span class="progress-text">{org_reachable}/{instances}</span>
                    </td>
                    <td>{deploy_region}</td>
                </tr>
            ''')
    
    # Full coverage plan - multiple deployments to cover ALL instances
    full_coverage_plan = org_result.get("full_coverage_plan", {})
    full_coverage_deployments = full_coverage_plan.get("deployments", [])
    
    # Build deployment cards (similar to single account format)
    deployment_cards = ""
    for deploy in full_coverage_deployments:
        order = deploy.get("deployment_order", 0)
        acct_id = deploy.get("account_id", "N/A")
        acct_name = deploy.get("account_name", "")
        region = deploy.get("region", "N/A")
        vpc_id = deploy.get("vpc_id", "") or "N/A"
        vpc_cidr = deploy.get("vpc_cidr", "") or ""
        subnet_id = deploy.get("subnet_id", "") or "N/A"
        subnet_cidr = deploy.get("subnet_cidr", "") or ""
        covers = deploy.get("covers_instances", 0)
        cumulative = deploy.get("cumulative_covered", 0)
        cum_pct = deploy.get("cumulative_percentage", 0)
        is_public = deploy.get("is_public", False)
        has_internet = deploy.get("has_internet", False)
        covered_instances_detail = deploy.get("covered_instances_detail", [])
        
        # Build instance rows for this deployment with full details
        dep_instance_rows = ""
        for inst in covered_instances_detail:
            dep_instance_rows += f'''
                <tr>
                    <td><code>{inst.get("instance_id", "")}</code></td>
                    <td>{inst.get("name", "") or "<em>No name</em>"}</td>
                    <td><code>{inst.get("private_ip", "")}</code></td>
                    <td>{inst.get("region", "")}</td>
                    <td><small>{inst.get("account_id", "")}</small></td>
                </tr>
            '''
        
        deployment_cards += f'''
        <div class="deployment-card" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
            <h3 style="color: #1e3a5f; margin-bottom: 15px;">🎯 Deployment #{order}: {acct_name} ({acct_id}) - {region}</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px;">
                <div><strong>Account:</strong> <code>{acct_id}</code></div>
                <div><strong>Region:</strong> {region}</div>
                <div><strong>VPC:</strong> <code>{vpc_id}</code></div>
                <div><strong>VPC CIDR:</strong> {vpc_cidr}</div>
                <div><strong>Subnet:</strong> <code>{subnet_id}</code></div>
                <div><strong>Subnet CIDR:</strong> {subnet_cidr or "N/A"}</div>
                <div><strong>Type:</strong> {"🌐 Public" if is_public else "🔒 Private"}</div>
                <div><strong>Internet Access:</strong> {"✓ Yes" if has_internet else "✗ No"}</div>
                <div><strong>Instances Covered:</strong> +{covers} ({cum_pct:.0f}% cumulative)</div>
            </div>
            {f'''<details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: 600; color: #2563eb;">View {len(covered_instances_detail)} Instance(s) Covered</summary>
                <table style="margin-top: 10px; width: 100%;">
                    <thead>
                        <tr>
                            <th>Instance ID</th>
                            <th>Name</th>
                            <th>Private IP</th>
                            <th>Region</th>
                            <th>Account</th>
                        </tr>
                    </thead>
                    <tbody>
                        {dep_instance_rows if dep_instance_rows else '<tr><td colspan="5">No instances</td></tr>'}
                    </tbody>
                </table>
            </details>''' if covered_instances_detail else ''}
        </div>
        '''
    
    # Full coverage plan HTML
    full_coverage_html = ""
    if full_coverage_deployments:
        total_deployments = full_coverage_plan.get("total_deployments_needed", 0)
        total_covered = full_coverage_plan.get("total_instances_covered", 0)
        coverage_pct = full_coverage_plan.get("coverage_percentage", 0)
        unreachable = full_coverage_plan.get("unreachable_count", 0)
        
        full_coverage_html = f'''
        <div class="card warning">
            <h2>⚠️ Multi-Account Deployment Required</h2>
            <p style="margin-bottom: 15px;">Instances are distributed across accounts/VPCs with limited cross-account connectivity.</p>
            <p style="margin-bottom: 20px;">To reach all <strong>{total_instances}</strong> instances, 
               deploy scanners in <strong>{total_deployments}</strong> locations:</p>
            {deployment_cards}
        </div>
        '''
    
    # Organization deployment recommendation card (best single location)
    org_deploy_html = ""
    if org_deploy:
        org_deploy_html = f'''
        <div class="card highlight-card">
            <h2>🎯 Organization-Wide Deployment Recommendation</h2>
            <div class="recommendation-status {'success' if org_status == 'SUCCESS' else 'partial'}">
                <span class="status-badge {'success' if org_status == 'SUCCESS' else 'warning'}">{org_status}</span>
                <p>{org_rec.get("message", "")}</p>
            </div>
            <div class="deploy-details">
                <div class="deploy-grid">
                    <div class="deploy-item">
                        <label>Deploy Account</label>
                        <value><code>{org_deploy.get("account_id", "N/A")}</code><br><small>{org_deploy.get("account_name", "")}</small></value>
                    </div>
                    <div class="deploy-item">
                        <label>Region</label>
                        <value>{org_deploy.get("region", "N/A")}</value>
                    </div>
                    <div class="deploy-item">
                        <label>VPC</label>
                        <value><code>{org_deploy.get("vpc_id", "N/A")}</code><br><small>{org_deploy.get("vpc_cidr", "")}</small></value>
                    </div>
                    <div class="deploy-item">
                        <label>Subnet</label>
                        <value><code>{org_deploy.get("subnet_id", "N/A")}</code><br><small>{org_deploy.get("subnet_cidr", "")}</small></value>
                    </div>
                    <div class="deploy-item">
                        <label>Subnet Type</label>
                        <value>{'🌐 Public' if org_deploy.get("is_public_subnet") else '🔒 Private'}</value>
                    </div>
                    <div class="deploy-item">
                        <label>Internet Access</label>
                        <value>{'✅ Yes' if org_deploy.get("has_internet_access") else '❌ No'}</value>
                    </div>
                </div>
            </div>
            <div class="coverage-summary">
                <h3>Cross-Account Coverage</h3>
                <div class="coverage-stats">
                    <div class="coverage-stat">
                        <span class="big-number">{org_coverage.get("reachable_instances", 0)}</span>
                        <span class="label">/ {org_coverage.get("total_instances", 0)} instances reachable</span>
                    </div>
                    <div class="coverage-stat">
                        <span class="big-number" style="color: #10b981">{org_coverage.get("reachable_same_account", 0)}</span>
                        <span class="label">Same Account</span>
                    </div>
                    <div class="coverage-stat">
                        <span class="big-number" style="color: #8b5cf6">{org_coverage.get("reachable_cross_account", 0)}</span>
                        <span class="label">Cross-Account (TGW/Peering)</span>
                    </div>
                </div>
            </div>
        </div>
        '''
    
    # Connectivity summary
    conn_html = f'''
    <div class="card">
        <h2>🔗 Network Connectivity Summary</h2>
        <div class="conn-grid">
            <div class="conn-item">
                <span class="conn-value">{conn_summary.get("tgw_connected_vpcs", 0)}</span>
                <span class="conn-label">TGW-Connected VPCs</span>
            </div>
            <div class="conn-item">
                <span class="conn-value">{conn_summary.get("peered_vpcs", 0)}</span>
                <span class="conn-label">Peered VPCs</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: {'#ef4444' if conn_summary.get('isolated_vpcs', 0) > 0 else '#10b981'}">{conn_summary.get("isolated_vpcs", 0)}</span>
                <span class="conn-label">Isolated VPCs</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: #7c3aed">{conn_summary.get("cross_account_tgw_connected_vpcs", 0)}</span>
                <span class="conn-label">Cross-Account TGW VPCs</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: #7c3aed">{conn_summary.get("cross_account_peered_vpcs", 0)}</span>
                <span class="conn-label">Cross-Account Peered VPCs</span>
            </div>
            <div class="conn-item">
                <span class="conn-value">{conn_summary.get("total_tgw_attachments", 0)}</span>
                <span class="conn-label">Total TGW Attachments</span>
            </div>
        </div>
    </div>
    '''
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Organization Network Reachability Report - Cross-Account Analysis</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f3f4f6;
            color: #1f2937;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1500px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #1e3a5f 0%, #7c3aed 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header-meta {{ opacity: 0.9; font-size: 14px; }}
        .header-badge {{ 
            background: rgba(255,255,255,0.2); 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 12px;
            margin-left: 10px;
        }}
        .stats-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #1e3a5f; }}
        .stat-label {{ color: #6b7280; font-size: 13px; margin-top: 5px; }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .highlight-card {{
            border: 2px solid #7c3aed;
            background: linear-gradient(to bottom, #faf5ff, white);
        }}
        .card h2 {{ margin-bottom: 15px; color: #1e3a5f; font-size: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; color: #374151; font-size: 13px; }}
        tr:hover {{ background: #f9fafb; }}
        .error-row {{ background: #fef2f2; }}
        .error-row:hover {{ background: #fee2e2; }}
        code {{ font-family: 'Monaco', 'Consolas', monospace; font-size: 11px; background: #f3f4f6; padding: 2px 4px; border-radius: 3px; }}
        small {{ color: #6b7280; }}
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 12px;
        }}
        .status-badge.success {{ background: #d1fae5; color: #059669; }}
        .status-badge.warning {{ background: #fef3c7; color: #d97706; }}
        .status-badge.error {{ background: #fee2e2; color: #dc2626; }}
        .progress-bar {{ 
            width: 80px; 
            height: 8px; 
            background: #e5e7eb; 
            border-radius: 4px; 
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
        }}
        .progress-fill {{ height: 100%; border-radius: 4px; }}
        .progress-text {{ margin-left: 8px; font-size: 12px; color: #6b7280; }}
        .recommendation-status {{ margin-bottom: 20px; }}
        .recommendation-status p {{ color: #374151; margin-top: 10px; }}
        .deploy-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .deploy-item {{
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
        }}
        .deploy-item label {{
            display: block;
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 5px;
        }}
        .deploy-item value {{
            display: block;
            font-weight: 600;
            color: #1f2937;
        }}
        .coverage-summary {{ margin-top: 25px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
        .coverage-summary h3 {{ font-size: 16px; color: #374151; margin-bottom: 15px; }}
        .coverage-stats {{ display: flex; gap: 40px; flex-wrap: wrap; }}
        .coverage-stat {{ text-align: center; }}
        .coverage-stat .big-number {{ font-size: 36px; font-weight: bold; color: #1e3a5f; display: block; }}
        .coverage-stat .label {{ font-size: 13px; color: #6b7280; }}
        .conn-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
        }}
        .conn-item {{ text-align: center; padding: 20px; background: #f9fafb; border-radius: 8px; }}
        .conn-value {{ font-size: 32px; font-weight: bold; color: #7c3aed; display: block; }}
        .conn-label {{ font-size: 13px; color: #6b7280; margin-top: 5px; }}
        .footer {{ 
            text-align: center; 
            color: #9ca3af; 
            font-size: 12px; 
            margin-top: 30px;
            padding: 20px;
        }}
        .footer a {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 AWS Organization Network Reachability Report
                <span class="header-badge">Cross-Account Analysis</span>
            </h1>
            <div class="header-meta">
                Organization: <strong>{org_id}</strong> | 
                Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong> |
                Version: <strong>{VERSION}</strong>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_accounts}</div>
                <div class="stat-label">Accounts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #10b981">{successful}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {'#ef4444' if failed > 0 else '#10b981'}">{failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_vpcs}</div>
                <div class="stat-label">Total VPCs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_instances}</div>
                <div class="stat-label">Total Instances</div>
            </div>
        </div>
        
        {conn_html}
        
        {full_coverage_html}
        
        <div class="card">
            <h2>📊 Per-Account Analysis</h2>
            <p style="color: #6b7280; margin-bottom: 15px;">
                Shows per-account coverage (within that account) and how many instances are reachable from the org-wide deployment location.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Account ID</th>
                        <th>Account Name</th>
                        <th>Per-Acct Status</th>
                        <th>VPCs</th>
                        <th>Instances</th>
                        <th>Per-Acct Coverage</th>
                        <th>Org Reachable</th>
                        <th>Best Region</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(account_rows)}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            Generated by AWS Network Reachability Analyzer v{VERSION}<br>
            <a href="https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer">Documentation & Source</a>
        </div>
    </div>
</body>
</html>'''
    
    with open(output_file, 'w') as f:
        f.write(html)
    logger.info(f"Organization HTML report exported: {output_file}")


def export_org_to_html_unified(org_result, output_file, cloud: str = "aws"):
    """Export organization results to HTML report with same format for AWS, Azure, and GCP."""
    
    # Cloud-specific labels
    if cloud == "azure":
        entity_label = "Subscription"
        entity_label_plural = "Subscriptions"
        network_label = "VNet"
        network_label_plural = "VNets"
        instance_label = "VM"
        instance_label_plural = "VMs"
        entity_key = "subscriptions"
        entity_id_field = "subscription_id"
        icon = "☁️"
        org_id = org_result.get("tenant_id", "N/A")
        org_label = "Tenant"
    elif cloud == "gcp":
        entity_label = "Project"
        entity_label_plural = "Projects"
        network_label = "VPC"
        network_label_plural = "VPCs"
        instance_label = "Instance"
        instance_label_plural = "Instances"
        entity_key = "projects"
        entity_id_field = "project_id"
        icon = "🔷"
        org_id = org_result.get("org_id", org_result.get("organization_id", "N/A"))
        org_label = "Organization"
    else:  # aws
        entity_label = "Account"
        entity_label_plural = "Accounts"
        network_label = "VPC"
        network_label_plural = "VPCs"
        instance_label = "Instance"
        instance_label_plural = "Instances"
        entity_key = "accounts"
        entity_id_field = "account_id"
        icon = "🏢"
        org_id = org_result.get("org_id", "N/A")
        org_label = "Organization"

    per_entity_short = "Acct" if entity_label.lower() == "account" else "Sub" if entity_label.lower() == "subscription" else "Proj" if entity_label.lower() == "project" else entity_label[:4]
    
    # Get entities (accounts/subscriptions/projects)
    entities_raw = org_result.get(entity_key, {})
    if isinstance(entities_raw, list):
        entities = {e.get(entity_id_field, str(i)): e for i, e in enumerate(entities_raw)}
    else:
        entities = entities_raw
    
    org_rec = org_result.get("org_recommendation", {})
    summary = org_result.get("summary", {})
    conn_summary = org_result.get("connectivity_summary", {})
    
    # Calculate totals - try different field names for compatibility
    total_entities = summary.get(f"total_{entity_key}", summary.get(f"total_{entity_label.lower()}s_scanned", len(entities)))
    successful = summary.get(f"successful_{entity_key.rstrip('s')}s", summary.get(f"successful_{entity_label.lower()}s", 
                            sum(1 for e in entities.values() if e.get("status") != "error" and not e.get("error"))))
    failed = total_entities - successful
    
    # Handle different field names for totals
    total_instances = summary.get("total_instances", summary.get("total_vms", 0))
    total_networks = summary.get("total_vpcs", summary.get("total_vnets", summary.get("total_networks", 0)))
    
    # Organization-wide recommendation details
    org_status = org_rec.get("status", "UNKNOWN")
    org_coverage = org_rec.get("coverage", {})
    org_deploy = org_rec.get("deployment_location", {})
    overall_coverage = org_coverage.get("percentage", 0)
    org_cov_color = "#10b981" if overall_coverage == 100 else "#f59e0b" if overall_coverage > 0 else "#ef4444"
    
    # Build entity rows (accounts/subscriptions/projects)
    entity_rows = []
    org_reachable_by_entity = org_coverage.get("reachable_by_account", org_coverage.get("reachable_by_subscription", org_coverage.get("reachable_by_project", {})))
    
    for entity_id, entity_data in sorted(entities.items()):
        entity_name = entity_data.get("name", entity_data.get("display_name", entity_data.get(f"{entity_label.lower()}_name", "Unknown")))
        
        if entity_data.get("status") == "error" or entity_data.get("error"):
            entity_rows.append(f'''
                <tr class="error-row">
                    <td><code>{entity_id}</code></td>
                    <td>{entity_name}</td>
                    <td><span class="status-badge error">ERROR</span></td>
                    <td colspan="5">{entity_data.get("error", "Unknown error")}</td>
                </tr>
            ''')
        else:
            per_entity_rec = entity_data.get("per_account_recommendation", entity_data.get("recommendation", entity_data.get("report", {}).get("recommendation", {})))
            per_entity_cov = per_entity_rec.get("coverage", {})
            per_entity_status = entity_data.get("status", per_entity_rec.get("status", "UNKNOWN"))
            per_entity_deploy = per_entity_rec.get("deployment_location", {})
            
            instances = entity_data.get("instances", entity_data.get("vms", 0))
            networks = entity_data.get("vpcs", entity_data.get("vnets", 0))
            per_entity_pct = per_entity_cov.get("percentage", 0)
            
            org_reachable = org_reachable_by_entity.get(entity_id, 0)
            org_pct = (org_reachable / instances * 100) if instances > 0 else 0
            
            status_class = "success" if per_entity_status == "SUCCESS" else "warning" if per_entity_status == "PARTIAL" else "error"
            deploy_region = per_entity_deploy.get("region", per_entity_deploy.get("location", "N/A")) if per_entity_deploy else "N/A"
            
            entity_rows.append(f'''
                <tr>
                    <td><code>{entity_id}</code></td>
                    <td>{entity_name}</td>
                    <td><span class="status-badge {status_class}">{per_entity_status}</span></td>
                    <td>{networks}</td>
                    <td>{instances}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {per_entity_pct}%; background: {'#10b981' if per_entity_pct == 100 else '#f59e0b' if per_entity_pct > 0 else '#ef4444'}"></div>
                        </div>
                        <span class="progress-text">{per_entity_pct:.0f}%</span>
                    </td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {org_pct}%; background: {'#3b82f6' if org_pct == 100 else '#8b5cf6' if org_pct > 0 else '#ef4444'}"></div>
                        </div>
                        <span class="progress-text">{org_reachable}/{instances}</span>
                    </td>
                    <td>{deploy_region}</td>
                </tr>
            ''')
    
    # Full coverage plan - multiple deployments
    full_coverage_plan = org_result.get("full_coverage_plan", {})
    full_coverage_deployments = full_coverage_plan.get("deployments", [])
    
    # Build deployment cards
    deployment_cards = ""
    for deploy in full_coverage_deployments:
        order = deploy.get("deployment_order", 0)
        entity_id = deploy.get(entity_id_field, deploy.get("account_id", deploy.get("subscription_id", deploy.get("project_id", "N/A"))))
        entity_name = deploy.get(f"{entity_label.lower()}_name", deploy.get("account_name", deploy.get("subscription_name", deploy.get("project_name", ""))))
        region = deploy.get("region", deploy.get("location", "N/A"))
        network_id = deploy.get("vpc_id", deploy.get("vnet_id", "")) or "N/A"
        network_name = deploy.get("vpc_name", deploy.get("vnet_name", ""))
        network_cidr = deploy.get("vpc_cidr", deploy.get("vnet_cidr", "")) or ""
        subnet_id = deploy.get("subnet_id", "") or "N/A"
        subnet_name = deploy.get("subnet_name", "")
        subnet_cidr = deploy.get("subnet_cidr", "") or ""
        covers = deploy.get("covers_instances", deploy.get("covers_vms", 0))
        cumulative = deploy.get("cumulative_covered", 0)
        cum_pct = deploy.get("cumulative_percentage", 0)
        is_public = deploy.get("is_public", False)
        has_internet = deploy.get("has_internet", deploy.get("has_nat_gateway", False))
        covered_detail = deploy.get("covered_instances_detail", deploy.get("covered_vms_detail", []))
        
        # Build instance rows for details
        dep_instance_rows = ""
        for inst in covered_detail:
            inst_id = inst.get("instance_id", inst.get("vm_id", ""))
            inst_name = inst.get("name", "")
            private_ip = inst.get("private_ip", inst.get("internal_ip", ""))
            inst_region = inst.get("region", inst.get("location", inst.get("zone", "")))
            
            dep_instance_rows += f'''
                <tr>
                    <td><code>{inst_id[:40]}...</code></td>
                    <td>{inst_name or "<em>No name</em>"}</td>
                    <td><code>{private_ip}</code></td>
                    <td>{inst_region}</td>
                </tr>
            '''
        
        # Cloud-specific connectivity info
        if cloud == "aws":
            connectivity_html = f'''<div><strong>Type:</strong> {"🌐 Public" if is_public else "🔒 Private"}</div>
                <div><strong>Internet Access:</strong> {"✓ Yes" if has_internet else "✗ No"}</div>'''
        elif cloud == "azure":
            has_nat = deploy.get("has_nat_gateway", False)
            connectivity_html = f'''<div><strong>NAT Gateway:</strong> {"✓ Yes" if has_nat else "✗ No"}</div>
                <div><strong>Internet Access:</strong> {"✓ Via NAT" if has_nat else "⚠️ Needs NAT/Public IP"}</div>'''
        else:  # GCP
            has_pga = deploy.get("private_ip_google_access", False)
            connectivity_html = f'''<div><strong>Private Google Access:</strong> {"✓ Yes" if has_pga else "✗ No"}</div>
                <div><strong>Internet Access:</strong> {"✓ Via Cloud NAT" if has_internet else "⚠️ Needs Cloud NAT"}</div>'''
        
        deployment_cards += f'''
        <div class="deployment-card" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
            <h3 style="color: #1e3a5f; margin-bottom: 15px;">🎯 Deployment #{order}: {entity_name or entity_id} - {region}</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px;">
                <div><strong>{entity_label}:</strong> <code>{entity_id}</code></div>
                <div><strong>Region:</strong> {region}</div>
                <div><strong>{network_label}:</strong> <code>{network_id}</code></div>
                <div><strong>{network_label} CIDR:</strong> {network_cidr or ""}</div>
                <div><strong>Subnet:</strong> <code>{subnet_id or "N/A"}</code></div>
                <div><strong>Subnet CIDR:</strong> {subnet_cidr or "N/A"}</div>
                {connectivity_html}
                <div><strong>{instance_label_plural} Covered:</strong> +{covers} ({cum_pct:.0f}% cumulative)</div>
            </div>
            {f"""<details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: 600; color: #2563eb;">View {len(covered_detail)} {instance_label}(s) Covered</summary>
                <table style="margin-top: 10px; width: 100%;">
                    <thead>
                        <tr>
                            <th>{instance_label} ID</th>
                            <th>Name</th>
                            <th>Private IP</th>
                            <th>Region</th>
                        </tr>
                    </thead>
                    <tbody>
                        {dep_instance_rows if dep_instance_rows else f'<tr><td colspan="4">No {instance_label_plural.lower()}</td></tr>'}
                    </tbody>
                </table>
            </details>""" if covered_detail else ''}
        </div>
        '''
    
    # Full coverage plan HTML section - matching approved format
    full_coverage_html = ""
    total_deployments = full_coverage_plan.get("total_deployments_needed", len(full_coverage_deployments))
    total_covered = full_coverage_plan.get("total_instances_covered", 0)
    coverage_pct = full_coverage_plan.get("coverage_percentage", overall_coverage)
    if not full_coverage_deployments and total_instances > 0:
        deployment_cards = '<div style="background:#f9fafb;padding:15px;border:1px solid #e5e7eb;border-radius:8px;color:#6b7280;">No deployment plan was generated. Please rerun the analyzer or check account errors.</div>'
    elif not full_coverage_deployments and total_instances == 0:
        deployment_cards = f'<div style="background:#f9fafb;padding:15px;border:1px solid #e5e7eb;border-radius:8px;color:#6b7280;">No instances found across scanned {entity_label_plural.lower()}. No deployments required.</div>'
    full_coverage_html = f'''
        <div class="card warning">
            <h2>⚠️ Multi-{entity_label} Deployment Required</h2>
            <p style="margin-bottom: 15px;">{instance_label_plural} are distributed across {entity_label_plural.lower()}/{network_label_plural} with limited cross-{entity_label.lower()} connectivity.</p>
            <p style="margin-bottom: 20px;">To reach all <strong>{total_instances}</strong> {instance_label_plural.lower()}, 
               deploy scanners in <strong>{max(total_deployments, 1) if total_instances else 0}</strong> locations:</p>
            {deployment_cards}
        </div>
        '''
    
    # Connectivity summary HTML
    conn_html = ""
    if conn_summary:
        peered = conn_summary.get("peered_vpcs", conn_summary.get("peered_vnets", conn_summary.get("peered_networks", 0)))
        isolated = conn_summary.get("isolated_vpcs", conn_summary.get("isolated_vnets", conn_summary.get("isolated_networks", 0)))
        total_peering = conn_summary.get("total_peering_connections", 0)
        
        if cloud == "aws":
            tgw_connected = conn_summary.get("tgw_connected_vpcs", 0)
            cross_tgw = conn_summary.get("cross_account_tgw_connected_vpcs", 0)
            cross_peer = conn_summary.get("cross_account_peered_vpcs", 0)
            total_tgw = conn_summary.get("total_tgw_attachments", 0)
            
            conn_html = f'''
    <div class="card">
        <h2>🔗 Network Connectivity Summary</h2>
        <div class="conn-grid">
            <div class="conn-item">
                <span class="conn-value">{tgw_connected}</span>
                <span class="conn-label">TGW-Connected {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value">{peered}</span>
                <span class="conn-label">Peered {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: {'#ef4444' if isolated > 0 else '#10b981'}">{isolated}</span>
                <span class="conn-label">Isolated {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: #7c3aed">{cross_tgw}</span>
                <span class="conn-label">Cross-{entity_label} TGW {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: #7c3aed">{cross_peer}</span>
                <span class="conn-label">Cross-{entity_label} Peered {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value">{total_tgw}</span>
                <span class="conn-label">Total TGW Attachments</span>
            </div>
        </div>
    </div>
    '''
        else:
            # Azure/GCP - simpler connectivity summary
            conn_html = f'''
    <div class="card">
        <h2>🔗 Network Connectivity Summary</h2>
        <div class="conn-grid">
            <div class="conn-item">
                <span class="conn-value">{peered}</span>
                <span class="conn-label">Peered {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value" style="color: {'#ef4444' if isolated > 0 else '#10b981'}">{isolated}</span>
                <span class="conn-label">Isolated {network_label_plural}</span>
            </div>
            <div class="conn-item">
                <span class="conn-value">{total_peering}</span>
                <span class="conn-label">Total Peering Connections</span>
            </div>
        </div>
    </div>
    '''
    
    # Build HTML - using light theme matching approved format
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cloud.upper()} Organization Network Reachability Report - Cross-{entity_label} Analysis</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f3f4f6;
            color: #1f2937;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1500px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #1e3a5f 0%, #7c3aed 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header-meta {{ opacity: 0.9; font-size: 14px; }}
        .header-badge {{ 
            background: rgba(255,255,255,0.2); 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 12px;
            margin-left: 10px;
        }}
        .stats-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #1e3a5f; }}
        .stat-label {{ color: #6b7280; font-size: 13px; margin-top: 5px; }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .card.warning {{ border-left: 4px solid #f59e0b; }}
        .highlight-card {{
            border: 2px solid #7c3aed;
            background: linear-gradient(to bottom, #faf5ff, white);
        }}
        .card h2 {{ margin-bottom: 15px; color: #1e3a5f; font-size: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; color: #374151; font-size: 13px; }}
        tr:hover {{ background: #f9fafb; }}
        .error-row {{ background: #fef2f2; }}
        .error-row:hover {{ background: #fee2e2; }}
        code {{ font-family: 'Monaco', 'Consolas', monospace; font-size: 11px; background: #f3f4f6; padding: 2px 4px; border-radius: 3px; }}
        small {{ color: #6b7280; }}
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 12px;
        }}
        .status-badge.success {{ background: #d1fae5; color: #059669; }}
        .status-badge.warning {{ background: #fef3c7; color: #d97706; }}
        .status-badge.error {{ background: #fee2e2; color: #dc2626; }}
        .progress-bar {{ 
            width: 80px; 
            height: 8px; 
            background: #e5e7eb; 
            border-radius: 4px; 
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
        }}
        .progress-fill {{ height: 100%; border-radius: 4px; }}
        .progress-text {{ margin-left: 8px; font-size: 12px; color: #6b7280; }}
        .recommendation-status {{ margin-bottom: 20px; }}
        .recommendation-status p {{ color: #374151; margin-top: 10px; }}
        .deploy-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .deploy-item {{
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
        }}
        .deploy-item label {{
            display: block;
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 5px;
        }}
        .deploy-item value {{
            display: block;
            font-weight: 600;
            color: #1f2937;
        }}
        .coverage-summary {{ margin-top: 25px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
        .coverage-summary h3 {{ font-size: 16px; color: #374151; margin-bottom: 15px; }}
        .coverage-stats {{ display: flex; gap: 40px; flex-wrap: wrap; }}
        .coverage-stat {{ text-align: center; }}
        .coverage-stat .big-number {{ font-size: 36px; font-weight: bold; color: #1e3a5f; display: block; }}
        .coverage-stat .label {{ font-size: 13px; color: #6b7280; }}
        .conn-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
        }}
        .conn-item {{ text-align: center; padding: 20px; background: #f9fafb; border-radius: 8px; }}
        .conn-value {{ font-size: 32px; font-weight: bold; color: #7c3aed; display: block; }}
        .conn-label {{ font-size: 13px; color: #6b7280; margin-top: 5px; }}
        .footer {{ 
            text-align: center; 
            color: #9ca3af; 
            font-size: 12px; 
            margin-top: 30px;
            padding: 20px;
        }}
        .footer a {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{icon} {cloud.upper()} Organization Network Reachability Report
                <span class="header-badge">Cross-{entity_label} Analysis</span>
            </h1>
            <div class="header-meta">
                {org_label}: <strong>{org_id}</strong> | 
                Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong> |
                Version: <strong>{VERSION}</strong>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_entities}</div>
                <div class="stat-label">{entity_label_plural} Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #10b981">{successful}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {'#ef4444' if failed > 0 else '#10b981'}">{failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_networks}</div>
                <div class="stat-label">Total {network_label_plural}</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_instances}</div>
                <div class="stat-label">Total {instance_label_plural}</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {org_cov_color}">{overall_coverage:.0f}%</div>
                <div class="stat-label">{org_label} Coverage</div>
            </div>
        </div>
        
        {full_coverage_html}
        
        {conn_html}
        
        <div class="card">
            <h2>📊 Per-{entity_label} Analysis</h2>
            <p style="color: #6b7280; margin-bottom: 15px;">
                Shows per-{entity_label.lower()} coverage (within that {entity_label.lower()}) and how many {instance_label_plural.lower()} are reachable from the org-wide deployment location.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>{entity_label} ID</th>
                        <th>{entity_label} Name</th>
                        <th>Per-{per_entity_short} Status</th>
                        <th>{network_label_plural}</th>
                        <th>{instance_label_plural}</th>
                        <th>Per-{per_entity_short} Coverage</th>
                        <th>Org Reachable</th>
                        <th>Best Region</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(entity_rows)}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            Generated by Multi-Cloud Network Reachability Analyzer v{VERSION}
        </div>
    </div>
</body>
</html>'''
    
    with open(output_file, 'w') as f:
        f.write(html)
    logger.info(f"{cloud.upper()} Organization HTML report exported: {output_file}")


def run_dry_run(session, regions, args):
    """Execute dry run - validate without scanning."""
    print("\n" + "=" * 70)
    print("DRY RUN MODE - Preview Only (no actual scan)")
    print("=" * 70)
    
    print(f"\n✓ Credentials validated successfully")
    print(f"\n📋 SCAN CONFIGURATION:")
    print(f"   Mode:          {args.mode}")
    print(f"   Regions:       {len(regions)}")
    print(f"   Parallel:      {args.parallel} concurrent")
    print(f"   Timeout:       {args.timeout}s")
    print(f"   Output:        {args.output}")
    print(f"   Format:        {args.format}")
    
    print(f"\n🌍 REGIONS TO SCAN:")
    for i, region in enumerate(regions, 1):
        print(f"   {i:2}. {region}")
    
    # Estimate time
    est_time = (len(regions) / max(args.parallel, 1)) * 4  # ~4s per region
    print(f"\n⏱  ESTIMATED TIME: {est_time:.0f}-{est_time*1.5:.0f} seconds")
    
    print(f"\n💡 To execute the scan, run without --dry-run")
    print("=" * 70)


def main():
    global _executor
    
    args = parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Handle --list-resumable before anything else
    if args.list_resumable:
        try:
            cache_mod = _get_cache_module()
            state_manager = cache_mod.get_state_manager()
            resumable = state_manager.get_resumable_scans(cloud=args.cloud if args.cloud != "aws" else None)
            
            if not resumable:
                print("No resumable scans found.")
            else:
                print(f"\n📋 Resumable Scans ({len(resumable)} found):")
                print("-" * 80)
                for scan in resumable:
                    print(f"  Scan ID: {scan['scan_id']}")
                    print(f"  Cloud: {scan['cloud']} | Mode: {scan['mode']}")
                    print(f"  Progress: {scan['progress']} (✓{scan['successful']} ✗{scan['failed']})")
                    print(f"  Last Update: {scan['last_update']}")
                    print(f"  Resume with: --resume {scan['scan_id']}")
                    print("-" * 80)
        except Exception as e:
            print(f"❌ ERROR listing resumable scans: {e}", file=sys.stderr)
        sys.exit(EXIT_SUCCESS)
    
    # Track exit code
    exit_code = EXIT_SUCCESS
    result = None
    start_time = time.time()
    
    try:
        # Route to appropriate cloud handler
        if args.cloud == "aws":
            exit_code, result = run_aws_analysis(args, start_time)
        elif args.cloud == "azure":
            exit_code, result = run_azure_analysis(args, start_time)
        elif args.cloud == "gcp":
            exit_code, result = run_gcp_analysis(args, start_time)
        else:
            print(f"❌ ERROR: Unsupported cloud: {args.cloud}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        
        # Print JSON output if not quiet and format is json
        if not args.quiet and args.format == "json" and result:
            print("\n" + "=" * 70)
            print("JSON OUTPUT")
            print("=" * 70)
            print(json.dumps(result, indent=2, default=str))
    
    except KeyboardInterrupt:
        print("\n\n⚠ Scan interrupted by user", file=sys.stderr)
        exit_code = EXIT_INTERRUPTED
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        exit_code = EXIT_ERROR
    
    # Log final status
    total_time = time.time() - start_time
    logger.info(f"Completed in {total_time:.1f}s with exit code {exit_code}")
    
    sys.exit(exit_code)


def run_aws_analysis(args, start_time):
    """Run AWS-specific network analysis."""
    global _executor
    exit_code = EXIT_SUCCESS
    result = None
    
    # Import the enhanced analyzers - use relative import for package, fallback to absolute
    try:
        from aws_network_analyzer.analyzer import AWSNetworkAnalyzer
    except ImportError:
        from .analyzer import AWSNetworkAnalyzer
    
    # OrgNetworkAnalyzer is defined inline above
    
    logger.debug(f"AWS Network Reachability Analyzer v{VERSION}")
    
    if args.mode == "account":
        # Create session using new credential handling
        try:
            session, auth_method = create_session(args)
            logger.info(f"Authentication method: {auth_method}")
        except ValueError as e:
            print(f"❌ ERROR: {e}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        
        # Validate credentials
        account_id, cred_error = validate_credentials(session, args.profile)
        if cred_error:
            print(f"❌ ERROR: {cred_error}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        
        print(f"AWS Network Reachability Analyzer v{VERSION}")
        print(f"Account: {account_id}")
        
        # Determine and validate regions
        if args.regions:
            requested_regions = [r.strip() for r in args.regions.split(",")]
            valid_regions, invalid_regions, disabled_regions = validate_regions(session, requested_regions)
            
            if invalid_regions:
                print(f"⚠ WARNING: Invalid regions ignored: {', '.join(invalid_regions)}", file=sys.stderr)
            if disabled_regions:
                print(f"⚠ WARNING: Disabled regions ignored: {', '.join(disabled_regions)}", file=sys.stderr)
            
            if not valid_regions:
                print("❌ ERROR: No valid regions specified", file=sys.stderr)
                sys.exit(EXIT_ERROR)
            
            regions = valid_regions
        else:
            print("\nDiscovering enabled regions...")
            regions = get_regions(session)
            print(f"Found {len(regions)} regions: {', '.join(regions[:5])}{'...' if len(regions) > 5 else ''}")
        
        # Dry run mode - preview and exit
        if args.dry_run:
            run_dry_run(session, regions, args)
            sys.exit(EXIT_SUCCESS)
        
        # Show parallel mode info
        if args.parallel > 1 and len(regions) > 1:
            print(f"Parallel scanning enabled: {min(args.parallel, len(regions))} concurrent regions")
        
        # Setup timeout
        def timeout_handler():
            global _shutdown_requested
            if time.time() - start_time > args.timeout:
                logger.error(f"Timeout exceeded ({args.timeout}s)")
                _shutdown_requested = True
        
        # Use enhanced analyzer
        print("\nAnalyzing network infrastructure...")
        analyzer = AWSNetworkAnalyzer(session, regions, max_workers=args.parallel, quiet=args.quiet)
        
        def progress(msg):
            if not args.quiet:
                print(f"  {msg}")
        
        topology = analyzer.discover_all()
        
        # Check timeout
        if time.time() - start_time > args.timeout:
            print(f"\n⚠ WARNING: Timeout exceeded ({args.timeout}s), results may be incomplete", file=sys.stderr)
            exit_code = EXIT_TIMEOUT
        
        scan_duration = time.time() - start_time
        
        # Generate comprehensive report
        print("\nAnalyzing reachability paths...")
        report = analyzer.generate_report()
        report["account_id"] = account_id
        report["scan_duration_seconds"] = round(scan_duration, 1)
        report["version"] = VERSION
        
        # Get summary from report
        summary = report.get("summary", {})
        total_vpcs = summary.get("total_vpcs", len(analyzer.vpcs))
        total_instances = summary.get("total_instances", len(analyzer.instances))
        
        print(f"\nDiscovered: {total_vpcs} VPCs, {total_instances} EC2 instances")
        print(f"Scan completed in {scan_duration:.1f} seconds")
        
        # Print summary and get the text
        summary_text = print_reachability_summary(report)
        
        # Use analyzer's discovery data directly (not running legacy discover_account separately)
        # This avoids duplicate API calls and ensures data consistency
        account_data = analyzer.discovery_data
        
        # Build all_cidrs from discovery data
        all_cidrs = []
        for region_data in account_data.values():
            if isinstance(region_data, dict):
                for vpc in region_data.get("vpcs", {}).values():
                    if isinstance(vpc, dict) and vpc.get("cidr_block"):
                        all_cidrs.append(vpc["cidr_block"])
        
        # Generate recommendation from the analyzer's data
        legacy_recommendation = generate_recommendation(account_data, all_cidrs)
        
        # Merge new recommendation into legacy format
        if report.get("recommendation", {}).get("deployment_location"):
            loc = report["recommendation"]["deployment_location"]
            legacy_recommendation["selected_region"] = loc.get("region")
            legacy_recommendation["selected_vpc"] = loc.get("vpc_id")
            legacy_recommendation["selected_subnet"] = loc.get("subnet_id")
            legacy_recommendation["status"] = report["recommendation"]["status"]
            
            # Update reachability based on new analysis
            cov = report["recommendation"].get("coverage", {})
            if cov.get("percentage", 0) == 100:
                legacy_recommendation["status"] = "PASS"
            else:
                exit_code = EXIT_PARTIAL  # Partial coverage
        
        # Add multi-region recommendation to the report
        multi_region = generate_multi_region_recommendation(report)
        if multi_region:
            report["multi_region_deployment"] = multi_region
        
        # Build unified result structure (flat like Azure/GCP)
        # Add account-specific fields to the report
        report["account_id"] = account_id
        report["mode"] = "account"
        report["version"] = VERSION
        report["scan_duration_seconds"] = round(time.time() - start_time, 1)
        
        # Store discovery data separately for detailed analysis
        report["discovery"] = account_data
        
        # Keep legacy structure for backward compatibility
        result = {
            "mode": "account",
            "account_id": account_id,
            "version": VERSION,
            "generated_at": datetime.now().isoformat(),
            "discovery": account_data,
            "recommendation": legacy_recommendation,
            "enhanced_report": report,
            # Also include flat fields at top level for unified access
            "cloud": "aws",
            "all_instances": report.get("all_instances", []),
            "full_coverage_plan": report.get("full_coverage_plan", {}),
            "connectivity_summary": report.get("connectivity_summary", {}),
            "summary": report.get("summary", {})
        }
        
        # Save report based on format
        if args.format == "csv":
            csv_output = args.output if args.output.endswith('.csv') else args.output.replace('.json', '.csv')
            export_to_csv(result, csv_output)
            print(f"\n📊 CSV Report saved: {csv_output}")
        elif args.format == "html":
            html_output = args.output if args.output.endswith('.html') else args.output.replace('.json', '.html')
            try:
                generate_html = _get_html_report_module()
                generate_html(result, html_output, cloud="aws")
                print(f"\n🌐 HTML Report saved: {html_output}")
            except Exception as e:
                logger.warning(f"HTML report failed: {e}")
                print(f"\n⚠️  HTML report generation failed: {e}")
        else:
            # Save JSON report
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n📄 Report saved: {args.output}")
        
        # Save summary text file (only if not HTML, as HTML includes the summary)
        if args.format != "html":
            txt_output = args.output.replace('.json', '_summary.txt').replace('.csv', '_summary.txt')
            with open(txt_output, 'w') as f:
                f.write(f"AWS Network Reachability Analysis\n")
                f.write(f"Account: {account_id}\n")
                f.write(f"Version: {VERSION}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(summary_text)
            print(f"Summary saved: {txt_output}")
    
    elif args.mode == "org":
        print(f"AWS Network Reachability Analyzer v{VERSION}")
        print("Org mode - cross-account analysis...")
        print("This will analyze all accounts and provide organization-wide recommendations.\n")
        
        # Create session using new credential handling
        try:
            session, auth_method = create_session(args)
            logger.info(f"Authentication method: {auth_method}")
        except ValueError as e:
            print(f"❌ ERROR: {e}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        
        # Validate credentials for management account
        account_id, cred_error = validate_credentials(session, args.profile)
        if cred_error:
            print(f"❌ ERROR: {cred_error}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        
        print(f"Management Account: {account_id}")
        
        if args.regions:
            requested_regions = [r.strip() for r in args.regions.split(",")]
            regions, invalid, disabled = validate_regions(session, requested_regions)
            if invalid:
                print(f"⚠ WARNING: Invalid regions ignored: {', '.join(invalid)}", file=sys.stderr)
        else:
            print("Discovering enabled regions...")
            regions = get_regions(session)
            print(f"Found {len(regions)} regions")
        
        # Dry run mode
        if args.dry_run:
            run_dry_run(session, regions, args)
            sys.exit(EXIT_SUCCESS)
        
        # Use the new OrgNetworkAnalyzer for cross-account analysis
        org_analyzer = OrgNetworkAnalyzer(
            management_session=session,
            regions=regions,
            assume_role_name=args.assume_role,
            max_parallel=args.parallel,
            max_parallel_accounts=args.parallel_accounts
        )
        
        # Discover all accounts and build unified topology
        discovery_summary = org_analyzer.discover_organization(
            quiet=args.quiet,
            max_accounts=args.max_accounts
        )
        
        print(f"\n✅ Discovery complete:")
        print(f"   Accounts scanned: {discovery_summary['successful_accounts']}/{discovery_summary['total_accounts']}")
        print(f"   Total VPCs: {discovery_summary['total_vpcs']}")
        print(f"   Total Instances: {discovery_summary['total_instances']}")
        
        # Generate organization-wide report with cross-account analysis
        org_result = org_analyzer.generate_org_report()
        org_result["org_id"] = discovery_summary["org_id"]
        org_result["version"] = VERSION
        
        # Print full coverage plan (multiple deployments to cover ALL instances)
        full_cov_plan = org_result.get("full_coverage_plan", {})
        full_cov_deployments = full_cov_plan.get("deployments", [])
        if full_cov_deployments and discovery_summary['total_instances'] > 0:
            total_deploy = full_cov_plan.get("total_deployments_needed", 0)
            total_covered = full_cov_plan.get("total_instances_covered", 0)
            cov_pct = full_cov_plan.get("coverage_percentage", 0)
            unreachable = full_cov_plan.get("unreachable_count", 0)
            
            print(f"\n{'=' * 70}")
            print(f"📋 FULL COVERAGE PLAN: {total_deploy} DEPLOYMENT{'S' if total_deploy != 1 else ''} NEEDED")
            print(f"{'=' * 70}")
            
            if cov_pct == 100:
                print(f"✅ Deploy in these {total_deploy} locations to reach ALL {total_covered} instances:")
            else:
                print(f"⚠️  Deploy in these {total_deploy} locations to reach {total_covered}/{discovery_summary['total_instances']} instances ({cov_pct:.1f}%):")
                print(f"   ({unreachable} instances in isolated VPCs cannot be reached)")
            
            for deploy in full_cov_deployments:
                order = deploy.get("deployment_order", 0)
                covers = deploy.get("covers_instances", 0)
                cumulative = deploy.get("cumulative_covered", 0)
                cum_pct = deploy.get("cumulative_percentage", 0)
                
                print(f"\n   #{order}. {deploy.get('account_name', '')} ({deploy.get('account_id')})")
                print(f"       Region: {deploy.get('region')}")
                print(f"       VPC:    {deploy.get('vpc_id')} ({deploy.get('vpc_cidr')})")
                print(f"       Subnet: {deploy.get('subnet_id')}")
                print(f"       Type:   {'Public' if deploy.get('is_public') else 'Private'} | "
                      f"Internet: {'Yes' if deploy.get('has_internet') else 'No'}")
                print(f"       ➜ Covers: +{covers} instances (cumulative: {cumulative}/{discovery_summary['total_instances']} = {cum_pct:.0f}%)")
            
            print()
        
        # Print organization-wide recommendation (best single location)
        org_rec = org_result.get("org_recommendation", {})
        if org_rec:
            print(f"{'=' * 70}")
            print(f"🎯 BEST SINGLE DEPLOYMENT LOCATION: {org_rec.get('status', 'UNKNOWN')}")
            print(f"{'=' * 70}")
            print(org_rec.get("message", ""))
            
            if org_rec.get("deployment_location"):
                loc = org_rec["deployment_location"]
                print(f"\n>> BEST SINGLE LOCATION (maximum reach from one point):")
                print(f"   Account: {loc.get('account_id')} ({loc.get('account_name')})")
                print(f"   Region:  {loc.get('region')}")
                print(f"   VPC:     {loc.get('vpc_id')} ({loc.get('vpc_cidr')})")
                print(f"   Subnet:  {loc.get('subnet_id')} ({loc.get('subnet_cidr')})")
                print(f"   Type:    {'Public (has IGW)' if loc.get('is_public_subnet') else 'Private'}")
                print(f"   Internet: {'Yes' if loc.get('has_internet_access') else 'No'}")
            
            cov = org_rec.get("coverage", {})
            if cov:
                print(f"\n>> COVERAGE FROM THIS LOCATION:")
                print(f"   Reachable: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                      f"({cov.get('percentage', 0):.1f}%)")
                print(f"   Same Account: {cov.get('reachable_same_account', 0)}")
                print(f"   Cross-Account (via TGW/Peering): {cov.get('reachable_cross_account', 0)}")
        
        # Connectivity summary
        conn = org_result.get("connectivity_summary", {})
        if conn:
            print(f"\n>> CONNECTIVITY SUMMARY:")
            print(f"   TGW-connected VPCs: {conn.get('tgw_connected_vpcs', 0)}")
            print(f"   Peered VPCs: {conn.get('peered_vpcs', 0)}")
            print(f"   Isolated VPCs: {conn.get('isolated_vpcs', 0)}")
            if conn.get('cross_account_tgw_connected_vpcs', 0) > 0:
                print(f"   Cross-account TGW VPCs: {conn.get('cross_account_tgw_connected_vpcs', 0)}")
            if conn.get('cross_account_peered_vpcs', 0) > 0:
                print(f"   Cross-account Peered VPCs: {conn.get('cross_account_peered_vpcs', 0)}")
            print(f"   Total TGW Attachments: {conn.get('total_tgw_attachments', 0)}")
            print(f"   Total Peering Connections: {conn.get('total_peering_connections', 0)}")
        
        print(f"\n{'=' * 70}")
        
        if org_rec.get("coverage", {}).get("percentage", 0) < 100:
            exit_code = EXIT_PARTIAL
        
        result = org_result
        
        # Save report based on format
        if args.format == "csv":
            # For org mode, create summary CSV with cross-account info
            csv_output = args.output if args.output.endswith('.csv') else args.output.replace('.json', '.csv')
            with open(csv_output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["account_id", "account_name", "status", "vpcs", "instances", 
                               "per_account_coverage_pct", "reachable_from_org_deployment"])
                
                org_cov = org_rec.get("coverage", {}).get("reachable_by_account", {})
                for acct_id, acct_data in org_result.get("accounts", {}).items():
                    if acct_data.get("status") == "error":
                        writer.writerow([acct_id, acct_data.get("name", ""), "ERROR", 0, 0, 0, 0])
                    else:
                        per_acct_rec = acct_data.get("per_account_recommendation", {})
                        per_acct_cov = per_acct_rec.get("coverage", {})
                        writer.writerow([
                            acct_id,
                            acct_data.get("name", ""),
                            "SUCCESS",
                            acct_data.get("vpcs", 0),
                            acct_data.get("instances", 0),
                            per_acct_cov.get("percentage", 0),
                            org_cov.get(acct_id, 0)
                        ])
            print(f"\n📊 CSV Report saved: {csv_output}")
        elif args.format == "html":
            # For org mode, use unified org HTML generator for consistency across clouds
            html_output = args.output if args.output.endswith('.html') else args.output.replace('.json', '.html')
            export_org_to_html_unified(org_result, html_output, cloud="aws")
            print(f"\n🌐 HTML Report saved: {html_output}")
        else:
            # Save JSON report
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n📄 Organization report saved: {args.output}")
        
        # Save org summary text file (only if not HTML, as HTML includes the summary)
        if args.format != "html":
            txt_output = args.output.replace('.json', '_summary.txt').replace('.csv', '_summary.txt')
            with open(txt_output, 'w') as f:
                f.write(f"AWS Organization Network Reachability Analysis - CROSS-ACCOUNT\n")
                f.write(f"Organization: {org_result.get('org_id', 'N/A')}\n")
                f.write(f"Version: {VERSION}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Accounts Analyzed: {org_result.get('summary', {}).get('successful_accounts', 0)}\n")
                f.write(f"Total Instances: {org_result.get('summary', {}).get('total_instances', 0)}\n")
                f.write("\n" + "=" * 70 + "\n")
                f.write("ORGANIZATION-WIDE RECOMMENDATION\n")
                f.write("=" * 70 + "\n")
                if org_rec:
                    f.write(f"Status: {org_rec.get('status', 'UNKNOWN')}\n")
                    f.write(f"{org_rec.get('message', '')}\n\n")
                    if org_rec.get("deployment_location"):
                        loc = org_rec["deployment_location"]
                        f.write(f"Deploy in Account: {loc.get('account_id')} ({loc.get('account_name')})\n")
                        f.write(f"Region: {loc.get('region')}\n")
                        f.write(f"VPC: {loc.get('vpc_id')}\n")
                        f.write(f"Subnet: {loc.get('subnet_id')}\n")
                    cov = org_rec.get("coverage", {})
                    if cov:
                        f.write(f"\nCoverage: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                              f"({cov.get('percentage', 0):.1f}%)\n")
                f.write("\n" + "=" * 70 + "\n")
                f.write("PER-ACCOUNT BREAKDOWN\n")
                f.write("=" * 70 + "\n")
                # Handle both list and dict formats for accounts
                accounts = org_result.get("accounts", [])
                if isinstance(accounts, list):
                    for acct_data in accounts:
                        acct_id = acct_data.get("account_id", "Unknown")
                        if acct_data.get("status") == "error" or acct_data.get("error"):
                            f.write(f"\nAccount {acct_id}: ERROR - {acct_data.get('error', 'Unknown')}\n")
                        else:
                            f.write(f"\nAccount {acct_id} ({acct_data.get('account_name', 'Unknown')}):\n")
                            f.write(f"  VPCs: {acct_data.get('vpcs', 0)}, Instances: {acct_data.get('instances', 0)}\n")
                            per_acct = acct_data.get("per_account_recommendation", {})
                            if per_acct:
                                f.write(f"  Per-account coverage: {per_acct.get('coverage', {}).get('percentage', 0):.1f}%\n")
                else:
                    for acct_id, acct_data in accounts.items():
                        if acct_data.get("status") == "error":
                            f.write(f"\nAccount {acct_id}: ERROR - {acct_data.get('error', 'Unknown')}\n")
                        else:
                            f.write(f"\nAccount {acct_id} ({acct_data.get('name', 'Unknown')}):\n")
                            f.write(f"  VPCs: {acct_data.get('vpcs', 0)}, Instances: {acct_data.get('instances', 0)}\n")
                            per_acct = acct_data.get("per_account_recommendation", {})
                            if per_acct:
                                f.write(f"  Per-account coverage: {per_acct.get('coverage', {}).get('percentage', 0):.1f}%\n")
            print(f"Summary saved: {txt_output}")
    
    return exit_code, result


def run_azure_analysis(args, start_time):
    """Run Azure-specific network analysis."""
    exit_code = EXIT_SUCCESS
    result = None
    
    # Import Azure analyzer
    try:
        from aws_network_analyzer.azure_analyzer import AzureNetworkAnalyzer, AzureOrgAnalyzer, check_azure_sdk
    except ImportError:
        try:
            from azure_analyzer import AzureNetworkAnalyzer, AzureOrgAnalyzer, check_azure_sdk
        except ImportError:
            print("❌ ERROR: Azure SDK not installed. Install with:", file=sys.stderr)
            print("   pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-subscription", file=sys.stderr)
            return EXIT_ERROR, None
    
    # Check SDK availability
    try:
        check_azure_sdk()
    except ImportError as e:
        print(f"❌ ERROR: {e}", file=sys.stderr)
        return EXIT_ERROR, None
    
    logger.debug(f"Azure Network Reachability Analyzer v{VERSION}")
    
    # Setup Azure credentials
    credentials = None
    if args.tenant_id and args.client_id and args.client_secret:
        try:
            from azure.identity import ClientSecretCredential
            credentials = ClientSecretCredential(
                tenant_id=args.tenant_id,
                client_id=args.client_id,
                client_secret=args.client_secret
            )
            logger.info("Using Azure service principal credentials")
        except Exception as e:
            print(f"❌ ERROR: Failed to create Azure credentials: {e}", file=sys.stderr)
            return EXIT_ERROR, None
    else:
        try:
            from azure.identity import DefaultAzureCredential
            credentials = DefaultAzureCredential()
            logger.info("Using Azure default credentials")
        except Exception as e:
            print(f"❌ ERROR: Failed to get Azure credentials: {e}", file=sys.stderr)
            return EXIT_ERROR, None
    
    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",")]
    
    if args.mode == "account":
        print(f"Azure Network Reachability Analyzer v{VERSION}")
        
        if args.subscription_id:
            print(f"Subscription: {args.subscription_id}")
            subscription_id = args.subscription_id
        else:
            # Get default subscription
            try:
                from azure.mgmt.subscription import SubscriptionClient
                sub_client = SubscriptionClient(credentials)
                subscriptions = list(sub_client.subscriptions.list())
                if not subscriptions:
                    print("❌ ERROR: No Azure subscriptions found", file=sys.stderr)
                    return EXIT_ERROR, None
                subscription_id = subscriptions[0].subscription_id
                print(f"Using subscription: {subscriptions[0].display_name} ({subscription_id})")
            except Exception as e:
                print(f"❌ ERROR: Failed to list Azure subscriptions: {e}", file=sys.stderr)
                return EXIT_ERROR, None
        
        # Fetch all regions if not specified (consistent with AWS/GCP behavior)
        if not regions:
            print("Discovering Azure regions...")
            try:
                from azure.mgmt.subscription import SubscriptionClient
                sub_client = SubscriptionClient(credentials)
                locations = sub_client.subscriptions.list_locations(subscription_id)
                regions = [loc.name for loc in locations if loc.name]
                print(f"Found {len(regions)} regions")
            except Exception as e:
                print(f"Warning: Could not fetch regions, using defaults: {e}")
                regions = None
        
        analyzer = AzureNetworkAnalyzer(
            subscription_id=subscription_id,
            credentials=credentials,
            regions=regions,
            quiet=args.quiet
        )
        
        print("\nAnalyzing Azure network infrastructure...")
        summary = analyzer.discover_all(quiet=args.quiet)
        
        scan_duration = time.time() - start_time
        print(f"\nDiscovered: {summary['total_vnets']} VNets, {summary['total_vms']} VMs")
        print(f"Scan completed in {scan_duration:.1f} seconds")
        
        report = analyzer.generate_report()
        report["scan_duration_seconds"] = round(scan_duration, 1)
        report["version"] = VERSION
        
        # Print summary
        rec = report.get("recommendation", {})
        print(f"\n{'=' * 70}")
        print(f"AZURE DEPLOYMENT RECOMMENDATION: {rec.get('status', 'UNKNOWN')}")
        print(f"{'=' * 70}")
        print(rec.get("message", ""))
        
        if rec.get("deployment_location"):
            loc = rec["deployment_location"]
            print(f"\n>> DEPLOY IN:")
            print(f"   Location: {loc.get('location')}")
            print(f"   VNet:     {loc.get('vnet_name')}")
            print(f"   Subnet:   {loc.get('subnet_name')}")
            print(f"   CIDR:     {loc.get('subnet_cidr')}")
        
        cov = rec.get("coverage", {})
        if cov:
            print(f"\n>> COVERAGE: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                  f"({cov.get('percentage', 0):.1f}%)")
            if cov.get("percentage", 0) < 100:
                exit_code = EXIT_PARTIAL
        
        print(f"{'=' * 70}")
        
        result = report
        
        # Save report
        _save_report(args, result, "azure")
    
    elif args.mode == "org":
        print(f"Azure Network Reachability Analyzer v{VERSION}")
        print("Tenant mode - analyzing all subscriptions...\n")
        
        org_analyzer = AzureOrgAnalyzer(
            credentials=credentials,
            regions=regions,
            max_parallel=args.parallel,
            max_parallel_subscriptions=args.parallel_accounts,
            quiet=args.quiet
        )
        
        print("Discovering Azure subscriptions...")
        summary = org_analyzer.discover_organization(quiet=args.quiet)
        
        print(f"\n✅ Discovery complete:")
        print(f"   Subscriptions scanned: {summary['successful_subscriptions']}/{summary['total_subscriptions']}")
        print(f"   Total VNets: {summary['total_vnets']}")
        print(f"   Total VMs: {summary.get('total_vms', summary.get('total_instances', 0))}")
        
        report = org_analyzer.generate_org_report()
        report["version"] = VERSION
        
        # Print organization recommendation
        org_rec = report.get("org_recommendation", {})
        if org_rec:
            print(f"\n{'=' * 70}")
            print(f"AZURE ORGANIZATION RECOMMENDATION: {org_rec.get('status', 'UNKNOWN')}")
            print(f"{'=' * 70}")
            print(org_rec.get("message", ""))
            
            if org_rec.get("deployment_location"):
                loc = org_rec["deployment_location"]
                print(f"\n>> BEST LOCATION:")
                print(f"   Subscription: {loc.get('subscription_name')}")
                print(f"   Location:     {loc.get('location')}")
                print(f"   VNet:         {loc.get('vnet_name')}")
                print(f"   Subnet:       {loc.get('subnet_name')}")
            
            cov = org_rec.get("coverage", {})
            if cov:
                print(f"\n>> COVERAGE: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                      f"({cov.get('percentage', 0):.1f}%)")
                if cov.get("percentage", 0) < 100:
                    exit_code = EXIT_PARTIAL
        
        print(f"\n{'=' * 70}")
        
        result = report
        _save_report(args, result, "azure")
    
    return exit_code, result


def run_gcp_analysis(args, start_time):
    """Run GCP-specific network analysis."""
    exit_code = EXIT_SUCCESS
    result = None
    
    # Import GCP analyzer
    try:
        from aws_network_analyzer.gcp_analyzer import GCPNetworkAnalyzer, GCPOrgAnalyzer, check_gcp_sdk
    except ImportError:
        try:
            from gcp_analyzer import GCPNetworkAnalyzer, GCPOrgAnalyzer, check_gcp_sdk
        except ImportError:
            print("❌ ERROR: GCP SDK not installed. Install with:", file=sys.stderr)
            print("   pip install google-cloud-compute google-cloud-resource-manager google-auth", file=sys.stderr)
            return EXIT_ERROR, None
    
    # Check SDK availability
    try:
        check_gcp_sdk()
    except ImportError as e:
        print(f"❌ ERROR: {e}", file=sys.stderr)
        return EXIT_ERROR, None
    
    logger.debug(f"GCP Network Reachability Analyzer v{VERSION}")
    
    # Setup GCP credentials
    credentials = None
    if args.key_file:
        try:
            from google.oauth2 import service_account
            credentials = service_account.Credentials.from_service_account_file(args.key_file)
            logger.info(f"Using GCP service account from {args.key_file}")
        except Exception as e:
            print(f"❌ ERROR: Failed to load GCP key file: {e}", file=sys.stderr)
            return EXIT_ERROR, None
    else:
        logger.info("Using GCP application default credentials")
    
    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",")]
    
    if args.mode == "account":
        if not args.gcp_project:
            print("❌ ERROR: GCP project mode requires --project", file=sys.stderr)
            return EXIT_ERROR, None
        
        print(f"GCP Network Reachability Analyzer v{VERSION}")
        print(f"Project: {args.gcp_project}")
        
        analyzer = GCPNetworkAnalyzer(
            project_id=args.gcp_project,
            credentials=credentials,
            regions=regions,
            quiet=args.quiet
        )
        
        print("\nAnalyzing GCP network infrastructure...")
        summary = analyzer.discover_all(quiet=args.quiet)
        
        scan_duration = time.time() - start_time
        print(f"\nDiscovered: {summary['total_vpcs']} VPCs, {summary['total_instances']} VMs")
        print(f"Scan completed in {scan_duration:.1f} seconds")
        
        report = analyzer.generate_report()
        report["scan_duration_seconds"] = round(scan_duration, 1)
        report["version"] = VERSION
        
        # Print summary
        rec = report.get("recommendation", {})
        print(f"\n{'=' * 70}")
        print(f"GCP DEPLOYMENT RECOMMENDATION: {rec.get('status', 'UNKNOWN')}")
        print(f"{'=' * 70}")
        print(rec.get("message", ""))
        
        if rec.get("deployment_location"):
            loc = rec["deployment_location"]
            print(f"\n>> DEPLOY IN:")
            print(f"   Region:  {loc.get('region')}")
            print(f"   VPC:     {loc.get('vpc_name')}")
            print(f"   Subnet:  {loc.get('subnet_name')}")
            print(f"   CIDR:    {loc.get('subnet_cidr')}")
        
        cov = rec.get("coverage", {})
        if cov:
            print(f"\n>> COVERAGE: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                  f"({cov.get('percentage', 0):.1f}%)")
            if cov.get("percentage", 0) < 100:
                exit_code = EXIT_PARTIAL
        
        print(f"{'=' * 70}")
        
        result = report
        _save_report(args, result, "gcp")
    
    elif args.mode == "org":
        print(f"GCP Network Reachability Analyzer v{VERSION}")
        print("Org mode - analyzing all projects...\n")
        
        org_analyzer = GCPOrgAnalyzer(
            credentials=credentials,
            regions=regions,
            max_parallel=args.parallel,
            max_parallel_projects=args.parallel_accounts,
            quiet=args.quiet
        )
        
        print("Discovering GCP projects...")
        summary = org_analyzer.discover_organization(quiet=args.quiet, max_projects=args.max_accounts)
        
        print(f"\n✅ Discovery complete:")
        print(f"   Projects scanned: {summary['successful_projects']}/{summary['total_projects']}")
        print(f"   Total VPCs: {summary['total_vpcs']}")
        print(f"   Total VMs: {summary['total_instances']}")
        
        report = org_analyzer.generate_org_report()
        report["version"] = VERSION
        
        # Print organization recommendation
        org_rec = report.get("org_recommendation", {})
        if org_rec:
            print(f"\n{'=' * 70}")
            print(f"GCP ORGANIZATION RECOMMENDATION: {org_rec.get('status', 'UNKNOWN')}")
            print(f"{'=' * 70}")
            print(org_rec.get("message", ""))
            
            if org_rec.get("deployment_location"):
                loc = org_rec["deployment_location"]
                print(f"\n>> BEST LOCATION:")
                print(f"   Project: {loc.get('project_name')}")
                print(f"   Region:  {loc.get('region')}")
                print(f"   VPC:     {loc.get('vpc_name')}")
                print(f"   Subnet:  {loc.get('subnet_name')}")
            
            cov = org_rec.get("coverage", {})
            if cov:
                print(f"\n>> COVERAGE: {cov.get('reachable_instances')}/{cov.get('total_instances')} "
                      f"({cov.get('percentage', 0):.1f}%)")
                if cov.get("percentage", 0) < 100:
                    exit_code = EXIT_PARTIAL
        
        print(f"\n{'=' * 70}")
        
        result = report
        _save_report(args, result, "gcp")
    
    return exit_code, result


def _save_report(args, result, cloud: str):
    """Save report to file based on format - unified for Azure/GCP with feature parity to AWS."""
    is_org_mode = result.get("mode") in ["organization", "org"]
    
    if args.format == "csv":
        csv_output = args.output if args.output.endswith('.csv') else args.output.replace('.json', '.csv')
        
        if is_org_mode:
            # Org mode CSV - detailed subscription/project summary
            with open(csv_output, 'w', newline='') as f:
                writer = csv.writer(f)
                
                if cloud == "azure":
                    # Azure org mode - subscription summary
                    writer.writerow(["subscription_id", "subscription_name", "status", "vnets", "vms", 
                                   "per_subscription_coverage_pct", "reachable_from_org_deployment"])
                    
                    org_rec = result.get("org_recommendation", {})
                    for sub_id, sub_data in result.get("subscriptions", {}).items():
                        if sub_data.get("status") == "error":
                            writer.writerow([sub_id, sub_data.get("name", ""), "ERROR", 0, 0, 0, 0])
                        else:
                            report = sub_data.get("report", {})
                            rec = report.get("recommendation", {})
                            cov = rec.get("coverage", {})
                            writer.writerow([
                                sub_id,
                                sub_data.get("name", ""),
                                "SUCCESS",
                                sub_data.get("vnets", 0),
                                sub_data.get("vms", 0),
                                cov.get("percentage", 0),
                                cov.get("reachable_instances", cov.get("reachable_vms", 0))
                            ])
                else:
                    # GCP org mode - project summary
                    writer.writerow(["project_id", "project_name", "status", "vpcs", "instances", 
                                   "per_project_coverage_pct", "reachable_from_org_deployment"])
                    
                    for proj_id, proj_data in result.get("projects", {}).items():
                        if proj_data.get("status") == "error":
                            writer.writerow([proj_id, proj_data.get("name", ""), "ERROR", 0, 0, 0, 0])
                        else:
                            report = proj_data.get("report", {})
                            rec = report.get("recommendation", {})
                            cov = rec.get("coverage", {})
                            writer.writerow([
                                proj_id,
                                proj_data.get("name", ""),
                                "SUCCESS",
                                proj_data.get("vpcs", 0),
                                proj_data.get("instances", 0),
                                cov.get("percentage", 0),
                                cov.get("reachable_instances", 0)
                            ])
        else:
            # Single subscription/project mode - detailed instance list CSV
            with open(csv_output, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Get all instances
                all_instances = result.get("all_instances", result.get("all_vms", []))
                
                if all_instances:
                    if cloud == "azure":
                        writer.writerow(["location", "vnet_name", "subnet_id", "vm_id", "vm_name", 
                                       "private_ip", "public_ip", "state", "reachable"])
                        for inst in all_instances:
                            writer.writerow([
                                inst.get("location", ""),
                                inst.get("vnet_name", ""),
                                inst.get("subnet_id", ""),
                                inst.get("vm_id", ""),
                                inst.get("name", ""),
                                inst.get("private_ip", ""),
                                inst.get("public_ip", ""),
                                inst.get("state", ""),
                                "Yes" if inst.get("reachable") else "No"
                            ])
                    else:  # GCP
                        writer.writerow(["region", "zone", "vpc_name", "subnet_name", "instance_id", "instance_name", 
                                       "private_ip", "public_ip", "state", "reachable"])
                        for inst in all_instances:
                            writer.writerow([
                                inst.get("region", ""),
                                inst.get("zone", ""),
                                inst.get("vpc_name", ""),
                                inst.get("subnet_name", ""),
                                inst.get("instance_id", ""),
                                inst.get("name", ""),
                                inst.get("private_ip", ""),
                                inst.get("public_ip", inst.get("external_ip", "")),
                                inst.get("state", ""),
                                "Yes" if inst.get("reachable") else "No"
                            ])
                else:
                    # No instances - write summary
                    writer.writerow(["metric", "value"])
                    rec = result.get("recommendation", {})
                    cov = rec.get("coverage", {})
                    writer.writerow(["cloud", cloud])
                    writer.writerow(["status", rec.get("status", "")])
                    writer.writerow(["total_instances", cov.get("total_instances", 0)])
                    writer.writerow(["reachable_instances", cov.get("reachable_instances", 0)])
                    writer.writerow(["coverage_pct", cov.get("percentage", 0)])
        
        print(f"\n📊 CSV Report saved: {csv_output}")
        
    elif args.format == "html":
        html_output = args.output if args.output.endswith('.html') else args.output.replace('.json', '.html')
        
        if is_org_mode:
            # For org mode, use the AWS-style org HTML generator for consistency
            export_org_to_html_unified(result, html_output, cloud)
            print(f"\n🌐 HTML Report saved: {html_output}")
            return
        
        # Single account/subscription/project mode - use HTML report generator
        try:
            from .html_report import generate_html_report
            generate_html_report(result, html_output, cloud)
            print(f"\n🌐 HTML Report saved: {html_output}")
            return
        except ImportError:
            print("⚠️  HTML module not available, falling back to basic HTML")
        except Exception as e:
            print(f"⚠️  HTML report failed ({e}), falling back to basic HTML")
        
        # Basic HTML fallback
        rec = result.get("recommendation", result.get("org_recommendation", {}))
        cov = rec.get("coverage", {})
        html = f'''<!DOCTYPE html>
<html><head><title>{cloud.upper()} Network Reachability Report</title>
<style>body{{font-family:Arial;padding:20px}}h1{{color:#333}}
.box{{border:1px solid #ddd;padding:15px;margin:10px 0;border-radius:5px}}
.success{{border-left:4px solid #28a745}}.warning{{border-left:4px solid #ffc107}}</style>
</head><body>
<h1>{cloud.upper()} Network Reachability Report</h1>
<div class="box {'success' if rec.get('status')=='SUCCESS' else 'warning'}">
<h2>Status: {rec.get('status', 'UNKNOWN')}</h2>
<p>{rec.get('message', '')}</p>
</div>
<div class="box"><h3>Coverage</h3>
<p>{cov.get('reachable_instances', 0)}/{cov.get('total_instances', 0)} 
({cov.get('percentage', 0):.1f}%)</p></div>
<p>Generated: {datetime.now().isoformat()}</p>
</body></html>'''
        with open(html_output, 'w') as f:
            f.write(html)
        print(f"\n🌐 HTML Report saved: {html_output}")
    else:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n📄 Report saved: {args.output}")


if __name__ == "__main__":
    main()
