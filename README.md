# Multi-Cloud Network Reachability Analyzer

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer/releases/tag/v1.0.0)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Clouds](https://img.shields.io/badge/clouds-AWS%20|%20Azure%20|%20GCP-orange.svg)](#supported-clouds)

A comprehensive multi-cloud tool to analyze network infrastructure and find the optimal deployment location for a scanner VM that can reach all other VMs across VPCs/VNets, regions, and accounts/subscriptions/projects. Uses a **greedy set cover algorithm** to recommend the minimum number of deployments needed for 100% coverage.

**GitHub Repository:** https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer

## Table of Contents

- [Supported Clouds](#supported-clouds)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Line Reference](#command-line-reference)
- [Output Examples](#output-examples)
- [Exit Codes](#exit-codes)
- [Enhanced Features](#enhanced-features-v410)
- [Required Permissions](#required-permissions)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)

## Supported Clouds

| Cloud | Account Mode | Organization Mode | Status |
|-------|--------------|-------------------|--------|
| **AWS** | ✅ Single Account | ✅ AWS Organizations | Production |
| **Azure** | ✅ Single Subscription | ✅ All Subscriptions (Tenant) | Production |
| **GCP** | ✅ Single Project | ✅ All Projects | Production |

## Features

### Discovery & Analysis
- **Multi-Cloud Support**: AWS, Azure, and GCP with unified CLI interface
- **Multi-Region Discovery**: Scans all regions in parallel (AWS: ~20, Azure: ~60, GCP: ~40 regions)
- **Organization-Wide Analysis**: Scans all accounts/subscriptions/projects with cross-account reachability
- **Parallel Scanning**: 10 regions concurrent, 20 accounts concurrent for org mode (configurable)
- **Network Analysis**: VPCs/VNets, subnets, route tables, security groups/NSGs, NACLs, NAT gateways

### Connectivity Detection
- **AWS**: Transit Gateways (TGW), VPC Peering (including cross-region), Internet Gateways, NAT Gateways
- **Azure**: VNet Peering, Virtual WAN, NAT Gateway, Service Endpoints
- **GCP**: VPC Peering, Shared VPC, Private Google Access, Cloud NAT

### Recommendations
- **Optimal Deployment Location**: Best single location for maximum VM coverage
- **Full Coverage Plan**: Minimum set of deployments needed to reach 100% of instances (greedy set cover)
- **Coverage Analysis**: Percentage of VMs reachable from each recommended location
- **Unreachable Instances**: Detailed list of VMs that cannot be reached and why

### Output & Reporting
- **Multiple Formats**: JSON, CSV, and HTML reports
- **Unified HTML Reports**: Golden template with consistent layout across all clouds
- **D3.js Visualization**: Network topology visualization in HTML reports
- **Unified Schema**: Consistent output format across all clouds for automation
- **CI/CD Ready**: Exit codes for automation pipelines (0=success, 1=partial, 2=error)

### Advanced Features
- **Caching**: Cache discovery results to speed up re-runs (TTL configurable)
- **Resumable Scans**: Resume interrupted organization scans by scan ID
- **Progress Tracking**: Enhanced progress bar with ETA, throughput, and success/failure counts
- **Dry Run Mode**: Preview scan scope without executing (validates credentials and regions)

## Architecture

### High-Level Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   main.py    │────▶│ Cloud Router │────▶│   Analyzer   │
│  (CLI args)  │     │ aws/azure/gcp│     │  (Discover)  │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
                                                  ▼
                     ┌──────────────────────────────────────┐
                     │        Parallel Discovery            │
                     │  ┌────────┐ ┌────────┐ ┌────────┐    │
                     │  │Region 1│ │Region 2│ │Region N│    │
                     │  └────────┘ └────────┘ └────────┘    │
                     └──────────────────────────────────────┘
                                                  │
                                                  ▼
                     ┌──────────────────────────────────────┐
                     │      Reachability Analysis           │
                     │  • Build connectivity graph          │
                     │  • Check TGW/Peering/Same-VPC        │
                     │  • Calculate coverage from each loc  │
                     └──────────────────────────────────────┘
                                                  │
                                                  ▼
                     ┌──────────────────────────────────────┐
                     │      Greedy Set Cover Algorithm      │
                     │  • Find minimum deployment set       │
                     │  • Prioritize by coverage            │
                     └──────────────────────────────────────┘
                                                  │
                                                  ▼
                     ┌──────────────────────────────────────┐
                     │         Report Generation            │
                     │  • JSON / CSV / HTML output          │
                     │  • Unified golden template           │
                     └──────────────────────────────────────┘
```

### Module Structure

| Module | Purpose |
|--------|---------|
| `main.py` | Entry point, CLI parsing, cloud routing |
| `base.py` | Shared constants, enums, data classes |
| `utils.py` | Retry logic, progress indicators, CIDR utilities |
| `network_reachability.py` | AWS analyzer (VPCs, TGW, Peering) |
| `azure_analyzer.py` | Azure analyzer (VNets, Peering, vWAN) |
| `gcp_analyzer.py` | GCP analyzer (VPCs, Peering, Shared VPC) |
| `html_report.py` | Unified HTML report generator |
| `exporters.py` | JSON, CSV, Summary exporters |
| `cache.py` | Caching and resumable scan state |

## Installation

### Install from GitHub (Recommended)

```bash
# Install directly from GitHub (includes all cloud SDKs)
pip install git+https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer.git@v1.0.0

# Verify installation
aws-network-analyzer --version
```

### Install from Source

```bash
git clone https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer.git
cd multi-cloud-network-analyzer
pip install .
```

### Using Virtual Environment (Recommended)

```bash
git clone https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer.git
cd multi-cloud-network-analyzer
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install .
```

### Dependencies

All cloud SDKs are included by default:
- **AWS**: boto3, botocore
- **Azure**: azure-identity, azure-mgmt-compute, azure-mgmt-network, azure-mgmt-resource, azure-mgmt-subscription
- **GCP**: google-cloud-compute, google-cloud-resource-manager, google-auth

## Quick Start

### AWS
```bash
# Single account - all regions
aws-network-analyzer --cloud aws --mode account

# Specific regions
aws-network-analyzer --cloud aws --mode account --regions us-east-1,us-west-2

# Organization-wide
aws-network-analyzer --cloud aws --mode org
```

### Azure
```bash
# Single subscription (uses Azure CLI credentials)
aws-network-analyzer --cloud azure --mode subscription

# With service principal
aws-network-analyzer --cloud azure --mode subscription \
  --tenant-id YOUR_TENANT_ID \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET

# All subscriptions in tenant
aws-network-analyzer --cloud azure --mode tenant
```

### GCP
```bash
# Single project (uses gcloud credentials)
aws-network-analyzer --cloud gcp --mode project --project my-project-id

# With service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
aws-network-analyzer --cloud gcp --mode project --project my-project-id

# All projects in organization
aws-network-analyzer --cloud gcp --mode org
```

### HTML Reports
```bash
# Generate HTML report
aws-network-analyzer --cloud aws --mode account --format html --output report.html

# For organization mode
aws-network-analyzer --cloud aws --mode org --format html --output aws_org_report.html
```

### Org Mode with Limits
```bash
# Limit number of accounts (useful for testing)
aws-network-analyzer --cloud aws --mode org --max-accounts 10

# Adjust parallelism
aws-network-analyzer --cloud aws --mode org --parallel 5 --parallel-accounts 10
```

## Command Line Reference

### Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--version` | Show version number | - |
| `--cloud` | Cloud provider: `aws`, `azure`, or `gcp` | `aws` |
| `--mode` | Analysis mode (cloud-specific, see below) | Required |
| `--regions` | Comma-separated regions to scan | All regions |
| `--output` | Output file path | `reachability_report.json` |
| `--format` | Output format: `json`, `csv`, or `html` | `json` |
| `--quiet` | Suppress detailed output | False |
| `--verbose` | Enable debug logging | False |
| `--log-file` | Write logs to file | None |
| `--parallel` | Max parallel region scans | 10 |
| `--parallel-accounts` | Max parallel account scans (org mode) | 20 |
| `--max-accounts` | Limit accounts to scan in org mode | None (all) |
| `--timeout` | Global timeout in seconds | 600 |
| `--dry-run` | Preview scan scope only | False |

#### Cloud-Specific Mode Options

| Cloud | Single Scope | Multi-Scope |
|-------|--------------|-------------|
| AWS | `--mode account` | `--mode org` |
| Azure | `--mode subscription` | `--mode tenant` |
| GCP | `--mode project` | `--mode org` |

### AWS Authentication Options

| Option | Description |
|--------|-------------|
| `--profile` | AWS CLI profile name |
| `--access-key` | AWS access key ID |
| `--secret-key` | AWS secret access key |
| `--session-token` | AWS session token (for temporary credentials) |
| `--region` | Default AWS region for API calls |
| `--assume-role` | IAM role name for org mode cross-account access |

**AWS Authentication Priority:**
1. Explicit credentials (`--access-key`, `--secret-key`)
2. AWS profile (`--profile`)
3. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
4. IAM role (EC2 instance profile, ECS task role)
5. Default credential chain (`~/.aws/credentials`)

### Azure Authentication Options

| Option | Description |
|--------|-------------|
| `--tenant-id` | Azure tenant ID |
| `--client-id` | Azure application/client ID |
| `--client-secret` | Azure client secret |
| `--subscription-id` | Specific subscription ID (account mode) |

**Azure Authentication Priority:**
1. Explicit credentials (`--tenant-id`, `--client-id`, `--client-secret`)
2. Environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`)
3. Azure CLI credentials (`az login`)
4. Managed Identity

### GCP Authentication Options

| Option | Description |
|--------|-------------|
| `--project` | GCP project ID (required for account mode) |
| `--key-file` | Path to service account key JSON file |

**GCP Authentication Priority:**
1. Service account key file (`--key-file`)
2. Environment variable (`GOOGLE_APPLICATION_CREDENTIALS`)
3. Application Default Credentials (`gcloud auth application-default login`)

## Output Examples

### Console Output
```
GCP Network Reachability Analyzer v1.0.0
Project: my-project-1513669048551

Analyzing GCP network infrastructure...
Scanning 130 GCP zones across 43 regions...
  [██████████████████████████████] 130/130 (100%) - asia-east1-a (37.8s)

Discovered: 50 VPCs, 232 VMs
Scan completed in 37.8 seconds

======================================================================
GCP DEPLOYMENT RECOMMENDATION: PARTIAL
======================================================================
Primary location covers 81.5% of instances. Multi-region deployment recommended.

>> DEPLOY IN:
   Region:  asia-east1
   VPC:     default
   Subnet:  default
   CIDR:    10.140.0.0/20

>> COVERAGE: 189/232 (81.5%)
======================================================================
```

### JSON Report Structure
```json
{
  "cloud": "gcp",
  "project_id": "my-project-1513669048551",
  "recommendation": {
    "status": "PARTIAL",
    "message": "Primary location covers 81.5% of instances.",
    "deployment_location": {
      "region": "asia-east1",
      "vpc_name": "default",
      "subnet_name": "default",
      "subnet_cidr": "10.140.0.0/20"
    },
    "coverage": {
      "percentage": 81.5,
      "total_instances": 232,
      "reachable_instances": 189
    },
    "unreachable_instances": [...]
  },
  "full_coverage_plan": {
    "total_deployments_needed": 3,
    "total_instances_covered": 232,
    "coverage_percentage": 100.0,
    "deployments": [
      {
        "deployment_order": 1,
        "region": "asia-east1",
        "vpc_name": "default",
        "subnet_cidr": "10.140.0.0/20",
        "covers_instances": 189,
        "cumulative_percentage": 81.5
      },
      {
        "deployment_order": 2,
        "region": "us-central1",
        "vpc_name": "prod-vpc",
        "covers_instances": 35,
        "cumulative_percentage": 96.6
      },
      {
        "deployment_order": 3,
        "region": "europe-west1",
        "vpc_name": "isolated-vpc",
        "covers_instances": 8,
        "cumulative_percentage": 100.0
      }
    ]
  },
  "summary": {
    "total_regions_scanned": 43,
    "total_vpcs": 50,
    "total_instances": 232,
    "deployments_for_full_coverage": 3
  },
  "connectivity_summary": {
    "peered_vpcs": 12,
    "isolated_vpcs": 38
  },
  "generated_at": "2026-02-05T10:30:00.000000",
  "version": "1.0.0"
}
```

## Exit Codes

| Code | Meaning | Use Case |
|------|---------|----------|
| `0` | Success | All instances reachable from single location |
| `1` | Partial | Some instances unreachable, multi-deployment needed |
| `2` | Error | Credential, validation, or runtime error |
| `3` | Timeout | Global timeout exceeded |
| `130` | Interrupted | User pressed Ctrl+C |

## Enhanced Features

### HTML Reports

Generate beautiful, professional HTML reports with the "golden template" layout:

```bash
# Generate HTML report for single account
aws-network-analyzer --cloud aws --mode account --format html --output report.html

# For org mode
aws-network-analyzer --cloud aws --mode org --format html --output aws_org_report.html
```

**HTML Report Features:**
- Summary cards showing total VPCs, Instances, and Coverage %
- Full Coverage Plan table with recommended deployments
- Color-coded coverage indicators (green=100%, amber=partial, red=0%)
- Expandable instance details section
- Cloud-specific labels (VPC/VNet, Instances/VMs, Account/Subscription/Project)
- Responsive design with modern styling

### Caching

Speed up re-runs by caching discovery results:

```bash
# Enable caching (default TTL: 24 hours)
aws-network-analyzer --cloud aws --mode account --cache

# Custom cache TTL (2 hours)
aws-network-analyzer --cloud aws --mode account --cache --cache-ttl 2

# Force fresh scan (ignore cache)
aws-network-analyzer --cloud aws --mode account --no-cache
```

Cache location: `~/.aws-network-analyzer/cache/`

### Resumable Scans

Resume interrupted organization scans:

```bash
# Start org scan (state is saved automatically)
aws-network-analyzer --cloud aws --mode org

# If interrupted (Ctrl+C), list resumable scans
aws-network-analyzer --list-resumable

# Resume a specific scan
aws-network-analyzer --resume aws_org_20260203_153045
```

State location: `~/.aws-network-analyzer/state/`

### Enhanced Progress Tracking

For large organizations (100+ accounts), the progress indicator shows:
- Visual progress bar with percentage
- ETA based on rolling average
- Throughput (accounts/second)
- Success/failure count
- Current account being scanned

```
  [████████████░░░░░░░░░░░░░░░░░░] 42/150 (28%) ✓40 ✗2 | 2.1/min | ETA: 51.4m | account-xyz-prod
```

## Required Permissions

### AWS IAM Policy

**For Single Account Mode:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NetworkDiscovery",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeRegions",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**For Organization Mode** (add to above):
```json
{
  "Sid": "OrganizationAccess",
  "Effect": "Allow",
  "Action": [
    "organizations:ListAccounts",
    "organizations:DescribeOrganization",
    "sts:AssumeRole"
  ],
  "Resource": "*"
}
```

**Cross-Account Role** (must exist in each member account):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
Default role name: `OrganizationAccountAccessRole` (can be changed with `--assume-role`)

### Azure RBAC Roles

**For Single Subscription Mode:**
- **Reader** role on the subscription

**For Tenant-Wide Mode (all subscriptions):**
- **Reader** role on each subscription, OR
- **Reader** role at Management Group level (inherits to subscriptions)

**Service Principal Permissions:**
```
Microsoft.Compute/virtualMachines/read
Microsoft.Network/virtualNetworks/read
Microsoft.Network/virtualNetworks/subnets/read
Microsoft.Network/networkInterfaces/read
Microsoft.Network/publicIPAddresses/read
Microsoft.Network/natGateways/read
Microsoft.Network/routeTables/read
Microsoft.Network/networkSecurityGroups/read
Microsoft.Resources/subscriptions/read
```

### GCP IAM Roles

**For Single Project Mode:**
- **Compute Viewer** (`roles/compute.viewer`) on the project

**For Organization Mode (all projects):**
- **Compute Viewer** on each project, OR
- **Compute Viewer** at folder/organization level
- **Folder Viewer** or **Organization Viewer** to list projects

**Specific Permissions:**
```
compute.instances.list
compute.networks.list
compute.subnetworks.list
compute.regions.list
compute.zones.list
resourcemanager.projects.list
```

## How It Works

### Discovery Phase

Each cloud analyzer performs parallel discovery:

| Cloud | Discovery Method | Rate Limiting |
|-------|------------------|---------------|
| **AWS** | Per-region parallel scan with ThreadPoolExecutor | Exponential backoff with jitter |
| **Azure** | Single-fetch all resources, then filter by region | HTTP 429 retry handling |
| **GCP** | Global VPC discovery, per-zone instance scan | Quota exceeded retry |

### Reachability Analysis

The analyzer builds a connectivity graph and checks if VPC A can reach VPC B:

```python
def can_reach(source_vpc, target_vpc):
    # 1. Same VPC → Always reachable
    if source_vpc == target_vpc:
        return True, "same_vpc"
    
    # 2. Transit Gateway → Check shared TGW attachment
    if shared_tgw_exists(source_vpc, target_vpc):
        return True, "tgw"
    
    # 3. VPC Peering → Check active peering connection
    if peering_exists(source_vpc, target_vpc):
        return True, "peering"
    
    return False, None
```

### Full Coverage Algorithm

Uses **greedy set cover** to find minimum deployments:

```
1. Build candidate map: each (VPC, subnet) → set of reachable instances
2. While uncovered instances exist:
   a. Find candidate covering MOST uncovered instances
   b. Add to deployment list with coverage details
   c. Remove covered instances from uncovered set
3. Return ordered deployment list
```

This guarantees the minimum number of scanner deployments for 100% coverage.

### Connectivity Types Detected

| Cloud | Connectivity Type | Detection Method |
|-------|------------------|------------------|
| **AWS** | Same VPC | VPC ID match |
| **AWS** | Transit Gateway | Shared TGW attachment |
| **AWS** | VPC Peering | Active peering connection |
| **AWS** | Inter-region TGW | TGW peering attachment |
| **Azure** | Same VNet | VNet ID match |
| **Azure** | VNet Peering | Peering state = Connected |
| **Azure** | Virtual WAN | Hub-spoke topology |
| **GCP** | Same VPC | VPC name match |
| **GCP** | VPC Peering | Peering state = ACTIVE |
| **GCP** | Shared VPC | Host project connection |

## Feature Comparison

| Feature | AWS | Azure | GCP |
|---------|-----|-------|-----|
| Account/Single Mode | ✅ | ✅ | ✅ |
| Organization Mode | ✅ | ✅ | ✅ |
| Region Filtering | ✅ | ✅ | ✅ |
| All Regions by Default | ✅ | ✅ | ✅ |
| VPC/VNet Peering Detection | ✅ | ✅ | ✅ |
| Transit Gateway | ✅ | ❌ | ❌ |
| Shared VPC | ❌ | ❌ | ✅ |
| JSON/CSV/HTML Output | ✅ | ✅ | ✅ |
| Parallel Scanning | ✅ | ✅ | ✅ |
| Retry with Backoff | ✅ | ✅ | ✅ |
| Dry Run Mode | ✅ | ✅ | ✅ |

## Project Structure

```
aws-network-analyzer/
├── pyproject.toml              # Package configuration & dependencies
├── requirements.txt            # Python dependencies (minimal)
├── README.md                   # This documentation
├── CHANGELOG.md                # Version history
├── LICENSE                     # MIT License
├── MANIFEST.in                 # Package manifest
├── src/aws_network_analyzer/   # Package source
│   ├── __init__.py             # Package exports
│   ├── main.py                 # Multi-cloud CLI entry point (3800+ lines)
│   ├── base.py                 # Shared constants, enums, data classes
│   ├── utils.py                # Retry logic, progress, CIDR utilities
│   ├── network_reachability.py # AWS analyzer (VPCs, TGW, Peering)
│   ├── azure_analyzer.py       # Azure analyzer (VNets, Peering)
│   ├── gcp_analyzer.py         # GCP analyzer (VPCs, Peering)
│   ├── html_report.py          # Unified HTML report generator
│   ├── exporters.py            # JSON, CSV, Summary exporters
│   └── cache.py                # Caching & resumable scan state
└── tests/
    ├── __init__.py
    └── test_analyzer.py        # Unit tests (36+ tests)
```

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest

# Run all tests
pytest tests/ -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=aws_network_analyzer --cov-report=html
```

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| AWS Analyzer | 12 | VPC discovery, TGW, peering, instances |
| Azure Analyzer | 8 | VNet discovery, peering, VMs |
| GCP Analyzer | 8 | VPC discovery, peering, instances |
| Cache Module | 4 | Caching, state management |
| HTML Report | 4 | Report generation, templates |

### Dry Run Testing

Test credentials and scope without executing:

```bash
# Preview AWS org scan
aws-network-analyzer --cloud aws --mode org --dry-run

# Preview Azure tenant scan
aws-network-analyzer --cloud azure --mode tenant --dry-run

# Preview GCP org scan
aws-network-analyzer --cloud gcp --mode org --dry-run
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full version history.

### v1.0.0 (2025-02-05)
- **First Stable Release** - Production-ready multi-cloud network analyzer
- **Multi-Cloud Support** - AWS, Azure, and GCP with unified CLI
- **Organization-Wide Scanning** - Scan entire AWS Organizations, Azure Tenants, GCP Organizations
- **VPC/VNet Peering Detection** - Automatically detect peered networks
- **Transit Gateway Support** - Detect AWS Transit Gateway attachments
- **Internet Access Detection** - AWS (IGW, NAT), Azure (Public IP, NAT), GCP (External IP, Cloud NAT)
- **Smart Recommendations** - Optimal scanner deployment locations
- **Multiple Output Formats** - JSON, CSV, HTML with D3.js visualization
- **Caching & Resume** - Cache results and resume interrupted scans
- **Progress Tracking** - Real-time progress with ETA estimates

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer.git
cd multi-cloud-network-analyzer
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"  # Install in editable mode with dev dependencies
pytest tests/ -v
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'aws_network_analyzer'` | Run `pip install .` from the project root |
| AWS throttling errors | Reduce `--parallel` value (default: 10) |
| Azure 429 errors | Analyzer has built-in retry; if persistent, reduce parallelism |
| GCP quota exceeded | Reduce `--parallel` or request quota increase |
| Timeout errors | Increase `--timeout` (default: 600 seconds) |
| No instances found | Check that VMs are in "running" state |

### Debug Mode

```bash
# Enable verbose logging
aws-network-analyzer --cloud aws --mode account --verbose

# Write logs to file
aws-network-analyzer --cloud aws --mode account --verbose --log-file debug.log
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Yash Jhunjhunwala** - [GitHub](https://github.com/yash-jhunjhunwala)

---

## Support

- **Issues**: [GitHub Issues](https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yash-jhunjhunwala/multi-cloud-network-analyzer/discussions)
