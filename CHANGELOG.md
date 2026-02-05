# Changelog

All notable changes to Multi-Cloud Network Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-02-03

### 🎉 First Stable Release

This marks the first production-ready release of the Multi-Cloud Network Analyzer.

### Features
- **Multi-Cloud Support** - Analyze AWS, Azure, and GCP networks
- **Organization-Wide Scanning** - Scan entire AWS Organizations, Azure Tenants, and GCP Organizations
- **VPC/VNet Peering Detection** - Automatically detect peered networks to recommend consolidated deployments
- **Transit Gateway Support** - Detect AWS Transit Gateway attachments for network connectivity
- **Internet Access Detection**
  - AWS: Internet Gateways, NAT Gateways
  - Azure: Public IPs on VMs, NAT Gateways
  - GCP: External IPs on instances, Cloud NAT
- **Smart Recommendations** - Suggests optimal scanner deployment locations based on network topology
- **Multiple Output Formats** - JSON, CSV, HTML, and summary text reports
- **HTML Visualization** - Rich D3.js network topology visualization
- **Parallel Discovery** - Multi-threaded scanning for fast analysis
- **Progress Tracking** - Real-time progress with ETA estimates
- **Caching System** - Resume interrupted scans with cached data
- **Cloud-Specific Modes**
  - AWS: `account` (single) or `org` (organization-wide)
  - Azure: `subscription` (single) or `tenant` (all subscriptions)
  - GCP: `project` (single) or `org` (organization-wide)

### Cloud Provider Requirements
- **AWS**: `sts:AssumeRole`, `ec2:Describe*`, `organizations:List*`
- **Azure**: Reader role on subscriptions
- **GCP**: Compute Viewer, Folder Viewer roles

---

## [4.2.0] - 2025-02-03 (Pre-release)

### Added
- **New Modular Architecture** - Major code refactoring for better maintainability
  - `base.py` - Shared base classes, constants, enums, and data models
    - `CloudProvider` enum for identifying cloud providers
    - `ExitCode` enum for standardized exit codes
    - `RecommendationStatus` enum for status handling
    - Data classes: `SubnetInfo`, `InstanceInfo`, `NetworkInfo`, `PeeringInfo`, `DeploymentLocation`, etc.
    - Single source of truth for VERSION constant
  - `utils.py` - Shared utility functions
    - `retry_with_backoff()` decorator for API retry logic
    - `ProgressIndicator` class for progress tracking
    - `ETAProgressTracker` for ETA calculations
    - CIDR utilities: `check_cidr_overlap()`, `cidr_contains_ip()`, `get_usable_host_count()`
    - `parallel_execute()` for ThreadPoolExecutor orchestration
    - Centralized logging with `setup_logging()` and `logger`
  - `exporters.py` - Export functionality for different formats
    - `JSONExporter` for JSON output
    - `CSVExporter` for CSV output with cloud-specific fieldnames
    - `SummaryExporter` for formatted text summaries
    - Factory function `get_exporter()` for format selection

### Changed
- All analyzers now use shared base classes and utilities
- Removed duplicate `ProgressIndicator` implementations from Azure and GCP analyzers
- Version is now managed in single location (`base.py`)
- Unified retry logic across all cloud providers
- Improved code organization following Python best practices

### Fixed
- Code duplication across cloud analyzer modules
- Inconsistent retry behavior between cloud providers
- Version number inconsistencies between modules

## [4.1.0] - 2026-02-03

### Added
- **HTML Reports** - Rich D3.js visualization for stakeholders
  - `--format html` generates HTML with network topology visualization
  - Summary cards, deployment recommendations, instance details
  - Modern responsive design with consistent styling across clouds
- **Caching System** - Speed up re-runs with cached discovery data
  - `--cache` flag enables caching of discovery results
  - `--cache-ttl` to set cache TTL in hours (default: 24)
  - `--no-cache` to force fresh discovery ignoring cache
  - Disk-based cache in `~/.aws-network-analyzer/cache`
  - Per-account, per-region cache keys
- **Resumable Scans** - Resume interrupted organization scans
  - `--resume SCAN_ID` to resume an interrupted scan
  - `--list-resumable` to list scans that can be resumed
  - State saved in `~/.aws-network-analyzer/state`
  - Partial results preserved for completed accounts
- **Enhanced Progress Tracking** - Better visibility for large organization scans
  - Progress bar with percentage and visual indicator
  - ETA calculation based on rolling average
  - Throughput display (items/second or items/minute)
  - Success/failure count during scan
  - Current item being processed
- **Expanded Test Suite** - Unit tests for Azure and GCP analyzers
  - Tests for cache module (ScanCache, ScanStateManager, ProgressTracker)
  - Tests for HTML report generation
  - Mock-based tests for Azure analyzer
  - Mock-based tests for GCP analyzer

### Changed
- Improved `__init__.py` exports including new modules
- Better lazy loading of optional modules for faster startup

## [4.0.0] - 2026-02-03

### Added
- **Multi-Cloud Support** - Now supports AWS, Azure, and GCP with unified CLI
  - `--cloud aws|azure|gcp` flag to select cloud provider
  - Consistent behavior and output format across all clouds
  - All cloud SDKs included by default (no optional extras needed)
- **Azure Analyzer** - Full Azure network analysis
  - Subscription and organization (all subscriptions) modes
  - VNet, subnet, VM discovery across all regions
  - VNet peering detection
  - Service principal and Azure CLI authentication
  - Optimized single-fetch architecture to avoid API throttling
- **GCP Analyzer** - Full GCP network analysis  
  - Project and organization (all projects) modes
  - VPC, subnet, VM discovery across all zones
  - VPC peering detection
  - Service account and Application Default Credentials support
- **New Authentication Options**
  - Azure: `--tenant-id`, `--client-id`, `--client-secret`, `--subscription-id`
  - GCP: `--project`, `--key-file`

### Changed
- Package renamed conceptually to "Multi-Cloud Network Analyzer" (CLI remains `aws-network-analyzer`)
- All regions scanned by default across all clouds (consistent behavior)
- Removed `--all-regions` flag (now the default)
- SDKs for Azure and GCP are now required dependencies, not optional

### Fixed
- Azure API throttling (429 errors) with efficient single-fetch architecture
- Azure now scans all 60+ regions without hanging

## [3.2.0] - 2026-02-03

### Added
- **Full CLI Feature Parity** - `aws-network-analyzer` command now has ALL features
  - `--mode account|org` for single account or organization-wide analysis
  - `--format json|csv|html` for multiple output formats
  - `--assume-role` for cross-account role assumption in org mode
  - `--parallel-accounts` for concurrent account scanning
  - `--max-accounts` to limit accounts in org mode
  - `--timeout` for global timeout control
  - `--dry-run` to preview scan scope
  - `--log-file` for file logging
- Packaged CLI now wraps the full main module for complete functionality

### Changed
- CLI entry point now imports from `main.py` instead of simplified implementation
- Package now includes `network_reachability.py` for enhanced analyzers

## [3.1.0] - 2026-02-03

### Added
- **Flexible Authentication Options** - Multiple ways to provide AWS credentials
  - `--access-key` and `--secret-key` for explicit IAM credentials
  - `--session-token` for temporary credentials (STS, SSO, assumed roles)
  - `--region` to set default region for API calls
  - Clear authentication priority: explicit creds > profile > env vars > IAM role > default chain
- **CLI Entry Point Fix** - `aws-network-analyzer` command now works properly when installed via pip
- **Improved Error Messages** - Better credential validation with actionable error messages

### Changed
- Refactored session creation into dedicated `create_session()` function
- Updated help text with comprehensive authentication examples
- CLI module is now self-contained and doesn't depend on external scripts

### Fixed
- Fixed pip installation issue where CLI command showed "aws_network_analyzer.py not found"
- Removed circular import in package `__init__.py`

## [3.0.0] - 2026-02-03

### Added
- **Full Coverage Plan** - Both account and org modes now provide multiple deployment recommendations
  - Uses greedy set cover algorithm to find minimum deployments for 100% coverage
  - Shows cumulative coverage as each deployment is added
  - Console and HTML output include visual deployment plan
  - JSON report includes `full_coverage_plan` array with all deployment details
- **Enhanced Connectivity Summary** - Clear visibility into network topology
  - TGW-connected VPCs count
  - Peered VPCs count
  - Isolated VPCs count (highlighted when > 0)
  - Cross-account connectivity metrics for org mode

### Changed
- **Reorganized Output** - Cleaner, more actionable recommendations
  - Full Coverage Plan shown first (multiple deployments for 100% reach)
  - Best Single Location shown second (maximum reach from one point)
  - Better visual hierarchy in console and HTML reports
- **Removed Qualys branding** - Project is now fully open source under personal authorship
- Version bump to 3.0.0 for breaking output format changes

### Fixed
- Connectivity summary correctly shows isolated VPCs when no TGW/peering exists
- HTML report handles edge cases with missing deployment data

## [2.2.1] - 2026-02-03

### Added
- **Full Coverage Plan for Account Mode** - Account mode now also provides multiple deployment recommendations
  - Uses same greedy set cover algorithm as org mode
  - Shows all locations needed to reach 100% of instances
  - Console output shows numbered deployment plan with cumulative coverage
  
### Changed
- **Improved Connectivity Summary** - Both account and org modes now show:
  - TGW-connected VPCs count
  - Peered VPCs count  
  - Isolated VPCs count (highlighted in red when > 0)
  - Cross-account TGW/peering connections (org mode)
  - Total TGW attachments and peering connections
- HTML reports now show all connectivity metrics with color coding
- Cleaner console output format for both modes

## [2.2.0] - 2026-02-03

### Added
- **Full Coverage Plan for Organization Mode** - Now provides multiple deployment recommendations to cover ALL instances
  - Greedy set cover algorithm finds the minimum number of deployments needed
  - Shows cumulative coverage as each deployment is added
  - Works identically to account mode - always provides complete coverage recommendations
  - Console output shows numbered deployment plan with coverage percentages
  - HTML report includes visual "Full Coverage Plan" section with progress bars
  - JSON report includes `full_coverage_plan` with all deployment details

### Changed
- Organization mode now shows both:
  1. **Full Coverage Plan** - Multiple deployments to reach 100% of instances
  2. **Best Single Location** - Maximum reach from a single deployment point
- Clearer console output with distinct sections for each recommendation type
- Summary now includes `deployments_for_full_coverage` count

## [2.1.1] - 2026-02-03

### Changed
- **10x Faster Organization Scanning** - Parallel account scanning for org mode
  - Accounts are now scanned in parallel (default: 20 concurrent accounts)
  - Reduced scan time from ~47 minutes to ~5 minutes for 985 accounts
  - Progress counter shows real-time completion status
- New CLI options for org mode:
  - `--parallel-accounts N` - Set number of concurrent account scans (default: 20)
  - `--max-accounts N` - Limit accounts to scan (useful for testing)

### Fixed
- HTML export handles missing deployment data gracefully

## [2.1.0] - 2026-02-03

### Added
- **Cross-Account Organization Analysis** - Organization mode now aggregates data across ALL accounts
  - Unified network topology view across the entire organization
  - Cross-account TGW connectivity detection
  - Cross-account VPC peering detection
  - Single organization-wide deployment recommendation
  - Find the best location to deploy that can reach instances across multiple accounts
- **OrgNetworkAnalyzer Class** - New analyzer for cross-account reachability
  - Builds unified connectivity graph across accounts
  - Calculates organization-wide coverage from any deployment location
  - Tracks cross-account vs same-account reachability
- **Enhanced Org HTML Report** - New cross-account analysis visualizations
  - Organization-wide deployment recommendation card
  - Cross-account connectivity summary
  - Per-account breakdown with org-reachable count
  - Shows how many instances in each account are reachable from the org deployment

### Changed
- `--mode org` now performs cross-account analysis instead of per-account only
- Organization recommendation now considers TGW and peering across account boundaries
- CSV export for org mode includes cross-account reachability data

## [2.0.0] - 2026-02-03

### Added
- **HTML Report Export** - Beautiful, shareable HTML reports with visual styling
  - Professional layout with CSS styling
  - Stats cards showing key metrics
  - Interactive regional breakdown table
  - Instance details with reachability status
  - Multi-region deployment recommendations
- **Package Structure** - Now installable via pip
  - `pip install .` from source
  - Entry point: `aws-network-analyzer` CLI command
  - Proper module structure with `__init__.py`
- **CSV Export** - Export results to CSV format
  - Instance-level details with reachability
  - Connectivity type classification
- **Dry Run Mode** - Preview scan scope without executing (`--dry-run`)
- **Global Timeout** - Set maximum scan duration (`--timeout`)
- **Graceful Shutdown** - Ctrl+C handling with partial results

### Changed
- Version bumped to 2.0.0

### Fixed
- CSV export now properly shows reachability status instead of "Unknown"
- File corruption during pyproject.toml creation resolved
- HTML export no longer overwritten by text summary

## [1.2.0] - 2024-02-02

### Added
- **Logging System** - Proper logging with `--verbose` and `--log-file` options
- **Credentials Validation** - Fail-fast validation before scan begins
- **Exit Codes** - Standardized exit codes for CI/CD integration
  - 0: Success (100% coverage)
  - 1: Partial (some instances unreachable)
  - 2: Error during execution
  - 3: Timeout exceeded
  - 130: Interrupted (Ctrl+C)
- **Input Validation** - Validate regions and profiles before scanning
- **Version Flag** - `--version` shows current version

## [1.1.0] - 2024-02-01

### Added
- **Parallel Scanning** - Multi-region scanning with ThreadPoolExecutor
  - Configurable parallelism via `--parallel` flag
  - Default: 10 concurrent region scans
- **Progress Indicator** - Visual progress bar during scanning
- **Retry Logic** - Exponential backoff for AWS API throttling
- **AWS Profile Support** - Use `--profile` to specify credentials
- **Instance Names** - Display Name tags for EC2 instances

### Changed
- Improved scan performance (3-5x faster with parallel scanning)

## [1.0.0] - 2024-01-31

### Added
- Initial release
- Single account analysis (`--mode account`)
- Organization-wide analysis (`--mode org`)
- Multi-region support
- VPC peering and Transit Gateway analysis
- Deployment location recommendations
- Multi-region deployment suggestions for isolated VPCs
- JSON output format
