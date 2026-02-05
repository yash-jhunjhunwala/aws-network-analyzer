#!/usr/bin/env python3
"""
Exporters Module for Multi-Cloud Network Analyzer

Provides export functionality for different output formats:
- JSON export
- CSV export  
- HTML report generation

All exporters follow a common interface for consistency.
"""

import csv
import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import VERSION, CloudProvider


class BaseExporter(ABC):
    """Abstract base class for all exporters."""
    
    @abstractmethod
    def export(self, data: Dict[str, Any], output_path: str) -> None:
        """Export data to the specified path."""
        pass
    
    @abstractmethod
    def get_extension(self) -> str:
        """Get the file extension for this format."""
        pass


class JSONExporter(BaseExporter):
    """Export data to JSON format."""
    
    def __init__(self, indent: int = 2, sort_keys: bool = False):
        """
        Initialize JSON exporter.
        
        Args:
            indent: Indentation level for pretty-printing
            sort_keys: Whether to sort keys alphabetically
        """
        self.indent = indent
        self.sort_keys = sort_keys
    
    def export(self, data: Dict[str, Any], output_path: str) -> None:
        """Export data to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=self.indent, sort_keys=self.sort_keys, default=str)
    
    def get_extension(self) -> str:
        return ".json"
    
    def to_string(self, data: Dict[str, Any]) -> str:
        """Convert data to JSON string."""
        return json.dumps(data, indent=self.indent, sort_keys=self.sort_keys, default=str)


class CSVExporter(BaseExporter):
    """Export data to CSV format."""
    
    def export(self, data: Dict[str, Any], output_path: str) -> None:
        """
        Export data to CSV file.
        
        Extracts instance/VM data and writes to CSV with reachability info.
        """
        rows = self._extract_rows(data)
        
        if rows:
            fieldnames = self._get_fieldnames(data)
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        else:
            # Write summary if no instances
            self._write_summary_csv(data, output_path)
    
    def get_extension(self) -> str:
        return ".csv"
    
    def _get_fieldnames(self, data: Dict[str, Any]) -> List[str]:
        """Get fieldnames based on cloud provider."""
        cloud = data.get("cloud", "aws")
        
        base_fields = [
            "region",
            "instance_id",
            "instance_name",
            "private_ip",
            "public_ip",
            "state",
            "reachable"
        ]
        
        if cloud == "aws":
            return ["region", "vpc_id", "subnet_id", "instance_id", "instance_name",
                   "private_ip", "public_ip", "state", "reachable_from_primary", "connectivity_type"]
        elif cloud == "azure":
            return ["location", "vnet_id", "vnet_name", "subnet_id", "vm_id", "vm_name",
                   "private_ip", "public_ip", "resource_group", "state", "reachable_from_primary"]
        elif cloud == "gcp":
            return ["region", "zone", "vpc_name", "subnet_name", "instance_id", "instance_name",
                   "private_ip", "public_ip", "state", "reachable_from_primary"]
        
        return base_fields
    
    def _extract_rows(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract instance rows from report data."""
        rows = []
        cloud = data.get("cloud", "aws")
        
        # Try to get all_instances/all_vms list first (preferred)
        all_instances = data.get("all_instances", data.get("all_vms", []))
        
        if all_instances:
            for inst in all_instances:
                row = self._instance_to_row(inst, cloud)
                rows.append(row)
        else:
            # Fall back to extracting from discovery data
            rows = self._extract_from_discovery(data)
        
        # Sort by region, then network, then instance
        rows.sort(key=lambda x: (
            x.get("region", x.get("location", "")),
            x.get("vpc_id", x.get("vnet_id", x.get("vpc_name", ""))),
            x.get("instance_id", x.get("vm_id", ""))
        ))
        
        return rows
    
    def _instance_to_row(self, inst: Dict[str, Any], cloud: str) -> Dict[str, Any]:
        """Convert instance dict to CSV row."""
        if cloud == "aws":
            return {
                "region": inst.get("region", ""),
                "vpc_id": inst.get("vpc_id", inst.get("network_id", "")),
                "subnet_id": inst.get("subnet_id", ""),
                "instance_id": inst.get("instance_id", ""),
                "instance_name": inst.get("name", ""),
                "private_ip": inst.get("private_ip", inst.get("primary_private_ip", "")),
                "public_ip": inst.get("public_ip", ""),
                "state": inst.get("state", ""),
                "reachable_from_primary": "Yes" if inst.get("reachable") else "No",
                "connectivity_type": inst.get("connectivity_type", "")
            }
        elif cloud == "azure":
            return {
                "location": inst.get("location", inst.get("region", "")),
                "vnet_id": inst.get("vnet_id", inst.get("network_id", "")),
                "vnet_name": inst.get("vnet_name", ""),
                "subnet_id": inst.get("subnet_id", ""),
                "vm_id": inst.get("vm_id", inst.get("instance_id", "")),
                "vm_name": inst.get("name", ""),
                "private_ip": inst.get("private_ip", ""),
                "public_ip": inst.get("public_ip", ""),
                "resource_group": inst.get("resource_group", ""),
                "state": inst.get("state", ""),
                "reachable_from_primary": "Yes" if inst.get("reachable") else "No"
            }
        elif cloud == "gcp":
            return {
                "region": inst.get("region", ""),
                "zone": inst.get("zone", ""),
                "vpc_name": inst.get("vpc_name", ""),
                "subnet_name": inst.get("subnet_name", ""),
                "instance_id": inst.get("instance_id", ""),
                "instance_name": inst.get("name", ""),
                "private_ip": inst.get("private_ip", inst.get("internal_ip", "")),
                "public_ip": inst.get("public_ip", inst.get("external_ip", "")),
                "state": inst.get("state", ""),
                "reachable_from_primary": "Yes" if inst.get("reachable") else "No"
            }
        
        return inst
    
    def _extract_from_discovery(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract rows from discovery data (fallback method)."""
        rows = []
        discovery = data.get("discovery", {})
        recommendation = data.get("recommendation", {})
        
        unreachable_ids = set()
        for inst in recommendation.get("unreachable_instances", recommendation.get("unreachable_vms", [])):
            unreachable_ids.add(inst.get("instance_id", inst.get("vm_id", "")))
        
        for region, region_data in discovery.items():
            if "error" in region_data or not isinstance(region_data, dict):
                continue
            
            for vpc_id, vpc_data in region_data.get("vpcs", region_data.get("vnets", {})).items():
                for instance_id, inst_data in vpc_data.get("instances", vpc_data.get("vms", {})).items():
                    is_reachable = instance_id not in unreachable_ids
                    
                    rows.append({
                        "region": region,
                        "vpc_id": vpc_id,
                        "subnet_id": inst_data.get("subnet_id", ""),
                        "instance_id": instance_id,
                        "instance_name": inst_data.get("name", ""),
                        "private_ip": (inst_data.get("private_ips", [""])[0] 
                                      if inst_data.get("private_ips") else 
                                      inst_data.get("private_ip", "")),
                        "public_ip": inst_data.get("public_ip", ""),
                        "state": inst_data.get("state", "running"),
                        "reachable_from_primary": "Yes" if is_reachable else "No",
                        "connectivity_type": ""
                    })
        
        return rows
    
    def _write_summary_csv(self, data: Dict[str, Any], output_path: str) -> None:
        """Write summary CSV when no instances found."""
        summary = data.get("summary", {})
        recommendation = data.get("recommendation", {})
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])
            writer.writerow(["cloud", data.get("cloud", "")])
            writer.writerow(["total_regions", summary.get("total_regions_scanned", 0)])
            writer.writerow(["total_vpcs", summary.get("total_vpcs", summary.get("total_vnets", 0))])
            writer.writerow(["total_instances", summary.get("total_instances", summary.get("total_vms", 0))])
            writer.writerow(["recommendation_status", recommendation.get("status", "")])
            
            deploy_loc = recommendation.get("deployment_location")
            if deploy_loc:
                writer.writerow(["recommended_region", deploy_loc.get("region", "")])
                writer.writerow(["recommended_vpc", deploy_loc.get("vpc_id", deploy_loc.get("vnet_id", ""))])
                writer.writerow(["recommended_subnet", deploy_loc.get("subnet_id", "")])


class SummaryExporter:
    """Export formatted text summary."""
    
    def __init__(self, cloud: str = "aws"):
        self.cloud = cloud
    
    def format_summary(self, data: Dict[str, Any]) -> str:
        """Format data as readable text summary."""
        lines = []
        
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"{self.cloud.upper()} NETWORK REACHABILITY ANALYSIS")
        lines.append("=" * 70)
        
        summary = data.get("summary", {})
        total_instances = summary.get('total_instances', summary.get('total_vms', 0))
        total_networks = summary.get('total_vpcs', summary.get('total_vnets', 0))
        total_regions = summary.get('total_regions_scanned', 0)
        
        lines.append(f"\nScanned: {total_regions} regions, "
                    f"{total_networks} {'VPCs' if self.cloud == 'aws' else 'VNets' if self.cloud == 'azure' else 'VPCs'}, "
                    f"{total_instances} {'EC2 instances' if self.cloud == 'aws' else 'VMs' if self.cloud == 'azure' else 'instances'}")
        
        # Full coverage plan
        full_cov_plan = data.get("full_coverage_plan", {})
        full_cov_deployments = full_cov_plan.get("deployments", [])
        
        if full_cov_deployments and total_instances > 0:
            total_deploy = full_cov_plan.get("total_deployments_needed", 0)
            total_covered = full_cov_plan.get("total_instances_covered", full_cov_plan.get("total_vms_covered", 0))
            cov_pct = full_cov_plan.get("coverage_percentage", 0)
            unreachable = full_cov_plan.get("unreachable_count", 0)
            
            lines.append(f"\n{'=' * 70}")
            lines.append(f"📋 FULL COVERAGE PLAN: {total_deploy} DEPLOYMENT{'S' if total_deploy != 1 else ''} NEEDED")
            lines.append(f"{'=' * 70}")
            
            if cov_pct == 100:
                lines.append(f"✅ Deploy in these {total_deploy} locations to reach ALL {total_covered} instances:")
            else:
                lines.append(f"⚠️  Deploy in these {total_deploy} locations to reach {total_covered}/{total_instances} instances ({cov_pct:.1f}%):")
                lines.append(f"   ({unreachable} instances in isolated networks cannot be reached)")
            
            for deploy in full_cov_deployments:
                order = deploy.get("deployment_order", 0)
                covers = deploy.get("covers_instances", deploy.get("covers_vms", 0))
                cumulative = deploy.get("cumulative_covered", 0)
                cum_pct = deploy.get("cumulative_percentage", 0)
                
                lines.append(f"\n   #{order}. {deploy.get('region', deploy.get('location', 'N/A'))}")
                lines.append(f"       VPC:    {deploy.get('vpc_id', deploy.get('vnet_id', 'N/A'))} ({deploy.get('vpc_cidr', deploy.get('vnet_cidr', 'N/A'))})")
                lines.append(f"       Subnet: {deploy.get('subnet_id', 'N/A')}")
                lines.append(f"       Type:   {'Public' if deploy.get('is_public') else 'Private'} | "
                            f"Internet: {'Yes' if deploy.get('has_internet') else 'No'}")
                lines.append(f"       ➜ Covers: +{covers} instances (cumulative: {cumulative}/{total_instances} = {cum_pct:.0f}%)")
            
            lines.append("")
        
        # Best single location recommendation
        rec = data.get("recommendation", {})
        if rec:
            lines.append(f"{'=' * 70}")
            lines.append(f"🎯 BEST SINGLE LOCATION: {rec.get('status', 'UNKNOWN')}")
            lines.append(f"{'=' * 70}")
            lines.append(f"{rec.get('message', 'No recommendation available')}")
            
            loc = rec.get("deployment_location")
            if loc:
                lines.append(f"\n>> BEST SINGLE DEPLOYMENT LOCATION:")
                lines.append(f"   Region:  {loc.get('region', loc.get('location', 'N/A'))}")
                lines.append(f"   VPC:     {loc.get('vpc_id', loc.get('vnet_id', 'N/A'))} ({loc.get('vpc_cidr', loc.get('vnet_cidr', 'N/A'))})")
                lines.append(f"   Subnet:  {loc.get('subnet_id', 'N/A')} ({loc.get('subnet_cidr', 'N/A')})")
                lines.append(f"   Type:    {'Public (has IGW)' if loc.get('is_public_subnet', loc.get('is_public')) else 'Private'}")
                lines.append(f"   Internet: {'Yes' if loc.get('has_internet_access', loc.get('has_internet')) else 'No'}")
            
            cov = rec.get("coverage")
            if cov:
                lines.append(f"\n>> COVERAGE FROM THIS LOCATION:")
                total = cov.get('total_instances', cov.get('total_vms', 0))
                reachable = cov.get('reachable_instances', cov.get('reachable_vms', 0))
                pct = cov.get('percentage', 0)
                lines.append(f"   Reachable: {reachable}/{total} ({pct:.1f}%)")
        
        # Connectivity summary
        conn = data.get("connectivity_summary", {})
        if conn:
            lines.append(f"\n>> CONNECTIVITY:")
            lines.append(f"   TGW-connected VPCs: {conn.get('tgw_connected_vpcs', conn.get('transit_gateway_networks', 0))}")
            lines.append(f"   Peered VPCs: {conn.get('peered_vpcs', conn.get('peered_networks', 0))}")
            lines.append(f"   Isolated VPCs: {conn.get('isolated_vpcs', conn.get('isolated_networks', 0))}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def print_summary(self, data: Dict[str, Any]) -> None:
        """Print formatted summary to stdout."""
        print(self.format_summary(data))


def get_exporter(format: str) -> BaseExporter:
    """
    Factory function to get the appropriate exporter.
    
    Args:
        format: Output format ('json', 'csv', 'html')
    
    Returns:
        Exporter instance
    """
    exporters = {
        'json': JSONExporter,
        'csv': CSVExporter,
    }
    
    if format not in exporters:
        raise ValueError(f"Unsupported format: {format}. Supported: {list(exporters.keys())}")
    
    return exporters[format]()


def export_report(
    data: Dict[str, Any],
    output_path: str,
    format: Optional[str] = None,
    cloud: Optional[str] = None
) -> None:
    """
    Export report data to file.
    
    Args:
        data: Report data dictionary
        output_path: Output file path
        format: Output format (auto-detected from extension if not provided)
        cloud: Cloud provider for format-specific handling
    """
    if format is None:
        # Auto-detect from extension
        ext = Path(output_path).suffix.lower()
        format_map = {'.json': 'json', '.csv': 'csv', '.html': 'html'}
        format = format_map.get(ext, 'json')
    
    exporter = get_exporter(format)
    exporter.export(data, output_path)
