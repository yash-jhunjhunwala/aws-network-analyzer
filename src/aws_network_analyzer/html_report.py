#!/usr/bin/env python3
"""Unified HTML report generator (golden layout) for all clouds/modes."""

from datetime import datetime
from typing import Any, Dict, List

from aws_network_analyzer.base import VERSION


def _normalize_report_data(result: Dict[str, Any] | None, cloud: str) -> Dict[str, Any]:
    normalized = result.copy() if isinstance(result, dict) else {}
    normalized.setdefault("cloud", cloud)
    normalized.setdefault("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    normalized.setdefault("version", VERSION)
    return normalized


def _get_labels(cloud: str) -> Dict[str, str]:
    if cloud == "azure":
        return {
            "entity": "Subscription",
            "entity_plural": "Subscriptions",
            "network": "VNet",
            "networks": "VNets",
            "instances": "VMs",
        }
    if cloud == "gcp":
        return {
            "entity": "Project",
            "entity_plural": "Projects",
            "network": "VPC",
            "networks": "VPCs",
            "instances": "Instances",
        }
    return {
        "entity": "Account",
        "entity_plural": "Accounts",
        "network": "VPC",
        "networks": "VPCs",
        "instances": "Instances",
    }


def _get_full_coverage_plan_css() -> str:
    return """
        /* Full Coverage Plan Styles */
        .full-coverage-plan {
            background: white;
            border-left: 4px solid #f59e0b;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 25px;
            margin-bottom: 20px;
        }
        .full-coverage-plan h2 {
            margin-bottom: 15px;
            font-size: 20px;
            color: #1e3a5f;
        }
        .deployments-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 15px;
        }
        .deployment-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 18px;
        }
        .deployment-header {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 10px;
        }
        .deployment-order {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            color: white;
            font-weight: 700;
            width: 26px;
            height: 26px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .deployment-region { font-weight: 600; color: #1e3a5f; flex: 1; }
        .deployment-covers {
            background: #d1fae5;
            color: #059669;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .deployment-row { display: flex; justify-content: space-between; font-size: 12px; padding: 3px 0; }
        .deployment-label { color: #6b7280; }
        .deployment-value { color: #374151; font-family: monospace; max-width: 230px; overflow: hidden; text-overflow: ellipsis; font-size: 11px; }
        .deployment-progress { margin-top: 10px; }
        .progress-bar { width: 100%; height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 4px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); }
        .progress-text { font-size: 12px; color: #6b7280; }
    """


def _generate_full_coverage_plan_html(plan: Dict[str, Any], labels: Dict[str, str], cloud: str = "aws") -> str:
    deployments: List[Dict[str, Any]] = plan.get("deployments", []) or []
    total_instances = plan.get("total_instances", plan.get("total_instances_covered", 0))
    total_deployments = plan.get("total_deployments_needed", len(deployments)) or (1 if total_instances else 0)

    if not deployments:
        msg = "No " + labels["instances"].lower() + " found." if total_instances == 0 else "Please rerun the analyzer."
        return f'''
        <div class="card warning">
            <h2>⚠️ Multi-{labels['network']} Deployment Required</h2>
            <p style="margin-bottom: 15px;">No deployment plan generated. {msg}</p>
        </div>
        '''

    cards = []
    for dep in deployments:
        order = dep.get("deployment_order", len(cards) + 1)
        covers = dep.get("covers_instances", dep.get("covers_vms", 0))
        cum_pct = dep.get("cumulative_percentage", 0)
        region = dep.get("region", dep.get("location", "N/A"))
        entity_id = dep.get("account_id", dep.get("subscription_id", dep.get("project_id", "N/A")))
        entity_name = dep.get("account_name", dep.get("subscription_name", dep.get("project_name", "")))
        net_id = dep.get("vpc_id", dep.get("vnet_id", "N/A")) or "N/A"
        net_cidr = dep.get("vpc_cidr", dep.get("vnet_cidr", "")) or ""
        subnet_id = dep.get("subnet_id", "") or "N/A"
        subnet_cidr = dep.get("subnet_cidr", "") or "N/A"
        is_public = dep.get("is_public", False)
        has_internet = dep.get("has_internet", dep.get("has_nat_gateway", False))
        covered_detail = dep.get("covered_instances_detail", dep.get("covered_vms_detail", []))
        
        # Cloud-specific connectivity info
        if cloud == "aws":
            connectivity_html = f'''<div><strong>Type:</strong> {"🌐 Public" if is_public else "🔒 Private"}</div>
                <div><strong>Internet Access:</strong> {"✓ Yes" if has_internet else "✗ No"}</div>'''
        elif cloud == "azure":
            has_nat = dep.get("has_nat_gateway", False)
            connectivity_html = f'''<div><strong>NAT Gateway:</strong> {"✓ Yes" if has_nat else "✗ No"}</div>
                <div><strong>Internet Access:</strong> {"✓ Via NAT" if has_nat else "⚠️ Needs NAT/Public IP"}</div>'''
        else:  # GCP
            has_pga = dep.get("private_ip_google_access", False)
            connectivity_html = f'''<div><strong>Private Google Access:</strong> {"✓ Yes" if has_pga else "✗ No"}</div>
                <div><strong>Internet Access:</strong> {"✓ Via Cloud NAT" if has_internet else "⚠️ Needs Cloud NAT"}</div>'''
        
        # Build instance rows for details
        dep_instance_rows = ""
        for inst in covered_detail:
            inst_id = inst.get("instance_id", inst.get("vm_id", ""))
            inst_name = inst.get("name", "")
            private_ip = inst.get("private_ip", inst.get("internal_ip", ""))
            inst_region = inst.get("region", inst.get("location", inst.get("zone", "")))
            inst_id_display = inst_id[:40] + "..." if len(inst_id) > 40 else inst_id
            dep_instance_rows += f'''
                <tr>
                    <td><code>{inst_id_display}</code></td>
                    <td>{inst_name or "<em>No name</em>"}</td>
                    <td><code>{private_ip}</code></td>
                    <td>{inst_region}</td>
                </tr>
            '''
        
        inst_label = labels["instances"]
        inst_lower = labels["instances"].lower()
        title = f"{entity_name or entity_id} - {region}"
        
        details_html = ""
        if covered_detail:
            details_html = f'''<details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: 600; color: #2563eb;">View {len(covered_detail)} {inst_label}(s) Covered</summary>
                <table style="margin-top: 10px; width: 100%;">
                    <thead>
                        <tr>
                            <th>{inst_label} ID</th>
                            <th>Name</th>
                            <th>Private IP</th>
                            <th>Region</th>
                        </tr>
                    </thead>
                    <tbody>
                        {dep_instance_rows if dep_instance_rows else f'<tr><td colspan="4">No {inst_lower}</td></tr>'}
                    </tbody>
                </table>
            </details>'''
        
        cards.append(f'''
        <div class="deployment-card" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
            <h3 style="color: #1e3a5f; margin-bottom: 15px;">🎯 Deployment #{order}: {title}</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 15px;">
                <div><strong>{labels['entity']}:</strong> <code>{entity_id}</code></div>
                <div><strong>Region:</strong> {region}</div>
                <div><strong>{labels['network']}:</strong> <code>{net_id}</code></div>
                <div><strong>{labels['network']} CIDR:</strong> {net_cidr or "N/A"}</div>
                <div><strong>Subnet:</strong> <code>{subnet_id}</code></div>
                <div><strong>Subnet CIDR:</strong> {subnet_cidr}</div>
                {connectivity_html}
                <div><strong>{inst_label} Covered:</strong> +{covers} ({cum_pct:.0f}% cumulative)</div>
            </div>
            {details_html}
        </div>
        ''')

    ent_lower = labels["entity"].lower()
    net_lower = labels["network"].lower()
    inst_lower = labels["instances"].lower()
    loc_s = "s" if total_deployments != 1 else ""
    return f'''
    <div class="card warning full-coverage-plan">
        <h2>⚠️ Multi-{labels['network']} Deployment Required</h2>
        <p style="margin-bottom: 15px;">{labels['instances']} are distributed across {labels['networks'].lower()} with limited cross-{net_lower} connectivity.</p>
        <p style="margin-bottom: 20px;">To reach all <strong>{total_instances}</strong> {inst_lower}, deploy scanners in <strong>{total_deployments}</strong> location{loc_s}:</p>
        {''.join(cards)}
    </div>
    '''


def _generate_unified_html(result: Dict[str, Any], cloud: str) -> str:
    normalized = _normalize_report_data(result, cloud)
    labels = _get_labels(cloud)

    summary = result.get("summary", {})
    connectivity = result.get("connectivity", result.get("connectivity_summary", {}))
    recommendation = result.get("recommendation", result.get("report", {}).get("recommendation", {}))
    coverage = recommendation.get("coverage", {})
    coverage_pct = coverage.get("percentage", 0.0)
    fcp_html = _generate_full_coverage_plan_html(result.get("full_coverage_plan", {}), labels, cloud)

    # Get instances from multiple possible keys: all_instances, instances, or vms
    instances: List[Dict[str, Any]] = result.get("all_instances", result.get("instances", result.get("vms", []))) or []

    instance_rows = []
    for inst in instances[:200]:
        reachable = inst.get("reachable", False)
        reachable_icon = "✅" if reachable else "❌"
        row_class = "reachable" if reachable else "unreachable"
        name = inst.get("name", "N/A")
        priv_ips = inst.get("private_ips", [])
        priv_ip = inst.get("private_ip", priv_ips[0] if priv_ips else "-")
        pub_ip = inst.get("public_ip", inst.get("external_ip", "")) or "-"
        region = inst.get("region", inst.get("location", "N/A"))
        instance_rows.append(f'''
        <tr class="{row_class}">
            <td>{name}</td>
            <td class="mono">{priv_ip}</td>
            <td class="mono">{pub_ip}</td>
            <td>{region}</td>
            <td>{reachable_icon}</td>
        </tr>
        ''')

    if len(instances) > 200:
        remaining = len(instances) - 200
        inst_lower = labels["instances"].lower()
        instance_rows.append(f'<tr><td colspan="5" style="text-align:center;color:#64748b;">... and {remaining} more {inst_lower}</td></tr>')

    # Coverage color
    if coverage_pct == 100:
        cov_color = "#10b981"
    elif coverage_pct > 0:
        cov_color = "#f59e0b"
    else:
        cov_color = "#ef4444"

    # Isolated color
    iso_count = connectivity.get("isolated_networks", 0)
    iso_color = "#ef4444" if iso_count > 0 else "#10b981"

    total_accounts = summary.get("total_accounts", 1)
    successful = summary.get("successful_accounts", 1)
    failed = summary.get("failed_accounts", 0)
    total_nets = summary.get("total_networks", 0)
    total_inst = summary.get("total_instances", summary.get("total_vms", 0))
    tgw_conn = connectivity.get("tgw_connected_vpcs", connectivity.get("tgw_connected_networks", 0))
    peered = connectivity.get("peered_networks", 0)
    peering_total = connectivity.get("total_peering_connections", 0)

    inst_table_body = "".join(instance_rows) if instance_rows else '<tr><td colspan="5" style="color:#6b7280;text-align:center;">No instances found</td></tr>'

    fcp_css = _get_full_coverage_plan_css()

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cloud.upper()} Network Reachability Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #1f2937; line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 1500px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #7c3aed 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header-meta {{ opacity: 0.9; font-size: 14px; }}
        .header-badge {{ background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 12px; margin-left: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #1e3a5f; }}
        .stat-label {{ color: #6b7280; font-size: 13px; margin-top: 5px; }}
        .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .card.warning {{ border-left: 4px solid #f59e0b; }}
        .card h2 {{ margin-bottom: 15px; color: #1e3a5f; font-size: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; color: #374151; font-size: 13px; }}
        tr:hover {{ background: #f9fafb; }}
        .mono {{ font-family: monospace; font-size: 13px; }}
        .reachable {{ }}
        .unreachable {{ opacity: 0.6; }}
        .conn-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .conn-item {{ background: #f8fafc; padding: 15px; border-radius: 8px; text-align: center; }}
        .conn-value {{ font-size: 28px; font-weight: bold; color: #1e3a5f; display: block; }}
        .conn-label {{ font-size: 12px; color: #6b7280; margin-top: 5px; display: block; }}
        .footer {{ text-align: center; color: #9ca3af; font-size: 12px; margin-top: 30px; padding: 20px; }}
        {fcp_css}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 {cloud.upper()} Network Reachability Report
                <span class="header-badge">Account Analysis</span>
            </h1>
            <div class="header-meta">
                Cloud: <strong>{cloud.upper()}</strong> |
                Generated: <strong>{normalized.get('generated_at')}</strong> |
                Version: <strong>{normalized.get('version')}</strong>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value">{total_accounts}</div><div class="stat-label">{labels['entity_plural']} Scanned</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#10b981">{successful}</div><div class="stat-label">Successful</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#ef4444">{failed}</div><div class="stat-label">Failed</div></div>
            <div class="stat-card"><div class="stat-value">{total_nets}</div><div class="stat-label">Total {labels['networks']}</div></div>
            <div class="stat-card"><div class="stat-value">{total_inst}</div><div class="stat-label">Total {labels['instances']}</div></div>
            <div class="stat-card"><div class="stat-value" style="color:{cov_color}">{coverage_pct:.0f}%</div><div class="stat-label">Coverage</div></div>
        </div>

        {fcp_html}

        <div class="card">
            <h2>🔗 Network Connectivity Summary</h2>
            <div class="conn-grid">
                <div class="conn-item"><span class="conn-value">{tgw_conn}</span><span class="conn-label">TGW-Connected {labels['networks']}</span></div>
                <div class="conn-item"><span class="conn-value">{peered}</span><span class="conn-label">Peered {labels['networks']}</span></div>
                <div class="conn-item"><span class="conn-value" style="color:{iso_color}">{iso_count}</span><span class="conn-label">Isolated {labels['networks']}</span></div>
                <div class="conn-item"><span class="conn-value">{peering_total}</span><span class="conn-label">Total Peering Connections</span></div>
            </div>
        </div>

        <div class="card">
            <h2>📋 {labels['instances']} ({len(instances)})</h2>
            <table>
                <thead>
                    <tr><th>Name</th><th>Private IP</th><th>Public IP</th><th>Region</th><th>Reachable</th></tr>
                </thead>
                <tbody>
                    {inst_table_body}
                </tbody>
            </table>
        </div>

        <div class="footer">Generated by Multi-Cloud Network Reachability Analyzer v{VERSION}</div>
    </div>
</body>
</html>
'''
    return html


def generate_html_report(result: Dict[str, Any], output_file: str, cloud: str = "aws"):
    """Generate unified HTML report for any cloud provider."""
    html = _generate_unified_html(result, cloud)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


# Alias for backward compatibility
generate_interactive_html = generate_html_report
