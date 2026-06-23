"""
report.py
Generates a markdown gap report from baseline check results.
"""

from datetime import datetime, timezone


def generate_report(results, policy_count, location_count):
    """Generate a markdown report from baseline check results."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    passed = [r for r in results if r["status"] == "PASS"]
    failed = [r for r in results if r["status"] == "FAIL"]
    warnings = [r for r in results if r["status"] == "WARNING"]

    lines = []
    lines.append("# Entra ID Zero Trust Policy Audit Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Policies evaluated:** {policy_count}")
    lines.append(f"**Named locations:** {location_count}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Result | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| PASS | {len(passed)} |")
    lines.append(f"| FAIL | {len(failed)} |")
    lines.append(f"| WARNING | {len(warnings)} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    if failed:
        lines.append("## Failures")
        lines.append("")
        for r in failed:
            lines.append(f"### {r['id']}: {r['name']}")
            lines.append("")
            lines.append(f"**Status:** FAIL")
            lines.append("")
            lines.append(r["detail"])
            lines.append("")
            lines.append(f"**Reference:** {r['reference']}")
            lines.append("")
        lines.append("---")
        lines.append("")

    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for r in warnings:
            lines.append(f"### {r['id']}: {r['name']}")
            lines.append("")
            lines.append(f"**Status:** WARNING")
            lines.append("")
            lines.append(r["detail"])
            lines.append("")
            lines.append(f"**Reference:** {r['reference']}")
            lines.append("")
        lines.append("---")
        lines.append("")

    if passed:
        lines.append("## Passed")
        lines.append("")
        for r in passed:
            lines.append(f"### {r['id']}: {r['name']}")
            lines.append("")
            lines.append(f"**Status:** PASS")
            lines.append("")
            lines.append(r["detail"])
            lines.append("")
            lines.append(f"**Reference:** {r['reference']}")
            lines.append("")

    return "\n".join(lines)
