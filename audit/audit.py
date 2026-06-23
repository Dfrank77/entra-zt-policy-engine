"""
audit.py
Main entry point for the Zero Trust Conditional Access audit.
Connects to the tenant, pulls policies, runs baseline checks,
and generates a gap report.
"""

import sys
import os
from graph_client import get_headers, list_conditional_access_policies, list_named_locations
from baseline import run_all_checks
from report import generate_report


def main():
    print("Authenticating to Microsoft Graph...")
    headers = get_headers()

    print("Retrieving Conditional Access policies...")
    policies = list_conditional_access_policies(headers)
    print(f"  Found {len(policies)} policies.")

    print("Retrieving named locations...")
    locations = list_named_locations(headers)
    print(f"  Found {len(locations)} named locations.")

    print("\nRunning Zero Trust baseline checks...\n")
    results = run_all_checks(policies, locations)

    for r in results:
        icon = {"PASS": "PASS", "FAIL": "FAIL", "WARNING": "WARN"}[r["status"]]
        print(f"  [{icon}] {r['id']}: {r['name']}")

    passed = len([r for r in results if r["status"] == "PASS"])
    failed = len([r for r in results if r["status"] == "FAIL"])
    warnings = len([r for r in results if r["status"] == "WARNING"])
    print(f"\n  Results: {passed} passed, {failed} failed, {warnings} warnings\n")

    report = generate_report(results, len(policies), len(locations))

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample-output")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "gap_report.md")

    with open(report_path, "w") as f:
        f.write(report)

    print(f"  Report saved to: {report_path}")


if __name__ == "__main__":
    main()
