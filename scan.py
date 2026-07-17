"""
scan.py

The front door of the tool. Run this file, and it does everything:
builds/connects to an AWS account, reads all role permissions, builds
a graph of who can reach admin (directly or through a chain), and
prints a clean report.

Usage:
    python3 scan.py
"""
from scanner.visualize import draw_graph
from moto import mock_aws
from tests.fake_aws import build_fake_account
import boto3
import sys
from scanner.collector import collect_all_roles
from scanner.graph import build_graph, find_all_paths_to_admin, ADMIN_NODE


def describe_path(path):
    """
    Turns a path like ['auditor-role', 'ci-deploy-role', 'ADMIN']
    into a readable arrow chain: 'auditor-role -> ci-deploy-role -> ADMIN'
    """
    return " -> ".join(path)

def _run_report(all_roles_data):
    graph = build_graph(all_roles_data)
    paths_to_admin = find_all_paths_to_admin(graph)

    for role_name, data in all_roles_data.items():
        print("-" * 60)
        if role_name in paths_to_admin:
            path = paths_to_admin[role_name]
            hops = len(path) - 1
            kind = "DIRECT" if hops == 1 else f"CHAINED ({hops} hops)"
            print(f"⚠️  {role_name}  —  escalation path found [{kind}]")
            print(f"    Permissions: {data['actions']}")
            print(f"    Path: {describe_path(path)}")
        else:
            print(f"✅  {role_name}  —  no escalation path found")
            print(f"    Permissions: {data['actions']}")

    print("-" * 60)
    vulnerable_count = len(paths_to_admin)
    total = len(all_roles_data)
    print(f"\nSCAN COMPLETE: {vulnerable_count} of {total} roles "
          f"have a path to admin (direct or chained).\n")

    draw_graph(graph, paths_to_admin)

def run_scan():
    print("=" * 60)
    print("NHI ESCALATION SCANNER")
    print("Scanning workload identities for hidden paths to admin...")
    print("=" * 60)

    use_real_aws = "--real" in sys.argv

    if use_real_aws:
        print("Mode: REAL AWS account\n")
        iam = boto3.client("iam")
        all_roles_data = collect_all_roles(iam)
        _run_report(all_roles_data)
    else:
        print("Mode: FAKE test environment\n")
        with mock_aws():
            iam = build_fake_account()
            all_roles_data = collect_all_roles(iam)
            _run_report(all_roles_data)


if __name__ == "__main__":
    run_scan()

