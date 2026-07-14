"""
graph.py

Builds a map (graph) of which roles can reach which other roles, then
searches it for ANY path - direct or multi-step - that leads to admin.

Uses networkx, a library for exactly this kind of "can I get from A to
B" problem.
"""

import networkx as nx
from scanner.patterns import find_escalation_paths


ADMIN_NODE = "ADMIN"


def extract_role_name_from_arn(arn):
    """
    Turns 'arn:aws:iam::123456789012:role/ci-deploy-role' into just
    'ci-deploy-role' - the plain role name we use elsewhere in the tool.
    """
    if "/" in arn:
        return arn.split("/")[-1]
    return arn


def build_graph(all_roles_data):
    """
    all_roles_data looks like:
        {
            "auditor-role": {
                "actions": [...],
                "passable_roles": ["arn:...role/ci-deploy-role"]
            },
            ...
        }

    Builds a directed graph:
      - Role -> ADMIN, if that role has a DIRECT escalation pattern
      - Role -> OtherRole, if that role can pass/control OtherRole
    """
    graph = nx.DiGraph()
    graph.add_node(ADMIN_NODE)

    for role_name, data in all_roles_data.items():
        graph.add_node(role_name)

        # Road 1: direct escalation to admin (reuses your existing patterns)
        direct_findings = find_escalation_paths(data["actions"])
        if direct_findings:
            graph.add_edge(role_name, ADMIN_NODE, reason=direct_findings[0]["pattern"])

        # Road 2: this role can pass/control another specific role
        for arn in data["passable_roles"]:
            target_role = extract_role_name_from_arn(arn)
            graph.add_edge(role_name, target_role, reason="iam:PassRole")

    return graph


def find_all_paths_to_admin(graph):
    """
    Checks EVERY role in the graph: is there ANY path (direct or
    chained, any number of hops) that reaches ADMIN?

    Returns a dict like:
        {
            "ci-deploy-role": ["ci-deploy-role", "ADMIN"],
            "auditor-role": ["auditor-role", "ci-deploy-role", "ADMIN"],
        }
    """
    results = {}

    for node in graph.nodes():
        if node == ADMIN_NODE:
            continue
        if nx.has_path(graph, node, ADMIN_NODE):
            path = nx.shortest_path(graph, node, ADMIN_NODE)
            results[node] = path

    return results
