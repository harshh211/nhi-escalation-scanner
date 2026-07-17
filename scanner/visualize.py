"""
visualize.py

Draws the escalation graph as an image, so you can literally SEE the
attack paths instead of just reading text. Vulnerable roles are red,
safe roles are green, and the ADMIN node stands out in a different shape.
"""

import matplotlib.pyplot as plt
import networkx as nx
from scanner.graph import ADMIN_NODE


def draw_graph(graph, paths_to_admin, output_path="escalation_graph.png"):
    """
    Draws the full graph and saves it as a PNG image.

    graph: the networkx graph built by build_graph()
    paths_to_admin: dict of {role_name: [path]} from find_all_paths_to_admin()
    output_path: where to save the image
    """
    plt.figure(figsize=(12, 8))

    # Decide a position for every node - spring_layout arranges them
    # in a readable way automatically, like a force-directed diagram
    pos = nx.spring_layout(graph, seed=42, k=1.5)

    # Color each node: red if vulnerable, green if safe, gold if it's ADMIN
    node_colors = []
    for node in graph.nodes():
        if node == ADMIN_NODE:
            node_colors.append("gold")
        elif node in paths_to_admin:
            node_colors.append("#e74c3c")  # red
        else:
            node_colors.append("#2ecc71")  # green

    # Draw the nodes (the roles/ADMIN) as circles
    nx.draw_networkx_nodes(
        graph, pos, node_color=node_colors, node_size=2000, edgecolors="black"
    )

    # Draw the arrows (the escalation paths)
    nx.draw_networkx_edges(
        graph, pos, edge_color="#555555", arrows=True, arrowsize=25,
        width=1.5, connectionstyle="arc3,rad=0.1", node_size=2000
    )

    # Draw the labels (role names) on top
    nx.draw_networkx_labels(graph, pos, font_size=9, font_weight="bold")

    plt.title("AWS IAM Privilege Escalation Graph", fontsize=14, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

    print(f"\n📊 Graph image saved to: {output_path}")
