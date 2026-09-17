import networkx as nx

def get_dependencies(g,node): return list(g.successors(node))
def get_dependents(g,node): return list(g.predecessors(node))
def get_recursive_dependencies(g,node): return list(nx.descendants(g,node))
def get_recursive_dependents(g,node): return list(nx.ancestors(g,node))
def find_path(g,source,target):
    try: return nx.shortest_path(g,source,target)
    except (nx.NetworkXNoPath,nx.NodeNotFound): return []
def find_references_to(g,node): return get_dependents(g,node)
def resolve_node(g,object_id):
    matches=[n for n,d in g.nodes(data=True) if d["dto"].object_id==object_id or d["dto"].name==object_id]
    return matches[0] if len(matches)==1 else None