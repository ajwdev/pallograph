# Transitive reachability — classic Datalog example in Mangle syntax.
#
# EDB: known edges between nodes.
edge("a", "b").
edge("b", "c").
edge("c", "d").

# IDB: path/2 is the transitive closure of edge/2.
#
# Base case: a direct edge is a path.
path(X, Y) :- edge(X, Y).

# Recursive case: extend an existing path by one edge.
path(X, Z) :- path(X, Y), edge(Y, Z).
