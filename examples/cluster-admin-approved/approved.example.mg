# Example cluster-admin approval closure: the security team's record of who is
# allowed to hold cluster-admin. One fact per principal, keyed on the
# principal string:
#   - a user name, e.g. "alice@example.com"
#   - a group name, e.g. "platform-admins"
#   - a ServiceAccount, e.g. "system:serviceaccount:<namespace>:<name>"
#
# Built-in platform principals (system:*, eks:*) are cluster-admin by the
# platform and cannot be changed; list the specific ones your cluster has so
# they do not flag. `rbac::cluster-admin --all` prints the full roster to copy
# from.
#
# Replace these with your cluster's approved set.
cluster_admin_allowed("eks:addon-manager").
cluster_admin_allowed("system:masters").
cluster_admin_allowed("system:serviceaccount:sonobuoy:sonobuoy-serviceaccount").
cluster_admin_allowed("platform-admins@example.com").
