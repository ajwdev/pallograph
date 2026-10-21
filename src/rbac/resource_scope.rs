// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which resources live outside namespaces.
//!
//! A grant on a cluster-scoped resource never applies to a request in a
//! namespace: the API server sets no namespace on it. Pallograph loads no
//! data that says which resources are namespaced (`api-resources.txt` lists
//! names only, and CustomResourceDefinitions are not loaded), so this is a
//! fixed list of the upstream Kubernetes cluster-scoped resources. Anything
//! not on it, custom resources included, is treated as namespaced, which can
//! over-report but never hides access.
//!
//! TODO(ajw): load API discovery (`/apis`, the `namespaced` field of each
//! APIResource) and decide scope from it, including cluster-scoped CRDs,
//! then drop this hardcoded list.

/// (apigroup, resource) of every built-in cluster-scoped resource, except
/// `namespaces`: a request for namespace N (`/api/v1/namespaces/N`) carries
/// namespace N, so a RoleBinding in N can grant it.
const CLUSTER_SCOPED: &[(&str, &str)] = &[
    ("", "componentstatuses"),
    ("", "nodes"),
    ("", "persistentvolumes"),
    ("admissionregistration.k8s.io", "mutatingadmissionpolicies"),
    (
        "admissionregistration.k8s.io",
        "mutatingadmissionpolicybindings",
    ),
    (
        "admissionregistration.k8s.io",
        "mutatingwebhookconfigurations",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingadmissionpolicies",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingadmissionpolicybindings",
    ),
    (
        "admissionregistration.k8s.io",
        "validatingwebhookconfigurations",
    ),
    ("apiextensions.k8s.io", "customresourcedefinitions"),
    ("apiregistration.k8s.io", "apiservices"),
    ("authentication.k8s.io", "selfsubjectreviews"),
    ("authentication.k8s.io", "tokenreviews"),
    ("authorization.k8s.io", "selfsubjectaccessreviews"),
    ("authorization.k8s.io", "selfsubjectrulesreviews"),
    ("authorization.k8s.io", "subjectaccessreviews"),
    ("certificates.k8s.io", "certificatesigningrequests"),
    ("certificates.k8s.io", "clustertrustbundles"),
    ("flowcontrol.apiserver.k8s.io", "flowschemas"),
    (
        "flowcontrol.apiserver.k8s.io",
        "prioritylevelconfigurations",
    ),
    ("internal.apiserver.k8s.io", "storageversions"),
    ("networking.k8s.io", "ingressclasses"),
    ("networking.k8s.io", "ipaddresses"),
    ("networking.k8s.io", "servicecidrs"),
    ("node.k8s.io", "runtimeclasses"),
    ("rbac.authorization.k8s.io", "clusterrolebindings"),
    ("rbac.authorization.k8s.io", "clusterroles"),
    ("resource.k8s.io", "deviceclasses"),
    ("resource.k8s.io", "devicetaintrules"),
    ("resource.k8s.io", "resourceslices"),
    ("scheduling.k8s.io", "priorityclasses"),
    ("storage.k8s.io", "csidrivers"),
    ("storage.k8s.io", "csinodes"),
    ("storage.k8s.io", "storageclasses"),
    ("storage.k8s.io", "volumeattachments"),
    ("storage.k8s.io", "volumeattributesclasses"),
    ("storagemigration.k8s.io", "storageversionmigrations"),
];

/// Whether a grant on (`api_group`, `resource`) can apply to a request in
/// some namespace. Only a grant naming a known cluster-scoped resource, or a
/// subresource of one, cannot. A wildcard apigroup or resource can, as can
/// an unknown resource.
pub fn can_apply_in_namespace(api_group: &str, resource: &str) -> bool {
    let base = resource.split_once('/').map_or(resource, |(base, _)| base);
    !CLUSTER_SCOPED.contains(&(api_group, base))
}

#[cfg(test)]
mod tests {
    use super::can_apply_in_namespace;

    #[test]
    fn cluster_scoped_resources_do_not_apply_in_a_namespace() {
        assert!(!can_apply_in_namespace("", "nodes"));
        assert!(!can_apply_in_namespace("", "nodes/proxy"));
        assert!(!can_apply_in_namespace(
            "certificates.k8s.io",
            "clustertrustbundles"
        ));
        assert!(!can_apply_in_namespace(
            "authorization.k8s.io",
            "selfsubjectaccessreviews"
        ));

        assert!(can_apply_in_namespace("", "pods"));
        assert!(can_apply_in_namespace("", "namespaces"));
        assert!(can_apply_in_namespace(
            "authorization.k8s.io",
            "localsubjectaccessreviews"
        ));
        assert!(can_apply_in_namespace("", "*"));
        assert!(can_apply_in_namespace("*", "nodes"));
        assert!(can_apply_in_namespace("longhorn.io", "nodes"));
        assert!(can_apply_in_namespace("example.com", "widgets"));
    }
}
