Decl k8s(ApiVersion, Kind, Namespace, Name, Data).
Decl user_groups(Username, Group).
Decl api_resource(ApiGroup, Resource).
Decl object_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue).
Decl selector_match_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue).
Decl selector_expr_in(ApiVersion, Kind, Namespace, Name, LabelKey, AllowedValue).
Decl selector_expr_notin(ApiVersion, Kind, Namespace, Name, LabelKey, ExcludedValue).
Decl selector_expr_exists(ApiVersion, Kind, Namespace, Name, LabelKey).
Decl selector_expr_notexists(ApiVersion, Kind, Namespace, Name, LabelKey).
