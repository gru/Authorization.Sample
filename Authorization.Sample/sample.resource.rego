package sample.resource

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

allow if {
	requested_permission_allowed

	some role in data.UserRoles[input.Subject.Name]

	match_organization_context(role.OrganizationContext, input.OrganizationContext)

	some role_permission in data.RolePermissions[role.RoleId]

	role_permission_allowed(role_permission, {"SecurableId": input.SecurableId, "PermissionId": input.PermissionId})
}

allow_document if {
	input.SecurableId = "Document"
	not input.Resource
}

default allow_document := false

allow_document if {
	input.SecurableId = "Document"

	match_organization_context(input.OrganizationContext, {"BranchId": input.Resource.BranchId, "OfficeId": input.Resource.OfficeId})

	some role in data.UserRoles[input.Subject.Name]

	match_organization_context(role.OrganizationContext, input.OrganizationContext)

	some role_permission in data.RolePermissions[role.RoleId]

	role_permission_allowed(role_permission, {"SecurableId": input.SecurableId, "ResourceTypeId": "DocumentTypeId", "ResourceId": input.Resource.DocumentTypeId, "PermissionId": input.PermissionId})
}

default allow_documentation_file_category := false

allow_documentation_file_category if {
	input.SecurableId = "DocumentationFile"
	not input.Resource
}

allow_documentation_file_category if {
	input.SecurableId = "DocumentationFile"
	input.Resource.CategoryType in {"All", "Bank"}
}

requested_permission_allowed if {
	input.PermissionId in data.read_only_permissions
}

requested_permission_allowed if {
	not data.demo
}

match_organization_context(role_context, input_context) if {
	role_context == {"BranchId": "*", "RegionalOfficeId": "*", "OfficeId": "*"}
}

match_organization_context(role_context, input_context) if {
	role_context == {"BranchId": input_context.BranchId, "RegionalOfficeId": "*", "OfficeId": "*"}
}

match_organization_context(role_context, input_context) if {
	role_context == {"BranchId": input_context.BranchId, "RegionalOfficeId": input_context.RegionalOfficeId, "OfficeId": "*"}
}

match_organization_context(role_context, input_context) if {
	role_context == {"BranchId": input_context.BranchId, "RegionalOfficeId": input_context.RegionalOfficeId, "OfficeId": input_context.OfficeId}
}

match_organization_context(role_context, input_context) if {
	role_context == {"BranchId": input_context.BranchId, "RegionalOfficeId": "*", "OfficeId": input_context.OfficeId}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": requested_permission.SecurableId, "PermissionId": requested_permission.PermissionId}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": requested_permission.SecurableId, "PermissionId": "*"}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": "*", "PermissionId": "*", "ResourceTypeId": "*"}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": requested_permission.SecurableId, "PermissionId": requested_permission.PermissionId, "ResourceTypeId": requested_permission.ResourceTypeId, "ResourceId": requested_permission.ResourceId}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": requested_permission.SecurableId, "PermissionId": requested_permission.PermissionId, "ResourceTypeId": requested_permission.ResourceTypeId, "ResourceId": "*"}
}

role_permission_allowed(role_permission, requested_permission) if {
	role_permission == {"SecurableId": requested_permission.SecurableId, "PermissionId": requested_permission.PermissionId, "ResourceTypeId": "*"}
}