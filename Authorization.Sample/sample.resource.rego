package sample.resource

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

allow if {
	requested_permission_allowed

	some role_permission in user_has_permission

	action_allowed(role_permission.permission)
    securable_allowed(role_permission.securable)
}

user_has_permission contains role_permission if {
	some user_role in data.userRoles[input.subject.name]

	org_context_match(user_role.orgContext)

	some role_permission in data.rolePermissions[user_role.role]
}

org_context_match(ctx) if {
	branch_match(ctx.branch)
	reg_office_match(ctx.regOffice)
	office_match(ctx.office)
}

branch_match(branch) if {
	branch == "*"
}

branch_match(branch) if {
	branch == input.orgContext.branch
}

office_match(office) if {
	office == "*"
}

office_match(office) if {
	office == input.orgContext.office
}

reg_office_match(reg_office) if {
	reg_office == "*"
}

reg_office_match(reg_office) if {
	input.orgContext.regOffice == "*"
}

reg_office_match(reg_office) if {
	reg_office = input.orgContext.regOffice
}

requested_permission_allowed if {
	input.action in data.readOnlyPermissions
}

requested_permission_allowed if {
	not data.demoFlag
}

action_allowed(action) if {
	action == "*"
}

action_allowed(action) if {
	action == input.action
}

securable_allowed(action) if {
	action == "*"
}

securable_allowed(action) if {
	action == input.action
}