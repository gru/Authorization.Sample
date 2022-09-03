package sample.resource

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

allow if {
	requested_permission_allowed

	some role_permission in user_has_permission

	input.action == role_permission.permission
	input.object == role_permission.securable
}

user_has_permission contains role_permission if {
	some user_role in data.userRoles[input.user]
    
    org_context_match(user_role.orgContext)
    
    some role_permission in data.rolePermissions[user_role.role]
}

org_context_match(ctx) {
	branch_match(ctx.branch)
    reg_office_match(ctx.regOffice)
    office_match(ctx.office)
}

branch_match(branch) {
	branch == "*"
}

branch_match(branch) {
	branch == input.orgContext.branch
}

office_match(office) {
	office == "*"
}

office_match(office) {
	office == input.orgContext.office
}

reg_office_match(reg_office) {
	reg_office == "*"
}

reg_office_match(reg_office) {
	input.orgContext.regOffice == "*"
}

reg_office_match(reg_office) {
	reg_office = input.orgContext.regOffice
}

requested_permission_allowed {
	input.action in	data.readOnlyPermissions
}

requested_permission_allowed {
	not data.demoFlag
}