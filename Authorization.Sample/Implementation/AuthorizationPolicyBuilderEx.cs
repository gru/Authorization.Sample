using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

public static class AuthorizationPolicyBuilderEx
{
    public static AuthorizationPolicyBuilder AddOpaRequirement(this AuthorizationPolicyBuilder builder, string policy, SecurableId securableId, PermissionId permissionId)
    {
        return builder.AddRequirements(new OpaRequirement(policy, securableId.ToString(), permissionId.ToString()));
    }
    
    public static AuthorizationPolicyBuilder AddOpaRequirement(this AuthorizationPolicyBuilder builder, string policy, string securableId = "", string permissionId = "")
    {
        return builder.AddRequirements(new OpaRequirement(policy, securableId, permissionId));
    }
}