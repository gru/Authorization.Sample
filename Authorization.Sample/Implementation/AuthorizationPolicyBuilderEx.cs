using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

public static class AuthorizationPolicyBuilderEx
{
    public static AuthorizationPolicyBuilder AddOpaResourceRequirement(this AuthorizationPolicyBuilder builder, string name, SecurableId securableId, PermissionId permissionId)
    {
        return builder.AddRequirements(new OpaRequirement(name, securableId.ToString(), permissionId.ToString()));
    }
    
    public static AuthorizationPolicyBuilder AddOpaRequirement(this AuthorizationPolicyBuilder builder, string name, string resource = "", string operation = "")
    {
        return builder.AddRequirements(new OpaRequirement(name, resource, operation));
    }
}