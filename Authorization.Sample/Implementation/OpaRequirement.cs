using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

public class OpaRequirement : IAuthorizationRequirement
{
    public OpaRequirement(string name, string securableId, string permissionId)
    {
        Name = name;
        SecurableId = securableId;
        PermissionId = permissionId;
    }

    public string Name { get; }

    public string SecurableId { get; }

    public string PermissionId { get; }

    public string GetPolicy()
    {
        return Name.Replace('.', '/') ;
    }

    public string GetQuery()
    {
        return $"data.{Name} == true";
    }
}