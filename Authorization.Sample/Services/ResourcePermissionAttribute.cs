using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.Sample.Services;

public class ResourcePermissionAttribute : TypeFilterAttribute
{
    public ResourcePermissionAttribute(SecurableId securableId, PermissionId permissionId) 
        : base(typeof(ResourcePermissionFilter))
    {
        Arguments = new object[] { Tuple.Create(securableId, permissionId) };
    }
}