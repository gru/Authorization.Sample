using Authorization.Sample.Entities;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.Sample.Services;

public class SecurablePermissionAttribute : TypeFilterAttribute
{
    public SecurablePermissionAttribute(SecurableId securableId, PermissionId permissionId) 
        : base(typeof(SecurablePermissionFilter))
    {
        Arguments = new object[] { Tuple.Create(securableId, permissionId) };
    }
}