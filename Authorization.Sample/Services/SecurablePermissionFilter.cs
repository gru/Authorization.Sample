using Authorization.Sample.Entities;
using Authorization.Sample.Implementation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Authorization.Sample.Services;

public sealed class SecurablePermissionFilter : IAuthorizationFilter
{
    private readonly SecurableId _securableId;
    private readonly PermissionId _permissionId;
    private readonly AuthorizationEnforcer _enforcer;
    
    public SecurablePermissionFilter(Tuple<SecurableId, PermissionId> pair, AuthorizationEnforcer enforcer)
    {
        _securableId = pair.Item1;
        _permissionId = pair.Item2; 
        _enforcer = enforcer;
    }
    
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var authorizationResult = _enforcer.Enforce(new ResourceAuthorizationRequest(_securableId, _permissionId));
        if (authorizationResult) return;

        context.Result = new ForbidResult();
    }
}