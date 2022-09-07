using System.Reflection;
using Authorization.Sample.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Authorization.Sample.Implementation;

public class AuthorizationEnforcer : IAuthorizationEnforcer
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IHttpContextAccessor _contextAccessor;

    public AuthorizationEnforcer(
        IAuthorizationService authorizationService, IHttpContextAccessor contextAccessor)
    {
        _authorizationService = authorizationService;
        _contextAccessor = contextAccessor;
    }

    public Task<bool> Enforce()
    {
        var policy = GetPolicy(_contextAccessor.HttpContext);
        if (policy == null) 
            throw new InvalidOperationException($"Unable to find {nameof(AuthorizeAttribute)}");

        return Enforce(policy);
    }

    public async Task<bool> Enforce(string policy)
    {
        if (_contextAccessor.HttpContext == null)
            return false;
        
        var result = await _authorizationService
            .AuthorizeAsync(_contextAccessor.HttpContext.User, policy);
        
        return result.Succeeded;
    }

    public Task<bool> Enforce(object resource)
    {
        var policy = GetPolicy(_contextAccessor.HttpContext);
        if (policy == null) 
            throw new InvalidOperationException($"Unable to find {nameof(AuthorizeAttribute)}");

        
        return Enforce(policy, resource);
    }

    public async Task<bool> Enforce(string policy, object resource)
    {
        if (_contextAccessor.HttpContext == null)
            return false;
        
        var result = await _authorizationService
            .AuthorizeAsync(_contextAccessor.HttpContext.User, resource, policy);

        return result.Succeeded;
    }

    public Task<IQueryable<T>> EnforceQueryable<T>(IQueryable<T> resource)
    {
        var policy = GetPolicy(_contextAccessor.HttpContext);
        if (policy == null) 
            throw new InvalidOperationException($"Unable to find {nameof(AuthorizeAttribute)}");

        return EnforceQueryable(policy, resource);
    }

    public async Task<IQueryable<T>> EnforceQueryable<T>(string policy, IQueryable<T> resource)
    {
        if (_contextAccessor.HttpContext == null)
            return resource.Where(r => false);
        
        var result = await _authorizationService
            .AuthorizeQueryAsync(_contextAccessor.HttpContext.User, resource, policy);
        
        return result;
    }

    private static string GetPolicy(HttpContext httpContext)
    {
        if (httpContext != null && httpContext.Items["ActionDescriptor"] is ControllerActionDescriptor actionDescriptor)
        {
            var authorizeAttribute = actionDescriptor.MethodInfo
                .GetCustomAttribute<AuthorizeAttribute>();

            if (authorizeAttribute != null)
                return authorizeAttribute.Policy;
        }

        return null;
    }
}