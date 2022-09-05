using System.Linq.Expressions;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

public static class AuthorizationServiceEx
{
    public static async Task<IQueryable<T>> AuthorizeQueryAsync<T>(
        this IAuthorizationService service, ClaimsPrincipal user, IQueryable<T> query, string policy)
    {
        var wrapper = new QueryableWrapper(typeof(T));

        var result = await service.AuthorizeAsync(user, wrapper, policy);
        if (result.Succeeded)
        {
            if (wrapper.Expression is not Expression<Func<T, bool>> typedExpression)
                throw new InvalidOperationException($"Expression expected to be of type {typeof(Expression<Func<T, bool>>)}");
            
            return query.Where(typedExpression);
        }

        return query.Where(_ => false);
    }
}