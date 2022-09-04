using Microsoft.AspNetCore.Authorization;

namespace Authorization.Sample.Implementation;

public static class AuthorizationServiceEx
{
    public static IQueryable<T> AuthorizeQueryable<T>(this IAuthorizationService service, IQueryable<T> query)
    {
        return query;
    }
}