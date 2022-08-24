using Authorization.Sample.Services;

namespace Authorization.Sample.Implementation;

public class AuthorizationEnforcer
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ICurrentUserService _currentUserService;

    public AuthorizationEnforcer(IServiceProvider serviceProvider, ICurrentUserService currentUserService)
    {
        _serviceProvider = serviceProvider;
        _currentUserService = currentUserService;
    }

    public bool Enforce<TRequest>(TRequest request)
    {
        if (request is ICurrentUserAuthorizationRequest currentUserAuthorizationRequest)
        {
            currentUserAuthorizationRequest.UserId = _currentUserService.UserId;
            currentUserAuthorizationRequest.OrganizationContext ??= _currentUserService.OrganizationContext;
        }

        var matcher = _serviceProvider.GetService<IMatcher<TRequest>>()!;
        
        var effects = matcher.Match(request);
        
        return effects.Any(e => e == PolicyEffect.Allow);
    }

    public IQueryable<T> EnforceFilter<T, TRequest>(IQueryable<T> query, TRequest request)
    {
        if (request is ICurrentUserAuthorizationRequest currentUserAuthorizationRequest)
        {
            currentUserAuthorizationRequest.UserId = _currentUserService.UserId;
            currentUserAuthorizationRequest.OrganizationContext ??= _currentUserService.OrganizationContext;
        }

        var filter = _serviceProvider.GetService<IFilter<T, TRequest>>()!;

        return filter.Apply(query, request);
    }
}