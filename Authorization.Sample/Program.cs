using Microsoft.Extensions.DependencyInjection;

namespace Authorization.Sample;

public static class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
    }
}

public enum SecurableId
{
    Document = 1, DocumentationFile = 2, Any = 3
}

public enum PermissionId
{
    View = 1, Create = 2, Change = 3, Delete = 4, Any = 5
}

public static class Securables
{
    public static readonly SecurableId Document = SecurableId.Document;
    public static readonly SecurableId DocumentationFile = SecurableId.DocumentationFile;
}

public static class Permissions
{
    public static readonly PermissionId View = PermissionId.View;
    public static readonly PermissionId Create = PermissionId.Create;
    public static readonly PermissionId Change = PermissionId.Change;
    public static readonly PermissionId Delete = PermissionId.Delete;
}

public interface ICurrentUserService
{
    long UserId { get; }
}

public class CurrentUserAuthorizationRequest
{
    public long UserId { get; set; }
}

public class AuthorizationRequest : CurrentUserAuthorizationRequest
{
    public AuthorizationRequest(SecurableId resource, PermissionId action)
    {
        Resource = resource;
        Action = action;
    }

    public SecurableId Resource { get; }
    
    public PermissionId Action { get; }
}

public class AuthorizationPolicyRule
{
    public long UserId { get; set; }
    
    public SecurableId Resource { get; set; }
    
    public PermissionId Action { get; set; }
}

public class RoleAuthorizationPolicyRule
{
    public long UserId { get; set; }

    public string RoleName { get; set; }
}

public interface IAuthorizationPolicyRuleQuery<out TPolicy>
{
    public IQueryable<TPolicy> PrepareQuery();
}

public interface IMatcher<in TRequest>
{
    bool Match(TRequest request);
}

public abstract class Matcher<TRequest, TPolicy> : IMatcher<TRequest>
{
    private readonly IAuthorizationPolicyRuleQuery<TPolicy> _authorizationPolicyRuleQuery;

    protected Matcher(IAuthorizationPolicyRuleQuery<TPolicy> authorizationPolicyRuleQuery)
    {
        _authorizationPolicyRuleQuery = authorizationPolicyRuleQuery;
    }

    public bool Match(TRequest request)
    {
        return Match(request, _authorizationPolicyRuleQuery.PrepareQuery());
    }

    protected abstract bool Match(TRequest request, IQueryable<TPolicy> rules);
}

public class ResourcePermissionMatcher : Matcher<AuthorizationRequest, AuthorizationPolicyRule>
{
    public ResourcePermissionMatcher(IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override bool Match(AuthorizationRequest request, IQueryable<AuthorizationPolicyRule> rules)
    {
        return rules.Any(r => r.UserId == request.UserId && 
                             (r.Resource == request.Resource || r.Resource == SecurableId.Any) && 
                             (r.Action == request.Action || r.Action == PermissionId.Any));
    }
}

public class SuperuserMatcher : Matcher<AuthorizationRequest, RoleAuthorizationPolicyRule>
{
    public SuperuserMatcher(IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override bool Match(AuthorizationRequest request, IQueryable<RoleAuthorizationPolicyRule> rules)
    {
        return rules.Any(r => r.UserId == request.UserId && r.RoleName == "Superuser");
    }
}

public interface IEffector<TRequest>
{
    bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request);
}

public class AllowOverrideEffector<TRequest> : IEffector<TRequest>
{
    public bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request)
    {
        return matchers.Any(m => m.Match(request));
    }
}

public class DenyOverrideEffector<TRequest> : IEffector<TRequest>
{
    public bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request)
    {
        return matchers.All(m => m.Match(request));
    }
}

public class AllowAndDenyEffector<TRequest> : IEffector<TRequest>
{
    public bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request)
    {
        return matchers.Any(m => m.Match(request)) && matchers.All(m => m.Match(request));
    }
}

public enum Effector
{
    AllowOverride, 
    DenyOverride,
    AllowAndDeny
}

public class EnforceContext
{
    internal static readonly EnforceContext Default = new EnforceContext();
    
    public EnforceContext()
    {
        Effector = Effector.AllowOverride;
    }
    
    public Effector Effector { get; set; }
}

public class Enforcer
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ICurrentUserService _currentUserService;

    public Enforcer(IServiceProvider serviceProvider, ICurrentUserService currentUserService)
    {
        _serviceProvider = serviceProvider;
        _currentUserService = currentUserService;
    }

    public bool Enforce<TRequest>(TRequest request) 
        => Enforce(EnforceContext.Default, request);

    public bool Enforce<TRequest>(EnforceContext context, TRequest request)
    {
        if (request is CurrentUserAuthorizationRequest currentUserAuthorizationRequest)
            currentUserAuthorizationRequest.UserId = _currentUserService.UserId;

        var matchers = _serviceProvider.GetServices<IMatcher<TRequest>>().ToArray();
    
        IEffector<TRequest> effector = context.Effector switch
        {
            Effector.AllowOverride => new AllowOverrideEffector<TRequest>(),
            Effector.DenyOverride => new DenyOverrideEffector<TRequest>(),
            Effector.AllowAndDeny => new AllowAndDenyEffector<TRequest>(),
            _ => throw new ArgumentOutOfRangeException(nameof(context.Effector))
        };

        return effector.Apply(matchers, request);
    }
}