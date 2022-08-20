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

public enum PolicyEffect
{
    Allow, Deny
}

public interface IAuthorizationPolicyRuleQuery<out TPolicy>
{
    public IQueryable<TPolicy> PrepareQuery();
}

public interface IMatcher<in TRequest>
{
    IQueryable<PolicyEffect> Match(TRequest request);
}

public abstract class Matcher<TRequest, TPolicy> : IMatcher<TRequest>
{
    private readonly IAuthorizationPolicyRuleQuery<TPolicy> _authorizationPolicyRuleQuery;

    protected Matcher(IAuthorizationPolicyRuleQuery<TPolicy> authorizationPolicyRuleQuery)
    {
        _authorizationPolicyRuleQuery = authorizationPolicyRuleQuery;
    }

    public IQueryable<PolicyEffect> Match(TRequest request)
    {
        return Match(request, _authorizationPolicyRuleQuery.PrepareQuery());
    }

    protected abstract IQueryable<PolicyEffect> Match(TRequest request, IQueryable<TPolicy> rules);
}

public class ResourcePermissionMatcher : Matcher<AuthorizationRequest, AuthorizationPolicyRule>
{
    public ResourcePermissionMatcher(IAuthorizationPolicyRuleQuery<AuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(AuthorizationRequest request, IQueryable<AuthorizationPolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == request.UserId && 
                       (r.Resource == request.Resource || r.Resource == SecurableId.Any) && 
                       (r.Action == request.Action || r.Action == PermissionId.Any))
            .Select(r => PolicyEffect.Allow);
    }
}

public class SuperuserMatcher : SuperuserMatcherBase<AuthorizationRequest>
{
    public SuperuserMatcher(IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(AuthorizationRequest request, IQueryable<RoleAuthorizationPolicyRule> rules)
    {
        return Match(request.UserId, rules);
    }
}

public abstract class SuperuserMatcherBase<TRequest> : Matcher<TRequest, RoleAuthorizationPolicyRule>
{
    protected SuperuserMatcherBase(IAuthorizationPolicyRuleQuery<RoleAuthorizationPolicyRule> authorizationPolicyRuleQuery) 
        : base(authorizationPolicyRuleQuery)
    {
    }
    
    protected IQueryable<PolicyEffect> Match(long userId, IQueryable<RoleAuthorizationPolicyRule> rules)
    {
        return rules
            .Where(r => r.UserId == userId && r.RoleName == "Superuser")
            .Select(r => PolicyEffect.Allow);
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
        return matchers.SelectMany(m => m.Match(request)).Any(e => e == PolicyEffect.Allow);
    }
}

public class DenyOverrideEffector<TRequest> : IEffector<TRequest>
{
    public bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request)
    {
        return matchers.SelectMany(m => m.Match(request)).All(e => e == PolicyEffect.Allow);
    }
}

public class AllowAndDenyEffector<TRequest> : IEffector<TRequest>
{
    public bool Apply(IReadOnlyCollection<IMatcher<TRequest>> matchers, TRequest request)
    {
        var effects = matchers.SelectMany(m => m.Match(request)).ToArray();
        
        return effects.Any(e => e == PolicyEffect.Allow) && effects.All(e => e == PolicyEffect.Allow);
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