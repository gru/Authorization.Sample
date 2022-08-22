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

public class OrganizationContext
{
    public OrganizationContext(long branchId)
    {
        BranchId = branchId;
    }

    public OrganizationContext(long branchId, long regionalOfficeId)
        : this(branchId)
    {
        RegionalOfficeId = regionalOfficeId;
    }


    public OrganizationContext(long branchId, long regionalOfficeId, long officeId)
        : this(branchId, regionalOfficeId)
    {
        OfficeId = officeId;
    }

    public long BranchId { get; }
    
    public long? RegionalOfficeId { get; }
    
    public long? OfficeId { get; }
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
    public AuthorizationRequest(SecurableId resource, PermissionId action, OrganizationContext organizationContext = null)
    {
        Resource = resource;
        Action = action;
        OrganizationContext = organizationContext;
    }

    public SecurableId Resource { get; }
    
    public PermissionId Action { get; }

    public OrganizationContext OrganizationContext { get; }
}

public class ResourcePolicyRule
{
    public long UserId { get; set; }
    
    public SecurableId Resource { get; set; }
    
    public PermissionId Action { get; set; }

    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}

public class RolePolicyRule
{
    public long UserId { get; set; }

    public string RoleName { get; set; }
    
    public long? BranchId { get; set; }
    
    public long? RegionalOfficeId { get; set; }
    
    public long? OfficeId { get; set; }
}

public enum PolicyEffect
{
    Allow, Deny
}

public interface IPolicyRuleQuery<out TPolicy>
{
    public IQueryable<TPolicy> PrepareQuery();
}

public interface IMatcher<in TRequest>
{
    IQueryable<PolicyEffect> Match(TRequest request);
}

public abstract class Matcher<TRequest, TPolicy> : IMatcher<TRequest>
{
    private readonly IPolicyRuleQuery<TPolicy> _policyRuleQuery;

    protected Matcher(IPolicyRuleQuery<TPolicy> policyRuleQuery)
    {
        _policyRuleQuery = policyRuleQuery;
    }

    public IQueryable<PolicyEffect> Match(TRequest request)
    {
        return Match(request, _policyRuleQuery.PrepareQuery());
    }

    protected abstract IQueryable<PolicyEffect> Match(TRequest request, IQueryable<TPolicy> rules);
}

public class ResourcePermissionMatcher : Matcher<AuthorizationRequest, ResourcePolicyRule>
{
    public ResourcePermissionMatcher(IPolicyRuleQuery<ResourcePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(AuthorizationRequest request, IQueryable<ResourcePolicyRule> rules)
    {
        var query = rules
            .Where(r => r.UserId == request.UserId &&
                        (r.Resource == request.Resource || r.Resource == SecurableId.Any) &&
                        (r.Action == request.Action || r.Action == PermissionId.Any));

        if (request.OrganizationContext == null)
        {
            query = query
                .Where(r => r.BranchId == null &&
                            r.RegionalOfficeId == null &&
                            r.OfficeId == null);
        }
        else
        {
            var ctx = request.OrganizationContext;

            query = query
                .Where(r => (r.BranchId == null && r.RegionalOfficeId == null && r.OfficeId == null) ||
                            (r.BranchId == ctx.BranchId && 
                             (r.RegionalOfficeId == null || r.RegionalOfficeId == ctx.RegionalOfficeId) && 
                             (r.OfficeId == null || r.OfficeId == ctx.OfficeId)));
        }

        return query.Select(r => PolicyEffect.Allow);
    }
}

public class SuperuserMatcher : SuperuserMatcherBase<AuthorizationRequest>
{
    public SuperuserMatcher(IPolicyRuleQuery<RolePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }

    protected override IQueryable<PolicyEffect> Match(AuthorizationRequest request, IQueryable<RolePolicyRule> rules)
    {
        return Match(request.UserId, rules);
    }
}

public abstract class SuperuserMatcherBase<TRequest> : Matcher<TRequest, RolePolicyRule>
{
    protected SuperuserMatcherBase(IPolicyRuleQuery<RolePolicyRule> policyRuleQuery) 
        : base(policyRuleQuery)
    {
    }
    
    protected IQueryable<PolicyEffect> Match(long userId, IQueryable<RolePolicyRule> rules)
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

    public IQueryable<T> EnforceFilter<T>(IQueryable<T> query, PermissionId permissionId = PermissionId.View)
    {
        var filters = _serviceProvider.GetServices<IFilter<T, AuthorizationFilterContext>>().ToArray();
        var context = new AuthorizationFilterContext(_currentUserService.UserId, permissionId);

        return filters.Select(f => f.Apply(query, context)).Aggregate((q1, q2) => q1.Union(q2));;
    }
}

public interface IFilter<T, in TContext>
{
    IQueryable<T> Apply(IQueryable<T> query, TContext context);
}

public class AuthorizationFilterContext
{
    public AuthorizationFilterContext(long userId, PermissionId permissionId = PermissionId.View)
    {
        UserId = userId;
        PermissionId = permissionId;
    }

    public long UserId { get; }

    public PermissionId PermissionId { get; }
}

public abstract class Filter<T, TContext, TPolicy> : IFilter<T, TContext>
{
    private readonly IPolicyRuleQuery<TPolicy> _rules;

    protected Filter(IPolicyRuleQuery<TPolicy> rules)
    {
        _rules = rules;
    }

    public IQueryable<T> Apply(IQueryable<T> query, TContext context)
    {
        return Apply(query, context, _rules.PrepareQuery());
    }

    protected abstract IQueryable<T> Apply(IQueryable<T> query, TContext context, IQueryable<TPolicy> rules);
}

public abstract class Filter<T, TPolicy> : Filter<T, AuthorizationFilterContext, TPolicy>
{
    protected Filter(IPolicyRuleQuery<TPolicy> rules) 
        : base(rules)
    {
    }
}
